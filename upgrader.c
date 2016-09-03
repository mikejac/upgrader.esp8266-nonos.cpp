/* 
 * The MIT License (MIT)
 * 
 * ESP8266 Non-OS Firmware
 * Copyright (c) 2015 Michael Jacobsen (github.com/mikejac)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "upgrader.h"
#include <github.com/mikejac/bluemix.esp8266-nonos.cpp/bluemix.h>
#include <github.com/mikejac/raburton.rboot.esp8266-nonos.cpp/appcode/rboot-api.h>

#define DTXT(...)   os_printf(__VA_ARGS__)

static UPGRADER*  upgrader;

#define UPGRADE_FLAG_IDLE		0x00
#define UPGRADE_FLAG_START		0x01
#define UPGRADE_FLAG_FINISH		0x02

// callback method should take this format
typedef void (*ota_callback)(bool result, uint8 rom_slot);

typedef struct {
    uint8               rom_slot;   // rom slot to update
    ota_callback        callback;   // user callback when completed
    uint32              total_len;
    uint32              content_len;
    struct espconn*     conn;
    ip_addr_t           ip;
    rboot_write_status  write_status;
} upgrade_status;

static upgrade_status* upgrade;
static os_timer_t      ota_timer;

/*
 exported from ROM
 */
#ifdef __cplusplus
extern "C" {
#endif
 
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} md5_context_t;
 
extern void MD5Init(md5_context_t *);
extern void MD5Update(md5_context_t *, uint8_t *, uint16_t);
extern void MD5Final(uint8_t [16], md5_context_t *);
 
#ifdef __cplusplus
} // extern "C"
#endif

/**
 * 
 * @param result
 * @param rom_slot
 */
static void OtaUpdate_CallBack(bool result, uint8 rom_slot);
/**
 * 
 * @param callback
 * @return 
 */
static bool rboot_ota_start(ota_callback callback) ;
/**
 * 
 * @param name
 * @param ip
 * @param arg
 */
static void upgrade_resolved(const char *name, ip_addr_t *ip, void *arg);
/**
 * 
 */
static void rboot_ota_deinit();
/**
 * 
 * @param arg
 * @param pusrdata
 * @param length
 */
static void upgrade_recvcb(void *arg, char *pusrdata, unsigned short length);
/**
 * 
 * @param arg
 */
static void upgrade_disconcb(void *arg);
/**
 * 
 * @param arg
 */
static void upgrade_connect_cb(void *arg);
/**
 * 
 */
static void connect_timeout_cb();
/**
 * 
 * @param err
 * @return 
 */
static const char* esp_errstr(sint8 err);
/**
 * 
 * @param arg
 * @param errType
 */
static void upgrade_recon_cb(void *arg, sint8 errType);

/******************************************************************************************************************
 * public functions
 *
 */

/**
 * 
 * @param u
 * @param mqtt
 * @param nodename
 * @param pkgId
 * @param version
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_Initialize(UPGRADER* u, Mqtt* mqtt, const char* nodename, const char* pkgId, const uint32_t* version)
{
    u->m_Mqtt       = mqtt;
    u->m_Nodename   = (nodename == NULL) ? "+" : nodename;
    u->m_PkgId      = pkgId;
    u->m_Version    = version;
    
    u->m_Server     = NULL;
    u->m_Port       = -1;
    u->m_Filename   = NULL;
    
    upgrader        = u;
    
    return 0;
}
/**
 * 
 * @param u
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_Subscribe_Package(UPGRADER* u)
{
    CommandSubscription(u->m_Mqtt, 
                        u->m_Nodename,
                        ActorIdUpgrader,
                        PlatformIdUpgrader,
                        u->m_PkgId,                                 // feed_id
                        MQTT_QOS);

    return 0;
}
/**
 * 
 * @param u
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_Publish_Package(UPGRADER* u)
{
    char* data;
    
    data = os_malloc(256);

    if(data != NULL) {
        os_sprintf(data, "{\"d\":{\"_type\":\"firmware\",\"pkgid\":\"%s\",\"version\":%lu}}", 
                        u->m_PkgId,
                        *u->m_Version);

        CommandPublish( u->m_Mqtt, 
                        ActorIdUpgrader,        // actor_id 
                        PlatformIdPackage,      // platform_id 
                        u->m_PkgId,             // feed_id 
                        data,                   // data 
                        MQTT_QOS,               // qos 
                        0);                     // retain

        os_free(data);
    }

    return 0;
}
/**
 * 
 * @param u
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_NewPkg(UPGRADER* u)
{
    static int ret = 0;
    
    if(u->m_Server && u->m_Filename) {
        // check not already updating
        if(system_upgrade_flag_check() != UPGRADE_FLAG_START) {
            ret++;
        }
    }
    else {
        ret = 0;
    }
    
    return ret; 
}
/**
 * 
 * @param u
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_Run(UPGRADER* u)
{
    int ret = 0;
    
    if(u->m_Server && u->m_Filename) {
        // check not already updating
        if(system_upgrade_flag_check() == UPGRADE_FLAG_START) {
            
        }
        else {
            DTXT("Upgrader_Run(): package waiting; starting upgrade\n");
            upgrader = u;
        
            rboot_ota_start(OtaUpdate_CallBack);
        
            ret = 1;
        }
    }
    
    return ret; 
}
/**
 * 
 * @param u
 * @param nodename
 * @param actor_id
 * @param platform_id
 * @param feed_id
 * @param payload
 * @return 
 */
int ICACHE_FLASH_ATTR Upgrader_Check(   UPGRADER*   u,
                                        const char* nodename,
                                        const char* actorId,
                                        const char* platformId,
                                        const char* feedId,
                                        const char* payload)
{
    int ret = 0;
    
    if(strcmp(actorId, ActorIdUpgrader) == 0 && strcmp(platformId, PlatformIdUpgrader) == 0 && strcmp(feedId, u->m_PkgId) == 0) {
        /******************************************************************************************************************
         * extract data from 'd' object
         * 
         * {
         *   "d" : {
         *     "_type"    : "firmware",
         *     "pkgid"    : "RWNO",
         *     "server"   : "192.168.1.101",
         *     "bin0name" : "rom0.bin",
         *     "bin0md5"  : [26,89,236,133,10,104,117,4,15,160,7,215,30,22,136,52],
         *     "bin1name" : "rom1.bin",
         *     "bin1md5"  : [191,227,22,51,108,3,183,51,108,122,244,110,136,47,130,98],
         *     "version"  : 1
         *   }
         * }
         * 
         */
        if(BMix_DecoderBegin(payload) != NULL) {
            const char* _type;
            uint64_t    version;

            if(BMix_GetString("_type", &_type) == 0 && os_strcmp(_type, "firmware") == 0 && BMix_GetU64("version", &version) == 0) {
                DTXT("Upgrader_Check(): version = %lu\n", (long unsigned int) version);
                
                if(version != *u->m_Version) {
                    const char* server;
                    const char* filename;
                    int         port;
                    
                    if(BMix_GetString("server", &server) == 0) {
                        uint8_t slot = rboot_get_current_rom();
                    
                        if(slot == 0) {
                            slot = 1;
                        }
                        else {
                            slot = 0;
                        }
                        
                        if(BMix_GetString(slot == 0 ? "bin0name" : "bin1name", &filename) == 0) {
                            if(BMix_GetInt("port", &port) == 0) {
                                if(BMix_GetArrayByte(slot == 0 ? "bin0md5" : "bin1md5", u->m_MD5Sum, 16) == 16) {
                                    u->m_Port = port;

                                    if(u->m_Server) {
                                        os_free(u->m_Server);
                                    }

                                    u->m_Server = os_malloc(os_strlen(server) + 1);
                                    os_strcpy(u->m_Server, server);

                                    if(u->m_Filename) {
                                        os_free(u->m_Filename);
                                    }

                                    u->m_Filename = os_malloc(os_strlen(filename) + 1);
                                    os_strcpy(u->m_Filename, filename);

                                    DTXT("Upgrader_Check(): server = '%s', port = %d, filename = '%s'\n", u->m_Server, u->m_Port, u->m_Filename);
                                }
                                else {
                                    DTXT("Upgrader_Check(): error; MD5 array does not contain 16 bytes\n");
                                }
                            }
                        }
                    }
                }
            }
        }
        
        BMix_DecoderEnd();
        
        ret = 1;
    }
    
    return ret;
}

/******************************************************************************************************************
 * OTA functions
 *
 */

// general http header
#define HTTP_HEADER "Connection: keep-alive\r\n\
Cache-Control: no-cache\r\n\
User-Agent: rBoot-Sample/1.0\r\n\
Accept: */*\r\n\r\n"

// timeout for the initial connect and each recv (in ms)
#define OTA_NETWORK_TIMEOUT  10000

/**
 * 
 * @param result
 * @param rom_slot
 */
void ICACHE_FLASH_ATTR OtaUpdate_CallBack(bool result, uint8 rom_slot) 
{
    if(result == true) {
        // success - set to boot new rom and then reboot
        DTXT("OtaUpdate_CallBack(): firmware updated, rebooting to rom %d ...\n", rom_slot);

        rboot_set_current_rom(rom_slot);

        system_restart();
    } else {
        // fail
        DTXT("OtaUpdate_CallBack(): firmware update failed!\n");
    }
}
/**
 * start the ota process, with user supplied options
 * @param callback
 * @return 
 */
bool ICACHE_FLASH_ATTR rboot_ota_start(ota_callback callback) 
{
    uint8 slot;
    rboot_config bootconf;
    err_t result;

    // create upgrade status structure
    upgrade = (upgrade_status*)os_zalloc(sizeof(upgrade_status));
    if (!upgrade) {
        DTXT("rboot_ota_start(): no ram\n");
        return false;
    }

    // store the callback
    upgrade->callback = callback;

    // get details of rom slot to update
    bootconf = rboot_get_config();
    slot = bootconf.current_rom;
    if (slot == 0) slot = 1; else slot = 0;
    upgrade->rom_slot = slot;

    // flash to rom slot
    upgrade->write_status = rboot_write_init(bootconf.roms[upgrade->rom_slot]);

    // create connection
    upgrade->conn = (struct espconn *)os_zalloc(sizeof(struct espconn));
    if (!upgrade->conn) {
        DTXT("rboot_ota_start(): no ram\n");
        os_free(upgrade);
        return false;
    }
    upgrade->conn->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
    if (!upgrade->conn->proto.tcp) {
        DTXT("rboot_ota_start(): no ram\n");
        os_free(upgrade->conn);
        os_free(upgrade);
        return false;
    }

    // set update flag
    system_upgrade_flag_set(UPGRADE_FLAG_START);

    // dns lookup
    result = espconn_gethostbyname(upgrade->conn, upgrader->m_Server, &upgrade->ip, upgrade_resolved);
    if (result == ESPCONN_OK) {
        // hostname is already cached or is actually a dotted decimal ip address
        upgrade_resolved(0, &upgrade->ip, upgrade->conn);
    } else if (result == ESPCONN_INPROGRESS) {
        // lookup taking place, will call upgrade_resolved on completion
    } else {
        DTXT("rboot_ota_start(): DNS error\n");
        os_free(upgrade->conn->proto.tcp);
        os_free(upgrade->conn);
        os_free(upgrade);
        return false;
    }

    return true;
}
/**
 * call back for dns lookup
 * @param name
 * @param ip
 * @param arg
 */
void ICACHE_FLASH_ATTR upgrade_resolved(const char *name, ip_addr_t *ip, void *arg) 
{
    if (ip == 0) {
        DTXT("upgrade_resolved(): DNS lookup failed for '%s'\n", upgrader->m_Server);

        // not connected so don't call disconnect on the connection
        // but call our own disconnect callback to do the cleanup
        upgrade_disconcb(upgrade->conn);
        return;
    }

    // set up connection
    upgrade->conn->type                     = ESPCONN_TCP;
    upgrade->conn->state                    = ESPCONN_NONE;
    upgrade->conn->proto.tcp->local_port    = espconn_port();
    upgrade->conn->proto.tcp->remote_port   = upgrader->m_Port;
    
    os_memcpy(&upgrade->conn->proto.tcp->remote_ip, &ip->addr, 4);
    
    // set connection call backs
    espconn_regist_connectcb(upgrade->conn, upgrade_connect_cb);
    espconn_regist_reconcb(upgrade->conn,   upgrade_recon_cb);

    // try to connect
    espconn_connect(upgrade->conn);

    // set connection timeout timer
    os_timer_disarm(&ota_timer);
    os_timer_setfn(&ota_timer, (os_timer_func_t *)connect_timeout_cb, 0);
    os_timer_arm(&ota_timer, OTA_NETWORK_TIMEOUT, 0);
}
/**
 * clean up at the end of the update. will call the user call back to indicate completion
 */
void ICACHE_FLASH_ATTR rboot_ota_deinit() 
{
    bool result;
    uint8 rom_slot;
    ota_callback callback;
    struct espconn *conn;

    os_timer_disarm(&ota_timer);

    // save only remaining bits of interest from upgrade struct
    // then we can clean it up early, so disconnect callback
    // can distinguish between us calling it after update finished
    // or being called earlier in the update process
    conn     = upgrade->conn;
    rom_slot = upgrade->rom_slot;
    callback = upgrade->callback;

    // clean up
    os_free(upgrade);
    upgrade = 0;

    // if connected, disconnect and clean up connection
    if (conn) {
        espconn_disconnect(conn);
    }
    
    // check for completion
    if (system_upgrade_flag_check() == UPGRADE_FLAG_FINISH) {
        result = true;
    } 
    else {
        system_upgrade_flag_set(UPGRADE_FLAG_IDLE);
        result = false;
    }

    // call user call back
    if (callback) {
        callback(result, rom_slot);
    }
}
/**
 * called when connection receives data (hopefully the rom)
 * @param arg
 * @param pusrdata
 * @param length
 */
void ICACHE_FLASH_ATTR upgrade_recvcb(void *arg, char *pusrdata, unsigned short length) 
{
    char *ptrData, *ptrLen, *ptr;

    // disarm the timer
    os_timer_disarm(&ota_timer);

    // first reply?
    if (upgrade->content_len == 0) {
        // valid http response?
        if ((ptrLen = (char*)os_strstr(pusrdata, "Content-Length: "))
                && (ptrData = (char*)os_strstr(ptrLen, "\r\n\r\n"))
                && (os_strncmp(pusrdata + 9, "200", 3) == 0)) {

            // end of header/start of data
            ptrData += 4;
            // length of data after header in this chunk
            length -= (ptrData - pusrdata);
            // running total of download length
            upgrade->total_len += length;
            
            DTXT(".");
            
            // process current chunk
            rboot_write_flash(&upgrade->write_status, (uint8*)ptrData, length);
            
            // work out total download size
            ptrLen += 16;
            ptr = (char *)os_strstr(ptrLen, "\r\n");
            *ptr = '\0'; // destructive
            upgrade->content_len = atoi(ptrLen);
        } else {
            DTXT("\n");

            // fail, not a valid http header/non-200 response/etc.
            rboot_ota_deinit();
            return;
        }
    } else {
        // not the first chunk, process it
        DTXT(".");

        upgrade->total_len += length;
        rboot_write_flash(&upgrade->write_status, (uint8*)pusrdata, length);
    }

    // check if we are finished
    if (upgrade->total_len == upgrade->content_len) {
        DTXT("\n");
        
        uint32 offset = rboot_get_slot_offset(upgrade->rom_slot);
        
        uint32 image_length;

        if(rboot_verify_image(offset, &image_length, NULL)) {
            //
            // calculate MD5 sum
            //
            md5_context_t ctx;
            
            MD5Init(&ctx);
            
            rboot_digest_image(offset, image_length, (rboot_digest_update_fn)MD5Update, &ctx);
            
            uint8_t hash_result[16];
            MD5Final(hash_result, &ctx);
            
            //
            // compare the calculated MD5 sum with the MD5 sum that came from the uprader server
            //
            if(os_memcmp(hash_result, upgrader->m_MD5Sum, 16) == 0) {
                DTXT("upgrade_recvcb(): MD5 ok\n");
                system_upgrade_flag_set(UPGRADE_FLAG_FINISH);
            }
            else {
                DTXT("upgrade_recvcb(): MD5 fail\n");
            }
        }
        
        // clean up and call user callback
        rboot_ota_deinit();
    } else if (upgrade->conn->state != ESPCONN_READ) {
        DTXT("\n");

        // fail, but how do we get here? premature end of stream?
        rboot_ota_deinit();
    } else {
        // timer for next recv
        os_timer_setfn(&ota_timer, (os_timer_func_t *)rboot_ota_deinit, 0);
        os_timer_arm(&ota_timer, OTA_NETWORK_TIMEOUT, 0);
    }
}
/**
 * disconnect callback, clean up the connection. we also call this ourselves
 * @param arg
 */
void ICACHE_FLASH_ATTR upgrade_disconcb(void *arg) 
{
    // use passed ptr, as upgrade struct may have gone by now
    struct espconn *conn = (struct espconn*)arg;

    os_timer_disarm(&ota_timer);
    if (conn) {
        if (conn->proto.tcp) {
            os_free(conn->proto.tcp);
        }
        os_free(conn);
    }

    // is upgrade struct still around?
    // if so disconnect was from remote end, or we called
    // ourselves to cleanup a failed connection attempt
    // must ensure disconnect was for this upgrade attempt,
    // not a previous one! this call back is async so another
    // upgrade struct may have been created already
    if (upgrade && (upgrade->conn == conn)) {
        // mark connection as gone
        upgrade->conn = 0;
        // end the update process
        rboot_ota_deinit();
    }
}
/**
 * successfully connected to update server, send the request
 * @param arg
 */
void ICACHE_FLASH_ATTR upgrade_connect_cb(void *arg) 
{
    uint8 *request;

    // disable the timeout
    os_timer_disarm(&ota_timer);

    // register connection callbacks
    espconn_regist_disconcb(upgrade->conn, upgrade_disconcb);
    espconn_regist_recvcb(upgrade->conn, upgrade_recvcb);

    // http request string
    request = (uint8 *)os_malloc(512);
    if (!request) {
        DTXT("upgrade_connect_cb(): no ram\n");
        rboot_ota_deinit();
        return;
    }

    os_sprintf((char*)request,
                "GET /firmware/%s/%s?clientid=%s HTTP/1.1\r\nHost: %s\r\n" HTTP_HEADER, 
                upgrader->m_PkgId,
                upgrader->m_Filename,
                GetNodename(upgrader->m_Mqtt),
                upgrader->m_Server);

    DTXT("upgrade_connect_cb(): request = %s", (char*)request);

    // send the http request, with timeout for reply
    os_timer_setfn(&ota_timer, (os_timer_func_t *)rboot_ota_deinit, 0);
    os_timer_arm(&ota_timer, OTA_NETWORK_TIMEOUT, 0);
    espconn_sent(upgrade->conn, request, os_strlen((char*)request));
    os_free(request);
}
/**
 * connection attempt timed out
 */
void ICACHE_FLASH_ATTR connect_timeout_cb() 
{
    DTXT("connect_timeout_cb(): timeout\n");
    // not connected so don't call disconnect on the connection
    // but call our own disconnect callback to do the cleanup
    upgrade_disconcb(upgrade->conn);
}
/**
 * 
 * @param err
 * @return 
 */
const char* ICACHE_FLASH_ATTR esp_errstr(sint8 err) 
{
    switch(err) {
        case ESPCONN_OK:
            return "No error, everything OK.";
        case ESPCONN_MEM:
            return "Out of memory error.";
        case ESPCONN_TIMEOUT:
            return "Timeout.";
        case ESPCONN_RTE:
            return "Routing problem.";
        case ESPCONN_INPROGRESS:
            return "Operation in progress.";
        case ESPCONN_ABRT:
            return "Connection aborted.";
        case ESPCONN_RST:
            return "Connection reset.";
        case ESPCONN_CLSD:
            return "Connection closed.";
        case ESPCONN_CONN:
            return "Not connected.";
        case ESPCONN_ARG:
            return "Illegal argument.";
        case ESPCONN_ISCONN:
            return "Already connected.";
    }
    
    return "Unknown error";
}
/**
 * call back for lost connection
 * @param arg
 * @param errType
 */
void ICACHE_FLASH_ATTR upgrade_recon_cb(void *arg, sint8 errType) 
{
    DTXT("upgrade_recon_cb(); connection error %s\n", esp_errstr(errType));

    // not connected so don't call disconnect on the connection
    // but call our own disconnect callback to do the cleanup
    upgrade_disconcb(upgrade->conn);
}

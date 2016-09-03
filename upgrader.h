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

#ifndef UPGRADER_H
#define	UPGRADER_H

#include <github.com/mikejac/rpcmqtt.esp8266-nonos.cpp/mqtt_connector.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
    Mqtt*               m_Mqtt;
    
    const char*         m_Nodename;
    const char*         m_PkgId;
    const uint32_t*     m_Version;
    uint8_t             m_MD5Sum[16];
    
    char*               m_Server;
    int                 m_Port;
    char*               m_Filename;
} UPGRADER;

/******************************************************************************************************************
 * prototypes
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
int Upgrader_Initialize(UPGRADER* u, Mqtt* mqtt, const char* nodename, const char* pkgId, const uint32_t* version);
/**
 * 
 * @param u
 * @return 
 */
int Upgrader_Subscribe_Package(UPGRADER* u);
/**
 * 
 * @param u
 * @return 
 */
int Upgrader_Publish_Package(UPGRADER* u);
/**
 * 
 * @param u
 * @return 
 */
int Upgrader_NewPkg(UPGRADER* u);
/**
 * 
 * @param u
 * @return 
 */
int Upgrader_Run(UPGRADER* u);
/**
 * 
 * @param u
 * @param nodename
 * @param actorId
 * @param platformId
 * @param feedId
 * @param payload
 * @return 
 */
int Upgrader_Check( UPGRADER*   u,
                    const char* nodename,
                    const char* actorId,
                    const char* platformId,
                    const char* feedId,
                    const char* payload);

#ifdef	__cplusplus
}
#endif

#endif	/* UPGRADER_H */


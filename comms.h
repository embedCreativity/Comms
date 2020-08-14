/*
  Copyright (C) 2020 Embed Creativity LLC
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef COMMS_H
#define COMMS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h> // for htonl, ntohl

// Function signatures are identical to the Socket module and they're pretty obvious, right?
typedef int (*OpenServerSocket_T)(uint16_t port);
typedef int (*AcceptClient_T)(int hSocket);
typedef int (*ConnectToServer_T)(const char* szIPAddress, uint16_t portNum);
typedef int32_t (*Read_T)( int hSocket, uint8_t* buffer, uint32_t bufferLen );
typedef int32_t (*Write_T)( int hSocket, uint8_t* data, uint32_t len );
typedef void (*Close_T)( int hSocket );

typedef struct _CommsInterface_t {
    OpenServerSocket_T OpenServerSocket;
    AcceptClient_T AcceptClient;
    ConnectToServer_T ConnectToServer;
    Read_T Read;
    Write_T Write;
    Read_T SecureRead;
    Write_T SecureWrite;
    Close_T Close;
} __attribute__((__packed__))CommsInterface_t;

#endif // COMMS_H


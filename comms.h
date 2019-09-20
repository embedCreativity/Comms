/*
*    blah blah blah.  Encrypted Sockets are better than great
*
*    History:
*        November 19, 2010:  created
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


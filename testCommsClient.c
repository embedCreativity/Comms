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

#include <stdio.h>
#include "comms.h"

#define BUF_LEN 1500
#define PLAINTEXT_CLIENT_TO_SERVER_LEN          15 // + NULL terminator
const char szPlaintextClientToServer[] =        "Hello, World!\n";
#define PLAINTEXT_SERVER_TO_CLIENT_LEN          13  // + NULL terminator
const char szPlaintextServerToClient[] =        "And to you.\n";

#define CIPHERTEXT_CLIENT_TO_SERVER_LEN         44 // + NULL terminator
const char szCiphertextClientToServer[] =       "Super Secret Message from Client to Server\n";
#define CIPHERTEXT_SERVER_TO_CLIENT_LEN         41  // + NULL terminator
const char szCiphertextServerToClient[] =       "I'll never tell - don't you worry, son.\n";

const char SERVER_ADDRESS[] =  "127.0.0.1";
#define SERVER_PORT     52000

extern CommsInterface_t commsIntf;

const uint8_t cryptoKey[] = {
    0x86, 0x09, 0x1F, 0x8D, 0x16, 0x11, 0x9F, 0x9A,
    0xC9, 0x1A, 0xC2, 0xED, 0x00, 0x8D, 0x08, 0x16
};

static uint8_t buffer[BUF_LEN];
static int32_t bytesReceived = 0;

int main ( void )
{
    int hSocketIntf;

    printf("INFO: Client Attempting to connect...\n");
    hSocketIntf = commsIntf.ConnectToServer(SERVER_ADDRESS, SERVER_PORT);
    if ( -1 == hSocketIntf ) {
        printf("ERROR: Connection Failed. Exiting Program.\n");
        return -1;
    }
    printf("INFO: Connected!\n");

    // Client initiates with a plaintext message
    strncpy((char*)buffer, szPlaintextClientToServer, BUF_LEN);
    commsIntf.Write(hSocketIntf, buffer, PLAINTEXT_CLIENT_TO_SERVER_LEN); // Send string plus NULL terminator

    printf("INFO: Client initiating context by sending Plaintext Test to server - PASSED\n");
    // Server responds with another message
    bytesReceived = commsIntf.Read(hSocketIntf, buffer, BUF_LEN);
    if ( bytesReceived != PLAINTEXT_SERVER_TO_CLIENT_LEN) {
        printf("ERROR: Test 1 - Plaintext Server to client failed. %d bytes received, expecting %d.\n", bytesReceived,
            PLAINTEXT_SERVER_TO_CLIENT_LEN);
        commsIntf.Close(hSocketIntf);
        return -1;
    } else if ( 0 != (strncmp((char*)buffer, szPlaintextServerToClient, BUF_LEN)) ) {
        printf("ERROR: Test 1 - Plaintext server to client failed. Incorrect data received:");
        commsIntf.Close(hSocketIntf); // close connection to server
        return -1;
    }
    printf("INFO: Client received Plaintext response from Server - PASSED\n");

    strncpy((char*)buffer, szCiphertextClientToServer, BUF_LEN);
    commsIntf.SecureWrite(hSocketIntf, buffer, CIPHERTEXT_CLIENT_TO_SERVER_LEN); // Send string plus NULL terminator
    printf("INFO: Client sending Ciphertext to server - PASSED\n");

    // Server now sends us an encrypted string
    bytesReceived = commsIntf.SecureRead(hSocketIntf, buffer, BUF_LEN);
    if ( bytesReceived != CIPHERTEXT_SERVER_TO_CLIENT_LEN) {
        printf("ERROR: Test 2 - Ciphertext server to client failed. %d bytes received, expecting %d.\n", bytesReceived,
            CIPHERTEXT_SERVER_TO_CLIENT_LEN);
        commsIntf.Close(hSocketIntf);
        return -1;
    } else if ( 0 != (strncmp((char*)buffer, szCiphertextServerToClient, BUF_LEN)) ) {
        printf("ERROR: Test 2 - Ciphertext server to client failed. Incorrect data received:");
        commsIntf.Close(hSocketIntf); // close connection to server
        return -1;
    }
    printf("INFO: Client received Ciphertext response from Server - PASSED\n");

    commsIntf.Close(hSocketIntf); // close connection to server

    printf("INFO: Client disconnected and shutting down - Test Complete!\n");
    return 0;
}




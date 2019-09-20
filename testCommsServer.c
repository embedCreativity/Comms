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
static int hSocketIntf;

int main ( void )
{
    int hClientIntf;

    printf("INFO: Attempting to connect...\n");
    hSocketIntf = commsIntf.OpenServerSocket(SERVER_PORT);
    if ( -1 == hSocketIntf ) {
        printf("ERROR: failed to open socket\n");
        return -1;
    }

    hClientIntf = commsIntf.AcceptClient(hSocketIntf);
    if ( -1 == hClientIntf ) {
        printf("ERROR: failed to connect client\n");
        return -1;
    }

    // Client initiates communication by sending us something
    bytesReceived = commsIntf.Read(hClientIntf, buffer, BUF_LEN);
    if ( bytesReceived != PLAINTEXT_CLIENT_TO_SERVER_LEN ) {
        printf("ERROR: Test 1 - Plaintext Client to Server failed. %d bytes received, expecting %d.\n", bytesReceived,
            PLAINTEXT_CLIENT_TO_SERVER_LEN);
        commsIntf.Close(hClientIntf);
        commsIntf.Close(hSocketIntf);
        return -1;
    } else if ( 0 != (strncmp((char*)buffer, szPlaintextClientToServer, BUF_LEN)) ) {
        printf("ERROR: Test 1 - Plaintext Client to Server failed. Incorrect data received:");
        commsIntf.Close(hClientIntf);
        commsIntf.Close(hSocketIntf);
        return -1;
    }
    printf("INFO: Server: Plaintext Received From Client - PASSED\n");

    // Server responds by sending a response
    strncpy((char*)buffer, szPlaintextServerToClient, BUF_LEN);
    commsIntf.Write(hClientIntf, buffer, PLAINTEXT_SERVER_TO_CLIENT_LEN); // Send string plus NULL terminator
    printf("INFO: Server: Plaintext Sent in Response to Client - PASSED\n");

    // Client now sends us an encrypted string
    bytesReceived = commsIntf.SecureRead(hClientIntf, buffer, BUF_LEN);
    if ( bytesReceived != CIPHERTEXT_CLIENT_TO_SERVER_LEN ) {
        printf("ERROR: Test 2 - Ciphertext Client to Server failed. %d bytes received, expecting %d.\n", bytesReceived,
            CIPHERTEXT_CLIENT_TO_SERVER_LEN);
        commsIntf.Close(hClientIntf);
        commsIntf.Close(hSocketIntf);
        return -1;
    } else if ( 0 != (strncmp((char*)buffer, szCiphertextClientToServer, BUF_LEN)) ) {
        printf("ERROR: Test 2 - Ciphertext Client to Server failed. Incorrect data received:\n");
        commsIntf.Close(hClientIntf);
        commsIntf.Close(hSocketIntf);
        return -1;
    }
    printf("INFO: Server: Ciphertext Received From Client - PASSED\n");

    strncpy((char*)buffer, szCiphertextServerToClient, BUF_LEN);
    commsIntf.SecureWrite(hClientIntf, buffer, CIPHERTEXT_SERVER_TO_CLIENT_LEN); // Send string plus NULL terminator
    printf("INFO: Server: Ciphertext Sent in Response to Client - PASSED\n");

    commsIntf.Close(hClientIntf);
    commsIntf.Close(hSocketIntf);

    printf("INFO: Server shutting down - Test Complete\n");
    return 0;
}




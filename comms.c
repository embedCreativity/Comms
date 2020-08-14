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

/* ------------------------------------------------------------ */
/*                Include File Definitions                        */
/* ------------------------------------------------------------ */
#include "comms.h"
#include "socket.h"
#include "crypto.h"
#include "tlv.h" // TCP packets are marked with type info

#define MAX_MESSAGE_LEN    1500
#define BUF_LEN MAX_MESSAGE_LEN*4

static uint8_t receiveBuffer[BUF_LEN];
static uint8_t* pEnd = receiveBuffer;

extern SocketInterface_T socketIntf;
extern CryptoInterface_T cryptoIntf;

// Your application needs to declare a global 16-byte key for the algorithm.
extern const uint8_t cryptoKey[16];


static int OpenServerSocket(uint16_t port)
{
    return socketIntf.OpenServerSocket(port);
}

static int AcceptClient(int hSocket)
{
    return socketIntf.AcceptClient(hSocket);
}

static int ConnectToServer(const char* szIPAddress, uint16_t portNum)
{
    return socketIntf.ConnectToServer(szIPAddress, portNum);
}

static int32_t Read( int hSocket, uint8_t* out, uint32_t bufferLen )
{
    int32_t outLen;
    uint32_t storedLen;
    int32_t readReturn;
    uint32_t tlvLength;
    uint32_t tlvType;

    pEnd = receiveBuffer; // reset pointer into buffer

    do {
        // we always know that the start of our TLV is at the beginning of the buffer as we enter this function
        // figure out how much data we have in buffer upon entering
        storedLen = pEnd - receiveBuffer;

        // if we have the length of a TLV header stored upon entering, then we can start processing it
        if ( storedLen >= TLV_OVERHEAD ) { // we have entire header
            tlvLength = ntohl(((TLV_t*)receiveBuffer)->length);
            tlvType = ntohl(((TLV_t*)receiveBuffer)->type);
            if ( storedLen >= TLV_OVERHEAD + tlvLength) { // we have entire TLV
                if ( tlvType != TLV_COMMS_PLAINTEXT_PAYLOAD ) {
                    return -1;
                }
                if ( tlvLength == 0 ) {
                    return 0;
                }
                if ( tlvLength > bufferLen ) {
                    return -1;
                }

                // move TLV data out
                memcpy(out, ((TLV_t*)receiveBuffer)->value, tlvLength);
                outLen = tlvLength;
                if ( storedLen > (TLV_OVERHEAD + tlvLength) ) { // we are going to have data left over
                    pEnd = receiveBuffer + (storedLen - (TLV_OVERHEAD + tlvLength)); // place at end of extra data
                    // whatever is left must be moved to the start of buffer
                    memcpy(receiveBuffer, (((TLV_t*)receiveBuffer)->value + tlvLength),
                        (storedLen - (TLV_OVERHEAD + tlvLength)));
                } else { // storedLen == (TLV_OVERHEAD + tlvLength)
                    pEnd = receiveBuffer; // nothing left over, start from beginning next read
                } // end replacement of pEnd
                return outLen;
            } // end: have entire header, have entire TLV
        } // we may(not) have entire header, but certainly do NOT have entire TLV
        readReturn = socketIntf.Read(hSocket, pEnd, (BUF_LEN - (pEnd - receiveBuffer)) ); // read, fill up to max of buffer
        if ( readReturn < 0 ) {
            return -1; // failure
        }
        pEnd += readReturn;
    } while(true);
} // end Read

static int32_t Write ( int hSocket, uint8_t* data, uint32_t len )
{
    uint8_t buffer[MAX_MESSAGE_LEN];
     int32_t writeLen;
    TLV_t* pTLV;
    uint32_t i;

    pTLV = (TLV_t*)buffer;
    pTLV->type = htonl(TLV_COMMS_PLAINTEXT_PAYLOAD);
    pTLV->length = htonl(len);
    // copy input data to the value location
    memcpy(pTLV->value, data, len);

    // reset index
    i = 0;
    do {
        writeLen = socketIntf.Write(hSocket, (buffer + i), (TLV_OVERHEAD + len - i));
        i += writeLen;
        if ( writeLen < 0 ) {
            return -1;
        }
    } while ( i < (TLV_OVERHEAD + len) );

    return len;
} // end Write

static int32_t SecureRead( int hSocket, uint8_t* out, uint32_t bufferLen )
{
    CryptoHandle_T* pHandle;
    uint8_t iv[IV_LEN];
    uint8_t plainText[MAX_MESSAGE_LEN - (IV_LEN + TLV_OVERHEAD)];
    TLV_t* pTLV;

    uint32_t storedLen;
    int32_t readReturn;
    uint32_t tlvType;
    uint32_t tlvLength;

    pEnd = receiveBuffer; // reset pointer into buffer

    do {
        pHandle = NULL; // init
        // we always know that the start of our TLV is at the beginning of the buffer as we enter this function
        // figure out how much data we have in buffer upon entering
        storedLen = pEnd - receiveBuffer;

        // if we have the length of a TLV header stored upon entering, then we can start processing it
        if ( storedLen >= (IV_LEN + TLV_OVERHEAD) ) { // we have IV and entire header

            memcpy(iv, receiveBuffer, IV_LEN); // get the IV from the beginning of the payload
            pHandle = (CryptoHandle_T*)cryptoIntf.CreateCryptoHandle(iv, cryptoKey);

            if ( pHandle == NULL ) {
                return -1;
            }

            // set pointer into buffer past the iv at the beginning of the ciphertext
            cryptoIntf.Decrypt(
                pHandle,
                (receiveBuffer + IV_LEN), // in - we want to decrypt the data after the IV
                plainText, // out
                (TLV_OVERHEAD) // decrypt what's left after IV, the TLV header
            );

            pTLV = (TLV_t*)plainText; // set TLV pointer
            tlvType = ntohl(pTLV->type);
            // validate
            if ( tlvType != TLV_COMMS_ENCRYPTED_PRIMARY_PAYLOAD ) {
                cryptoIntf.FreeCryptoHandle(pHandle);
                return -1;
            }
            // get payload length
            tlvLength = ntohl(pTLV->length);
            if ( tlvLength == 0 ) {
                cryptoIntf.FreeCryptoHandle(pHandle);
                return 0;
            }
            if ( tlvLength > bufferLen ) {
                cryptoIntf.FreeCryptoHandle(pHandle);
                return -1;
            }

            if ( storedLen >= (IV_LEN + TLV_OVERHEAD + tlvLength) ) { // we have IV and entire TLV with associated payload
                // first thing, we need to decrypt ciphertext
                // set pointer into buffer past the iv at the beginning of the ciphertext
                cryptoIntf.Decrypt(
                    pHandle,
                    (receiveBuffer + IV_LEN + TLV_OVERHEAD), // we want to decrypt the TLV payload
                    plainText,
                    tlvLength // decrypt what's left after IV, the TLV payload
                );

                // move TLV data out
                memcpy(out, plainText, tlvLength); // push out decrypted data
                if ( storedLen > (IV_LEN + TLV_OVERHEAD + tlvLength) ) { // we are going to have data left over
                    pEnd = receiveBuffer + (storedLen - (IV_LEN + TLV_OVERHEAD + tlvLength)); // place at end of extra data
                    // whatever is left must be moved to the start of buffer
                    memcpy(receiveBuffer, (receiveBuffer + IV_LEN + TLV_OVERHEAD + tlvLength),
                        (storedLen - (IV_LEN + TLV_OVERHEAD + tlvLength)));
                } else { // storedLen == (TLV_OVERHEAD + tlvLength)
                    pEnd = receiveBuffer; // nothing left over, start from beginning next read
                } // end replacement of pEnd
                cryptoIntf.FreeCryptoHandle(pHandle);
                return tlvLength;
            } // end: have entire header, have entire TLV
        } // we may(not) have entire header, but certainly do NOT have entire TLV
        if ( pHandle != NULL ) {
            cryptoIntf.FreeCryptoHandle(pHandle);
        }

        readReturn = socketIntf.Read(hSocket, pEnd, (BUF_LEN - (pEnd - receiveBuffer)) ); // read, fill up to max of buffer
        if ( readReturn < 0 ) {
            return -1; // failure
        }
        pEnd += readReturn;
    } while(true);

} // end SecureRead()

static int32_t SecureWrite ( int hSocket, uint8_t* data, uint32_t len )
{
    CryptoHandle_T* pHandle;
    uint8_t buffer[MAX_MESSAGE_LEN];
    uint8_t iv[IV_LEN];
    int32_t writeLen;
    TLV_t TLV;
    uint32_t i;

    if ( len > (MAX_MESSAGE_LEN - (IV_LEN + TLV_OVERHEAD)) ) { // we have a limit of MAX_MESSAGE_LEN bytes per write() just to keep it simple
        return -1;
    }

    // Generate a random initialization vector
    srand(time(NULL));
    for ( i = 0; i < IV_LEN; i++ ) {
        iv[i] = 0xFF & rand();
    }

    // The IV goes ahead of the encrypted TLV
    memcpy(buffer, iv, IV_LEN); // put the IV at the beginning of the payload

    // Whip up a Crypto handle
    pHandle = (CryptoHandle_T*)cryptoIntf.CreateCryptoHandle(iv, cryptoKey);
    if ( pHandle == NULL ) {
        return -1;
    }

    // set TLV header data
    TLV.type = htonl(TLV_COMMS_ENCRYPTED_PRIMARY_PAYLOAD);
    TLV.length = htonl(len);

    // Encrypt the TLV
    cryptoIntf.Encrypt (
        pHandle,
        (uint8_t*)&TLV, // in - TLV wrapper
        (buffer + IV_LEN), // out - encrypted TLV goes in buffer after the plaintext IV
        TLV_OVERHEAD
    );

    // Encrypt payload data
    cryptoIntf.Encrypt (
        pHandle,
        (uint8_t*)data, // TLV wrapper
        (buffer + IV_LEN + TLV_OVERHEAD), // encrypted payload goes in buffer after the plaintext IV and previously encrypted TLV
        len
    );
    // free Crypto handle
    cryptoIntf.FreeCryptoHandle(pHandle);

    // reset index
    i = 0;
    do {
        writeLen = socketIntf.Write(hSocket, (buffer + i), (IV_LEN + TLV_OVERHEAD + len - i));
        i += writeLen;
        if ( writeLen < 0 ) {
            return -1;
        }
    } while ( i < (IV_LEN + TLV_OVERHEAD + len) );
    return len;
} // end SecureWrite

static void Close ( int hSocket )
{
    socketIntf.Close(hSocket);
}

// this is the exported comms interface
CommsInterface_t commsIntf = {
    OpenServerSocket,
    AcceptClient,
    ConnectToServer,
    Read,
    Write,
    SecureRead,
    SecureWrite,
    Close
};


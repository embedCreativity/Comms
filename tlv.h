#ifndef TLV_H
#define TLV_H

#include <stdint.h>

// TLV type codes
enum {
	TLV_COMMS_ENCRYPTED_PRIMARY_PAYLOAD = 0x00001000,
	//TLV_COMMS_ENCRYPTED_PAYLOAD_ADDITIONAL_DATA = 0x00001001,
	TLV_COMMS_PLAINTEXT_PAYLOAD = 0x00002000
};

#define TLV_OVERHEAD ((uint32_t)(sizeof(uint32_t) + sizeof(uint32_t)))

typedef struct _TLV_t {
	uint32_t type;
	uint32_t length;
	uint8_t value[0];
} __attribute__((__packed__)) TLV_t;

#endif // TLV_H


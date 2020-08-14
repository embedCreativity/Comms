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


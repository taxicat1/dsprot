#include "rom_util.h"

// Function to be encrypted (cannot be called directly)
u32 ROMUtil_CRC32(void* buf, u32 size);


u32 ROMUtil_CRC32(void* buf, u32 size) {
	u32  crc;
	u32  poly;
	u8*  byte_ptr;
	
	byte_ptr = (u8*)buf;
	crc = 0xFFFFFFFF;
	poly = 0xEDB88320;
	while (size-- != 0) {
		crc ^= *byte_ptr++;
		
		// Must be unrolled to match
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
		if (crc & 1) {  crc = (crc >> 1);  } else {  crc = poly ^ (crc >> 1);  }
	}
	
	return ~crc;
}

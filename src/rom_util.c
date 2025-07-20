#include "rom_util.h"

// Functions to be encrypted (cannot be called directly)
u32 ROMUtil_CRC32(void* buf, u32 size);


u32 ROMUtil_CRC32(void* buf, u32 size) {
	u32  crc;
	u32  poly;
	u8*  byteptr;
	
	byteptr = (u8*)buf;
	crc = 0xFFFFFFFF;
	poly = 0xEDB88320;
	while (size-- != 0) {
		crc ^= *byteptr++;
		
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

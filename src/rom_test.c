#include "rom_test.h"

#include "encryptor.h"
#include "rom_util.h"

#define ROM_BLOCK_SIZE  (0x200)


u32 ROMTest_IsBad(void) {
	// Extra CRC entries are required to match
	u32  crcs[8];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	int  i;
	u32  ret;
	
	rom_addr = 0x1000;
	for (i = 0; i < 6; i++) {
		ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		if (i == 2) {
			// Has to be like this to match
			rom_addr = 1;
			rom_addr <<= 15;
		} else {
			rom_addr += ROM_BLOCK_SIZE;
		}
	}
	
	ENCRYPTION_START(0x31F6);
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			ret = 1;
			// Likely must be a goto here
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		ret = 1;
	} else {
		ret = 0;
	}
	
EXIT:
	for (i = 0; i < ROM_BLOCK_SIZE; i++) {
		rom_buf[i] = 0;
	}
	
	ENCRYPTION_END(0x31F6);
	
	return ret;
}


u32 ROMTest_IsGood(void) {
	// Extra CRC entries are required to match
	u32  crcs[8];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	int  i;
	u32  ret;
	
	rom_addr = 0x1000;
	for (i = 0; i < 6; i++) {
		ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		if (i == 2) {
			// Has to be like this to match
			rom_addr = 1;
			rom_addr <<= 15;
		} else {
			rom_addr += ROM_BLOCK_SIZE;
		}
	}
	
	ENCRYPTION_START(0x38CA);
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			ret = 0;
			// Likely must be a goto here
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		ret = 0;
	} else {
		ret = 1;
	}
	
EXIT:
	for (i = 0; i < ROM_BLOCK_SIZE; i++) {
		rom_buf[i] = 0;
	}
	
	ENCRYPTION_END(0x38CA);
	
	return ret;
}

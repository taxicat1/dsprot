#include "rom_test.h"

#include "rom_util.h"

// Functions to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(void);
u32 ROMTest_IsGood(void);

#define ROM_BLOCK_SIZE  (0x200)


u32 ROMTest_IsBad(void) { /* ov123_02260504 */
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	int  i;
	u32  ret;
	u8*  rom_buf_ptr;
	
	rom_addr = 0x1000;
	for (i = 0; i < 6; i++) {
		RunEncrypted_ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		if (i == 2) {
			// Has to be like this to match
			rom_addr = 1;
			rom_addr <<= 15;
		} else {
			rom_addr += ROM_BLOCK_SIZE;
		}
	}
	
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
	rom_buf_ptr = &rom_buf[0];
	for (i = 0; i < ROM_BLOCK_SIZE; i++) {
		*rom_buf_ptr++ = 0;
	}
	
	return ret;
}


u32 ROMTest_IsGood(void) { /* ov123_022605C8 */
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	int  i;
	u32  ret;
	u8*  rom_buf_ptr;
	
	rom_addr = 0x1000;
	for (i = 0; i < 6; i++) {
		RunEncrypted_ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		if (i == 2) {
			// Has to be like this to match
			rom_addr = 1;
			rom_addr <<= 15;
		} else {
			rom_addr += ROM_BLOCK_SIZE;
		}
	}
	
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
	rom_buf_ptr = &rom_buf[0];
	for (i = 0; i < ROM_BLOCK_SIZE; i++) {
		*rom_buf_ptr++ = 0;
	}
	
	return ret;
}

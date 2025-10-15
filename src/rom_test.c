#include "rom_test.h"

#include "encryptor.h"
#include "keys.h"
#include "nitro_card.h"
#include "nitro_mi.h"
#include "rom_util.h"

#define ROM_BLOCK_SIZE  CARD_ROM_PAGE_SIZE


u32 ROMTest_IsBad(void) {
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  ret;
	int  i;
	u32  rom_addr;
	
	ret = 0;
	MI_CpuClear8(&rom_buf[0], ROM_BLOCK_SIZE);
	
	for (i = 0; i < 7; i++) {
		if (i > 0) {
			// If `i` is at least 4, start from 0x8000. Else, 0
			rom_addr = ((i - 1) / 3) * 0x8000;
			
			// Add 0, 0x200, or 0x400 depending on residue mod 3
			rom_addr += ((i - 1) % 3) * 0x200;
			
			// In total (with no read at i = 0):
			//   i   addr
			//  ----------
			//   1      0*
			//   2    200*
			//   3    400*
			//   4   8000
			//   5   8200
			//   6   8400
			// 
			//   * = redirected to 8000
			ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		}
		
		// This includes a CRC of the empty buffer when i = 0
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
	}
	
	ENCRYPTION_START(KEY_ROM_TEST_1);
	
	// Checking the ROM reading results were as expected:
	//   1 == 2 == 3 == 4
	//   4 != 5 and 4 != 6
	
	for (i = 1; i < 4; i++) {
		if (crcs[i] != crcs[4]) {
			ret = 1;
			goto EXIT;
		}
	}
	
	if (crcs[4] == crcs[5] && crcs[4] == crcs[6]) {
		ret = 1;
	}
	
EXIT:
	ENCRYPTION_END(KEY_ROM_TEST_1);
	
	return ret;
}

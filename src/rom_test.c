#include "rom_test.h"

#include "nitro_card.h"
#include "nitro_os.h"
#include "primes.h"
#include "rom_util.h"

// Functions to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(void);
u32 ROMTest_IsGood(void);

#define ROM_BLOCK_SIZE  CARD_ROM_PAGE_SIZE


u32 ROMTest_IsBad(void) {
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u16  lock_id;
	u32  mul;
	int  i;
	
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 3; i++) {
		// Use encrypted, obfuscated read for below 0x8000
		RunEncrypted_ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Use standard ROM reading function for above 0x8000
		CARDi_ReadRom(MI_DMA_NOT_USE, (void*)(rom_addr + 0x7000), &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+3] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		rom_addr += ROM_BLOCK_SIZE;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 3
	//   3 != 4 and 3 != 5
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			mul = PRIME_TRUE;
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		mul = PRIME_TRUE;
	} else {
		mul = PRIME_FALSE;
	}
	
EXIT:
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	return mul * PRIME_ROM_TEST_1;
}


u32 ROMTest_IsGood(void) {
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u16  lock_id;
	u32  mul;
	int  i;
	
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 3; i++) {
		// For below 8000h reads, use manual read
		RunEncrypted_ROMUtil_Read(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// For above 8000h reads, use the SDK `CARDi_ReadRom`
		// This function is patched over on flashcarts, which can be detected
		CARDi_ReadRom(MI_DMA_NOT_USE, (void*)(rom_addr + 0x7000), &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+3] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		rom_addr += ROM_BLOCK_SIZE;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 3
	//   3 != 4 and 3 != 5
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			mul = PRIME_FALSE;
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		mul = PRIME_FALSE;
	} else {
		mul = PRIME_TRUE;
	}
	
EXIT:
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	return mul * PRIME_ROM_TEST_2;
}

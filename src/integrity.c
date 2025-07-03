#include "integrity.h"

#include "primes.h"
#include "encoding_constants.h"
#include "mac_owner.h"
#include "rom_test.h"

// Functions to be encrypted (cannot be called directly)
u32 Integrity_MACOwner_IsBad(void);
u32 Integrity_MACOwner_IsGood(void);
u32 Integrity_ROMTest_IsBad(void);
u32 Integrity_ROMTest_IsGood(void);

#define INTEGRITY_OBFS_OFFSET  (0x1000)


u32 Integrity_MACOwner_IsBad(void) {
	u8*  addr;
	u32  offset;
	
	// Obfuscated handling of function address
	addr = (u8*)(((u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1]) - (ENC_VAL_1 * 2));
	addr += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	if (addr[offset+0x0] != 0x0F) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x1] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x2] != 0x8F) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x3] != 0xE1) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0x4] != 0x0C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x5] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x6] != 0x1C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x7] != 0xE0) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0x8] != 0x00) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x9] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xA] != 0xA0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xB] != 0x03) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0xC] != 0x1C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xD] != 0xc0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xE] != 0x8C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xF] != 0x12) return PRIME_INTEGRITY * PRIME_TRUE;
	
	return PRIME_INTEGRITY * PRIME_FALSE;
}


u32 Integrity_MACOwner_IsGood(void) {
	u8*  addr;
	u32  offset;
	
	// Obfuscated handling of function address
	addr = (u8*)(((u32)&RunEncrypted_MACOwner_IsGood[ENC_VAL_1]) - (ENC_VAL_1 * 2));
	addr += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	if (addr[offset+0x0] != 0x0F) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x1] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x2] != 0x8F) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x3] != 0xE1) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0x4] != 0x0C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x5] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x6] != 0x1C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x7] != 0xE0) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0x8] != 0x00) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x9] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xA] != 0xA0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xB] != 0x03) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0xC] != 0x1C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xD] != 0xc0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xE] != 0x8C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xF] != 0x12) return PRIME_INTEGRITY * PRIME_FALSE;
	
	return PRIME_INTEGRITY * PRIME_TRUE;
}


u32 Integrity_ROMTest_IsBad(void) {
	u8*  addr;
	u32  offset;
	
	// Obfuscated handling of function address
	addr = (u8*)(((u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1]) - (ENC_VAL_1 * 2));
	addr += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	if (addr[offset+0x0] != 0x0F) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x1] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x2] != 0x8F) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x3] != 0xE1) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0x4] != 0x0C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x5] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x6] != 0x1C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x7] != 0xE0) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0x8] != 0x00) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0x9] != 0xC0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xA] != 0xA0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xB] != 0x03) return PRIME_INTEGRITY * PRIME_TRUE;
	
	if (addr[offset+0xC] != 0x1C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xD] != 0xc0) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xE] != 0x8C) return PRIME_INTEGRITY * PRIME_TRUE;
	if (addr[offset+0xF] != 0x12) return PRIME_INTEGRITY * PRIME_TRUE;
	
	return PRIME_INTEGRITY * PRIME_FALSE;
}


u32 Integrity_ROMTest_IsGood(void) {
	u8*  addr;
	u32  offset;
	
	// Obfuscated handling of function address
	addr = (u8*)(((u32)&RunEncrypted_ROMTest_IsGood[ENC_VAL_1]) - (ENC_VAL_1 * 2));
	addr += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	if (addr[offset+0x0] != 0x0F) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x1] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x2] != 0x8F) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x3] != 0xE1) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0x4] != 0x0C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x5] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x6] != 0x1C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x7] != 0xE0) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0x8] != 0x00) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0x9] != 0xC0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xA] != 0xA0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xB] != 0x03) return PRIME_INTEGRITY * PRIME_FALSE;
	
	if (addr[offset+0xC] != 0x1C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xD] != 0xc0) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xE] != 0x8C) return PRIME_INTEGRITY * PRIME_FALSE;
	if (addr[offset+0xF] != 0x12) return PRIME_INTEGRITY * PRIME_FALSE;
	
	return PRIME_INTEGRITY * PRIME_TRUE;
}

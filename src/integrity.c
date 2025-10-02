#include "integrity.h"

#include "encoding_constants.h"
#include "mac_owner.h"
#include "primes.h"
#include "rom_test.h"

// Functions to be encrypted (cannot be called directly)
u32 Integrity_MACOwner_IsBad(void* __unused);
u32 Integrity_ROMTest_IsBad(void* __unused);

#define INTEGRITY_OBFS_OFFSET  (ENC_VAL_1 & ~0xFFF)


// This was likely not originally an inline, but an inline is able to match here nicely
static inline u32 checkDecryptionWrapper(u8* addr, u32 match_ret, u32 mismatch_ret) {
	u32 offset;
	
	addr += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// The bytes checked here are from the `run_encrypted_func` macro defined in asm_macro.inc:
	//   e18fc00f    orr    ip, pc, pc
	//   e01cc00c    ands   ip, ip, ip
	//   03a0c000    moveq  ip, #0
	//   128cc08c    addne  ip, ip, #140
	if (addr[offset++] != 0x0F) return mismatch_ret;
	if (addr[offset++] != 0xC0) return mismatch_ret;
	if (addr[offset++] != 0x8F) return mismatch_ret;
	if (addr[offset++] != 0xE1) return mismatch_ret;
	
	if (addr[offset++] != 0x0C) return mismatch_ret;
	if (addr[offset++] != 0xC0) return mismatch_ret;
	if (addr[offset++] != 0x1C) return mismatch_ret;
	if (addr[offset++] != 0xE0) return mismatch_ret;
	
	if (addr[offset++] != 0x00) return mismatch_ret;
	if (addr[offset++] != 0xC0) return mismatch_ret;
	if (addr[offset++] != 0xA0) return mismatch_ret;
	if (addr[offset++] != 0x03) return mismatch_ret;
	
	if (addr[offset++] != 0x8C) return mismatch_ret;
	if (addr[offset++] != 0xC0) return mismatch_ret;
	if (addr[offset++] != 0x8C) return mismatch_ret;
	if (addr[offset++] != 0x12) return mismatch_ret;
	
	return match_ret;
}


u32 Integrity_MACOwner_IsBad(void* __unused) {
	#pragma unused(__unused)
	
	u8* addr;
	addr = (u8*)ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1) - (ENC_VAL_1 * 2);
	
	return checkDecryptionWrapper(addr, PRIME_INTEGRITY * PRIME_FALSE, PRIME_INTEGRITY * PRIME_TRUE);
}


u32 Integrity_ROMTest_IsBad(void* __unused) {
	#pragma unused(__unused)
	
	u8* addr;
	addr = (u8*)ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1) - (ENC_VAL_1 * 2);
	
	return checkDecryptionWrapper(addr, PRIME_INTEGRITY * PRIME_FALSE, PRIME_INTEGRITY * PRIME_TRUE);
}

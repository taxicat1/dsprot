#include "integrity.h"

#include "mac_owner.h"
#include "rom_test.h"
#include "encoding_constants.h"

// Functions to be encrypted (cannot be called directly)
u32 Integrity_MACOwner_IsBad(void);
u32 Integrity_MACOwner_IsGood(void);
u32 Integrity_ROMTest_IsBad(void);
u32 Integrity_ROMTest_IsBad(void);
u32 Integrity_ROMTest_IsGood(void);

#define INTEGRITY_OBFS_OFFSET  (0x1000)


u32 Integrity_MACOwner_IsBad(void) { /* ov123_0225F74C */
	u32  base;
	u8*  bytes;
	u32  offset;
	u32  ret;
	
	// Obfuscated handling of function address
	base = (u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1] - (ENC_VAL_1 * 2);
	bytes = (u8*)(base + INTEGRITY_OBFS_OFFSET);
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	ret = base + 1;
	
	// Bytes of the first four instructions of the function
	if (bytes[offset+0]  != 0xF0) return ret;
	if (bytes[offset+1]  != 0x00) return ret;
	if (bytes[offset+2]  != 0x2D) return ret;
	if (bytes[offset+3]  != 0xE9) return ret;
	
	if (bytes[offset+4]  != 0x0F) return ret;
	if (bytes[offset+5]  != 0x00) return ret;
	if (bytes[offset+6]  != 0x2D) return ret;
	if (bytes[offset+7]  != 0xE9) return ret;
	
	if (bytes[offset+8]  != 0xF0) return ret;
	if (bytes[offset+9]  != 0x00) return ret;
	if (bytes[offset+10] != 0xBD) return ret;
	if (bytes[offset+11] != 0xE8) return ret;
	
	if (bytes[offset+12] != 0x60) return ret;
	if (bytes[offset+13] != 0x10) return ret;
	if (bytes[offset+14] != 0x9F) return ret;
	if (bytes[offset+15] != 0xE5) return ret;
	
	return 0;
}


u32 Integrity_MACOwner_IsGood(void) { /* ov123_0225F824 */
	u32  base;
	u32  ret;
	u32  offset;
	
	// Obfuscated handling of function address
	base = (u32)&RunEncrypted_MACOwner_IsGood[ENC_VAL_1] - (ENC_VAL_1 * 2);
	ret = base;
	base += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	// (Has to be like this to match, `(u8*)base` as a varible causes regswaps)
	if (((u8*)base)[offset+0]  != 0xF0) return 0;
	if (((u8*)base)[offset+1]  != 0x00) return 0;
	if (((u8*)base)[offset+2]  != 0x2D) return 0;
	if (((u8*)base)[offset+3]  != 0xE9) return 0;
	
	if (((u8*)base)[offset+4]  != 0x0F) return 0;
	if (((u8*)base)[offset+5]  != 0x00) return 0;
	if (((u8*)base)[offset+6]  != 0x2D) return 0;
	if (((u8*)base)[offset+7]  != 0xE9) return 0;
	
	if (((u8*)base)[offset+8]  != 0xF0) return 0;
	if (((u8*)base)[offset+9]  != 0x00) return 0;
	if (((u8*)base)[offset+10] != 0xBD) return 0;
	if (((u8*)base)[offset+11] != 0xE8) return 0;
	
	if (((u8*)base)[offset+12] != 0x60) return 0;
	if (((u8*)base)[offset+13] != 0x10) return 0;
	if (((u8*)base)[offset+14] != 0x9F) return 0;
	if (((u8*)base)[offset+15] != 0xE5) return 0;
	
	return ret + 1;
}


u32 Integrity_ROMTest_IsBad(void) { /* ov123_0225F938 */
	u32  base;
	u8*  bytes;
	u32  offset;
	u32  ret;
	
	// Obfuscated handling of function address
	base = (u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1] - (ENC_VAL_1 * 2);
	bytes = (u8*)(base + INTEGRITY_OBFS_OFFSET);
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	ret = base + 1;
	
	// Bytes of the first four instructions of the function
	if (bytes[offset+0]  != 0xF0) return ret;
	if (bytes[offset+1]  != 0x00) return ret;
	if (bytes[offset+2]  != 0x2D) return ret;
	if (bytes[offset+3]  != 0xE9) return ret;
	
	if (bytes[offset+4]  != 0x0F) return ret;
	if (bytes[offset+5]  != 0x00) return ret;
	if (bytes[offset+6]  != 0x2D) return ret;
	if (bytes[offset+7]  != 0xE9) return ret;
	
	if (bytes[offset+8]  != 0xF0) return ret;
	if (bytes[offset+9]  != 0x00) return ret;
	if (bytes[offset+10] != 0xBD) return ret;
	if (bytes[offset+11] != 0xE8) return ret;
	
	if (bytes[offset+12] != 0x60) return ret;
	if (bytes[offset+13] != 0x10) return ret;
	if (bytes[offset+14] != 0x9F) return ret;
	if (bytes[offset+15] != 0xE5) return ret;
	
	return 0;
}


u32 Integrity_ROMTest_IsGood(void) { /* ov123_0225FA10 */
	u32  base;
	u32  ret;
	u32  offset;
	
	// Obfuscated handling of function address
	base = (u32)&RunEncrypted_ROMTest_IsGood[ENC_VAL_1] - (ENC_VAL_1 * 2);
	ret = base;
	base += INTEGRITY_OBFS_OFFSET;
	offset = ENC_VAL_1 - INTEGRITY_OBFS_OFFSET;
	
	// Bytes of the first four instructions of the function
	// (Has to be like this to match, `(u8*)base` as a varible causes regswaps)
	if (((u8*)base)[offset+0]  != 0xF0) return 0;
	if (((u8*)base)[offset+1]  != 0x00) return 0;
	if (((u8*)base)[offset+2]  != 0x2D) return 0;
	if (((u8*)base)[offset+3]  != 0xE9) return 0;
	
	if (((u8*)base)[offset+4]  != 0x0F) return 0;
	if (((u8*)base)[offset+5]  != 0x00) return 0;
	if (((u8*)base)[offset+6]  != 0x2D) return 0;
	if (((u8*)base)[offset+7]  != 0xE9) return 0;
	
	if (((u8*)base)[offset+8]  != 0xF0) return 0;
	if (((u8*)base)[offset+9]  != 0x00) return 0;
	if (((u8*)base)[offset+10] != 0xBD) return 0;
	if (((u8*)base)[offset+11] != 0xE8) return 0;
	
	if (((u8*)base)[offset+12] != 0x60) return 0;
	if (((u8*)base)[offset+13] != 0x10) return 0;
	if (((u8*)base)[offset+14] != 0x9F) return 0;
	if (((u8*)base)[offset+15] != 0xE5) return 0;
	
	return ret + 1;
}

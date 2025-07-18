#include "integrity.h"

#include "encryptor.h"
#include "mac_owner.h"
#include "rom_test.h"

#define INTEGRITY_OBFS_OFFSET  (0x10C)


u32 Integrity_MACOwner_IsBad(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(0x63ED);
	
	addr = (u8*)MACOwner_IsBad - INTEGRITY_OBFS_OFFSET;
	ret = (u32)addr + 1;
	
	if (
		// First three instructions of the function
		addr[INTEGRITY_OBFS_OFFSET+0x0] == 0xF8 && 
		addr[INTEGRITY_OBFS_OFFSET+0x1] == 0x4F && 
		addr[INTEGRITY_OBFS_OFFSET+0x2] == 0x2D && 
		addr[INTEGRITY_OBFS_OFFSET+0x3] == 0xE9 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x4] == 0x60 && 
		addr[INTEGRITY_OBFS_OFFSET+0x5] == 0xD0 && 
		addr[INTEGRITY_OBFS_OFFSET+0x6] == 0x4D && 
		addr[INTEGRITY_OBFS_OFFSET+0x7] == 0xE2 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x8] == 0x02 && 
		addr[INTEGRITY_OBFS_OFFSET+0x9] == 0x00 && 
		addr[INTEGRITY_OBFS_OFFSET+0xA] == 0x8D && 
		addr[INTEGRITY_OBFS_OFFSET+0xB] == 0xE2
	) {
		// x ^ x == 0, but must be like this to match
		ret = (u32)addr ^ (u32)addr;
	}
	
	ENCRYPTION_END(0x63ED);
	
	return ret;
}


u32 Integrity_MACOwner_IsGood(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(0x0BAE);
	
	addr = (u8*)MACOwner_IsGood - INTEGRITY_OBFS_OFFSET;
	// x ^ x == 0, but must be like this to match
	ret = (u32)addr ^ (u32)addr;
	
	if (
		// First three instructions of the function
		addr[INTEGRITY_OBFS_OFFSET+0x0] == 0xF8 && 
		addr[INTEGRITY_OBFS_OFFSET+0x1] == 0x4F && 
		addr[INTEGRITY_OBFS_OFFSET+0x2] == 0x2D && 
		addr[INTEGRITY_OBFS_OFFSET+0x3] == 0xE9 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x4] == 0x60 && 
		addr[INTEGRITY_OBFS_OFFSET+0x5] == 0xD0 && 
		addr[INTEGRITY_OBFS_OFFSET+0x6] == 0x4D && 
		addr[INTEGRITY_OBFS_OFFSET+0x7] == 0xE2 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x8] == 0x02 && 
		addr[INTEGRITY_OBFS_OFFSET+0x9] == 0x00 && 
		addr[INTEGRITY_OBFS_OFFSET+0xA] == 0x8D && 
		addr[INTEGRITY_OBFS_OFFSET+0xB] == 0xE2
	) {
		ret = (u32)addr + 1;
	}
	
	ENCRYPTION_END(0x0BAE);
	
	return ret;
}


u32 Integrity_ROMTest_IsBad(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(0x1800);
	
	addr = (u8*)ROMTest_IsBad - INTEGRITY_OBFS_OFFSET;
	ret = (u32)addr + 1;
	
	if (
		// First four instructions of the function
		addr[INTEGRITY_OBFS_OFFSET+0x0] == 0xF0 && 
		addr[INTEGRITY_OBFS_OFFSET+0x1] == 0x4F && 
		addr[INTEGRITY_OBFS_OFFSET+0x2] == 0x2D && 
		addr[INTEGRITY_OBFS_OFFSET+0x3] == 0xE9 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x4] == 0x89 && 
		addr[INTEGRITY_OBFS_OFFSET+0x5] == 0xDF && 
		addr[INTEGRITY_OBFS_OFFSET+0x6] == 0x4D && 
		addr[INTEGRITY_OBFS_OFFSET+0x7] == 0xE2 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x8] == 0x01 && 
		addr[INTEGRITY_OBFS_OFFSET+0x9] == 0xC0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xA] == 0xA0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xB] == 0xE3 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0xC] == 0x8C && 
		addr[INTEGRITY_OBFS_OFFSET+0xD] == 0xC7 && 
		addr[INTEGRITY_OBFS_OFFSET+0xE] == 0xA0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xF] == 0xE1
	) {
		// x ^ x == 0, but must be like this to match
		ret = (u32)addr ^ (u32)addr;
	}
	
	ENCRYPTION_END(0x1800);
	
	return ret;
}


u32 Integrity_ROMTest_IsGood(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(0x093F);
	
	addr = (u8*)ROMTest_IsGood - INTEGRITY_OBFS_OFFSET;
	// x ^ x == 0, but must be like this to match
	ret = (u32)addr ^ (u32)addr;
	
	if (
		// First four instructions of the function
		addr[INTEGRITY_OBFS_OFFSET+0x0] == 0xF0 && 
		addr[INTEGRITY_OBFS_OFFSET+0x1] == 0x4F && 
		addr[INTEGRITY_OBFS_OFFSET+0x2] == 0x2D && 
		addr[INTEGRITY_OBFS_OFFSET+0x3] == 0xE9 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x4] == 0x89 && 
		addr[INTEGRITY_OBFS_OFFSET+0x5] == 0xDF && 
		addr[INTEGRITY_OBFS_OFFSET+0x6] == 0x4D && 
		addr[INTEGRITY_OBFS_OFFSET+0x7] == 0xE2 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0x8] == 0x01 && 
		addr[INTEGRITY_OBFS_OFFSET+0x9] == 0xC0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xA] == 0xA0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xB] == 0xE3 && 
		
		addr[INTEGRITY_OBFS_OFFSET+0xC] == 0x8C && 
		addr[INTEGRITY_OBFS_OFFSET+0xD] == 0xC7 && 
		addr[INTEGRITY_OBFS_OFFSET+0xE] == 0xA0 && 
		addr[INTEGRITY_OBFS_OFFSET+0xF] == 0xE1
	) {
		ret = (u32)addr + 1;
	}
	
	ENCRYPTION_END(0x093F);
	
	return ret;
}

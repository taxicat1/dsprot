#include "integrity.h"

#include "encryptor.h"
#include "keys.h"
#include "mac_owner.h"
#include "rom_test.h"

#define INTEGRITY_OBFS_OFFSET  (0x10C)

// The bytes checked here can only be obtained by compiling and then disassembling
// mac_owner.c and rom_test.c. This is not ideal, and this requirement was removed in 
// future versions by instead checking the instructions of assembly functions.


u32 Integrity_MACOwner_IsBad(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(KEY_INTEGRITY_1);
	
	addr = (u8*)&MACOwner_IsBad - INTEGRITY_OBFS_OFFSET;
	ret = (u32)addr + 1;
	
	if (
		// <MACOwner_IsBad> disassembly:
		//   e92d4ff8  push  {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
		//   e24dd060  sub   sp, sp, #96  @ 0x60
		//   e28d0002  add   r0, sp, #2
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
		
		// Only three instructions are checked here because the 4th instruction is a function call
	) {
		// x ^ x == 0, but must be like this to match
		ret = (u32)addr ^ (u32)addr;
	}
	
	ENCRYPTION_END(KEY_INTEGRITY_1);
	
	return ret;
}


u32 Integrity_MACOwner_IsGood(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(KEY_INTEGRITY_2);
	
	addr = (u8*)&MACOwner_IsGood - INTEGRITY_OBFS_OFFSET;
	// x ^ x == 0, but must be like this to match
	ret = (u32)addr ^ (u32)addr;
	
	if (
		// <MACOwner_IsGood> disassembly:
		//   e92d4ff8  push  {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
		//   e24dd060  sub   sp, sp, #96  @ 0x60
		//   e28d0002  add   r0, sp, #2
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
		
		// Only three instructions are checked here because the 4th instruction is a function call
	) {
		ret = (u32)addr + 1;
	}
	
	ENCRYPTION_END(KEY_INTEGRITY_2);
	
	return ret;
}


u32 Integrity_ROMTest_IsBad(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(KEY_INTEGRITY_3);
	
	addr = (u8*)&ROMTest_IsBad - INTEGRITY_OBFS_OFFSET;
	ret = (u32)addr + 1;
	
	if (
		// <ROMTest_IsBad> disassembly:
		//   e92d4ff0  push  {r4, r5, r6, r7, r8, r9, sl, fp, lr}
		//   e24ddf89  sub   sp, sp, #548  @ 0x224
		//   e3a0c001  mov   ip, #1
		//   e1a0c78c  lsl   ip, ip, #15
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
	
	ENCRYPTION_END(KEY_INTEGRITY_3);
	
	return ret;
}


u32 Integrity_ROMTest_IsGood(void) {
	u32  ret;
	u8*  addr;
	
	ENCRYPTION_START(KEY_INTEGRITY_4);
	
	addr = (u8*)&ROMTest_IsGood - INTEGRITY_OBFS_OFFSET;
	// x ^ x == 0, but must be like this to match
	ret = (u32)addr ^ (u32)addr;
	
	if (
		// <ROMTest_IsGood> disassembly:
		//   e92d4ff0  push  {r4, r5, r6, r7, r8, r9, sl, fp, lr}
		//   e24ddf89  sub   sp, sp, #548  @ 0x224
		//   e3a0c001  mov   ip, #1
		//   e1a0c78c  lsl   ip, ip, #15
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
	
	ENCRYPTION_END(KEY_INTEGRITY_4);
	
	return ret;
}

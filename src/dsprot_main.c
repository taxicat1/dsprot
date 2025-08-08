/* No dedicated header */

#include "types.h"
#include "keys.h"

#include "encryptor.h"
#include "rom_test.h"
#include "mac_owner.h"

// Exported functions
u32 __DSProt_DetectFlashcart(u32 callback_addr);
u32 __DSProt_DetectNotFlashcart(u32 callback_addr);
u32 __DSProt_DetectEmulator(u32 callback_addr);
u32 __DSProt_DetectNotEmulator(u32 callback_addr);
u32 __DSProt_DetectDummy(u32 callback_addr);
u32 __DSProt_DetectNotDummy(u32 callback_addr);

#define DSP_OBFS_OFFSET  (0x320)

typedef u32 (*U32Func)(void);
typedef void (*VoidFunc)(void);

// Possible TODO: get a `static inline executeFunctionQueue` to match here as in other versions


u32 __DSProt_DetectFlashcart(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	func_queue[0] = (u32)&ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_1);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_1);
	
	return result;
}


u32 __DSProt_DetectNotFlashcart(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	func_queue[0] = (u32)&ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_2);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_2);
	
	return result;
}


u32 __DSProt_DetectEmulator(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	func_queue[0] = (u32)&MACOwner_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_3);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_3);
	
	return result;
}


u32 __DSProt_DetectNotEmulator(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	func_queue[0] = (u32)&MACOwner_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_4);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_4);
	
	return result;
}


u32 __DSProt_DetectDummy(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_5);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_5);
	
	return result;
}


u32 __DSProt_DetectNotDummy(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	u32   result;
	
	result = 0;
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = 0;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != 0; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((U32Func)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_6);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback_addr != 0 && result != 0) {
		((VoidFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_6);
	
	return result;
}

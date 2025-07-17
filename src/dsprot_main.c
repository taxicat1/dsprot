/* No dedicated header */

#include "types.h"

#include "encryptor.h"
#include "rom_test.h"
#include "mac_owner.h"

// Exported functions
u32 DSProt_DetectFlashcart(void* callback);
u32 DSProt_DetectNotFlashcart(void* callback);
u32 DSProt_DetectEmulator(void* callback);
u32 DSProt_DetectNotEmulator(void* callback);
u32 DSProt_DetectDummy(void* callback);
u32 DSProt_DetectNotDummy(void* callback);

#define DSP_OBFS_OFFSET  (0x320)

typedef u32 (*U32Func)(void);
typedef void (*VoidFunc)(void);

// Possible TODO: get a `static inline executeFunctionQueue` to match here as in other versions


u32 DSProt_DetectFlashcart(void* callback) {
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
	
	ENCRYPTION_START(0x4EF9);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x4EF9);
	
	return result;
}


u32 DSProt_DetectNotFlashcart(void* callback) {
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
	
	ENCRYPTION_START(0x292E);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x292E);
	
	return result;
}


u32 DSProt_DetectEmulator(void* callback) {
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
	
	ENCRYPTION_START(0x1186);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x1186);
	
	return result;
}


u32 DSProt_DetectNotEmulator(void* callback) {
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
	
	ENCRYPTION_START(0x1CC4);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x1CC4);
	
	return result;
}


u32 DSProt_DetectDummy(void* callback) {
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
	
	ENCRYPTION_START(0x72A8);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 1;
	} else if (func_result_sum == 0) {
		result = 0;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x72A8);
	
	return result;
}


u32 DSProt_DetectNotDummy(void* callback) {
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
	
	ENCRYPTION_START(0x7CD4);
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = 0;
	} else if (func_result_sum == 0) {
		result = 1;
	}
	
	if (callback != NULL && result != 0) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(0x7CD4);
	
	return result;
}

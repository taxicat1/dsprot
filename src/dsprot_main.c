/* No dedicated header */

#include "types.h"
#include "keys.h"

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
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = TRUE;
	} else if (func_result_sum == 0) {
		result = FALSE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_1);
	
	return result;
}


u32 DSProt_DetectNotFlashcart(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = FALSE;
	} else if (func_result_sum == 0) {
		result = TRUE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_2);
	
	return result;
}


u32 DSProt_DetectEmulator(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = TRUE;
	} else if (func_result_sum == 0) {
		result = FALSE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_3);
	
	return result;
}


u32 DSProt_DetectNotEmulator(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = FALSE;
	} else if (func_result_sum == 0) {
		result = TRUE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_4);
	
	return result;
}


u32 DSProt_DetectDummy(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = TRUE;
	} else if (func_result_sum == 0) {
		result = FALSE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_5);
	
	return result;
}


u32 DSProt_DetectNotDummy(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  result;
	
	result = FALSE;
	
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
	
	func_result_sum >>= 1;
	if (func_result_sum) {
		result = FALSE;
	} else if (func_result_sum == 0) {
		result = TRUE;
	}
	
	if (callback != NULL && result) {
		((VoidFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_6);
	
	return result;
}

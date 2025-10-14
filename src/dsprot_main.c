/* No dedicated header */

#include "encryptor.h"
#include "keys.h"
#include "nitro_types.h"
#include "rom_test.h"

// Exported functions
u32 __DSProt_DetectFlashcart(u32 callback_addr);
u32 __DSProt_DetectNotFlashcart(u32 callback_addr);
u32 __DSProt_DetectEmulator(u32 callback_addr);
u32 __DSProt_DetectNotEmulator(u32 callback_addr);
u32 __DSProt_DetectDummy(u32 callback_addr);
u32 __DSProt_DetectNotDummy(u32 callback_addr);

#define DSP_OBFS_OFFSET  (0x190)

#define FUNC_QUEUE_END  (0)

typedef u32 (*TaskFunc)(void);
typedef void (*CallbackFunc)(void);


u32 __DSProt_DetectFlashcart(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  ret;
	
	ret = FALSE;
	
	func_queue[0] = (u32)&ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = FUNC_QUEUE_END;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != FUNC_QUEUE_END; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((TaskFunc)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_1);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum != 0) {
		ret = TRUE;
	} else if (func_result_sum == 0) {
		ret = FALSE;
	}
	
	if (callback_addr != 0 && ret) {
		((CallbackFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_1);
	
	return (u32)ret;
}


u32 __DSProt_DetectNotFlashcart(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  ret;
	
	ret = FALSE;
	
	func_queue[0] = (u32)&ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = FUNC_QUEUE_END;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != FUNC_QUEUE_END; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((TaskFunc)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_2);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum != 0) {
		ret = FALSE;
	} else if (func_result_sum == 0) {
		ret = TRUE;
	}
	
	if (callback_addr != 0 && ret) {
		((CallbackFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_2);
	
	return (u32)ret;
}


u32 __DSProt_DetectDummy(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  ret;
	
	ret = FALSE;
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = FUNC_QUEUE_END;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != FUNC_QUEUE_END; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((TaskFunc)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_3);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum != 0) {
		ret = TRUE;
	} else if (func_result_sum == 0) {
		ret = FALSE;
	}
	
	if (callback_addr != 0 && ret) {
		((CallbackFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_3);
	
	return (u32)ret;
}


u32 __DSProt_DetectNotDummy(u32 callback_addr) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	BOOL  ret;
	
	ret = FALSE;
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = FUNC_QUEUE_END;
	
	func_result_sum = 0;
	for (i = 0; func_queue[i] != FUNC_QUEUE_END; i++) {
		func_queue[i] -= DSP_OBFS_OFFSET;
		
		func_result = ((TaskFunc)(func_queue[i]))() != 0;
		func_result_sum += func_result;
		func_result_sum <<= 1;
	}
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_4);
	
	callback_addr ^= DSP_OBFS_OFFSET;
	
	func_result_sum >>= 1;
	if (func_result_sum != 0) {
		ret = FALSE;
	} else if (func_result_sum == 0) {
		ret = TRUE;
	}
	
	if (callback_addr != 0 && ret) {
		((CallbackFunc)callback_addr)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_4);
	
	return (u32)ret;
}

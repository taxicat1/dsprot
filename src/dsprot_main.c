/* No dedicated header */

#include "encryptor.h"
#include "integrity.h"
#include "keys.h"
#include "mac_owner.h"
#include "nitro_types.h"
#include "rom_test.h"

// Exported functions
u32 DSProt_DetectFlashcart(void* callback);
u32 DSProt_DetectNotFlashcart(void* callback);
u32 DSProt_DetectEmulator(void* callback);
u32 DSProt_DetectNotEmulator(void* callback);
u32 DSProt_DetectDummy(void* callback);
u32 DSProt_DetectNotDummy(void* callback);

#define DSP_OBFS_OFFSET  (0x320)

typedef u32 (*TaskFunc)(void);
typedef void (*CallbackFunc)(void);


u32 DSProt_DetectFlashcart(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_1);
	
	func_queue[0] = (u32)&ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&Integrity_ROMTest_IsBad + DSP_OBFS_OFFSET;
	func_queue[2] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) & (compare_sum >> 1)) != 0;
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_1);
	
	return compare_sum;
}


u32 DSProt_DetectNotFlashcart(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_2);
	
	func_queue[0] = (u32)&ROMTest_IsGood + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&Integrity_ROMTest_IsGood + DSP_OBFS_OFFSET;
	func_queue[2] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) == (compare_sum >> 1));
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_2);
	
	return compare_sum;
}


u32 DSProt_DetectEmulator(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_3);
	
	func_queue[0] = (u32)&MACOwner_IsBad + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&Integrity_MACOwner_IsBad + DSP_OBFS_OFFSET;
	func_queue[2] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) & (compare_sum >> 1)) != 0;
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_3);
	
	return compare_sum;
}


u32 DSProt_DetectNotEmulator(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_4);
	
	func_queue[0] = (u32)&MACOwner_IsGood + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&Integrity_MACOwner_IsGood + DSP_OBFS_OFFSET;
	func_queue[2] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) == (compare_sum >> 1));
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_4);
	
	return compare_sum;
}


u32 DSProt_DetectDummy(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_5);
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) & (compare_sum >> 1)) != 0;
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_5);
	
	return compare_sum;
}


u32 DSProt_DetectNotDummy(void* callback) {
	u32   func_queue[32];
	BOOL  func_result;
	s32   func_result_sum;
	u32   i;
	s32   compare_sum;
	
	ENCRYPTION_START(KEY_DSPROT_MAIN_6);
	
	// Not optimized out here due to the asm inlines produced by the encryption macros
	func_queue[0] = 0;
	
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((TaskFunc)(func_queue[i] - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	compare_sum = ((func_result_sum >> 1) == (compare_sum >> 1));
	
	if (callback != NULL && compare_sum != 0) {
		((CallbackFunc)callback)();
	}
	
	ENCRYPTION_END(KEY_DSPROT_MAIN_6);
	
	return compare_sum;
}

/* No dedicated header */

#include "types.h"

#include "primes.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "rom_test.h"
#include "mac_owner.h"
#include "dummy.h"

// Functions to be encrypted (cannot be called directly)
u32 DetectFlashcart(void* callback, void* param);
u32 DetectNotFlashcart(void* callback, void* param);
u32 DetectEmulator(void* callback, void* param);
u32 DetectNotEmulator(void* callback, void* param);
u32 DetectDummy(void* callback, void* param);
u32 DetectNotDummy(void* callback, void* param);

static inline u32 executeFunctionQueue(u32* func_queue_ptr);

#define DSP_OBFS_OFFSET  (0x320)

typedef u32 (*U32Func)(void);
typedef u32 (*ArgFunc)(void*);


// This was likely not originally an inline, but an inline is able to match here nicely
static inline u32 executeFunctionQueue(u32* func_queue_ptr) {
	u32 func_checksum;
	
	func_checksum = PRIME_DSPROT_MAIN * PRIME_TRUE * PRIME_FALSE;
	do {
		func_checksum += ((U32Func)(*func_queue_ptr - ENC_VAL_1 - DSP_OBFS_OFFSET))();
		func_queue_ptr++;
	} while(*func_queue_ptr != 0);
	
	return func_checksum;
}


u32 DetectFlashcart(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if ((ret % PRIME_FALSE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}


u32 DetectNotFlashcart(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if (!(ret % PRIME_TRUE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}


u32 DetectEmulator(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if ((ret % PRIME_FALSE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}


u32 DetectNotEmulator(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if (!(ret % PRIME_TRUE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}


u32 DetectDummy(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	// No integrity check on dummy detectors
	func_queue[0] = (u32)&RunEncrypted_Dummy_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if ((ret % PRIME_FALSE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}


u32 DetectNotDummy(void* callback, void* param) {
	u32  func_queue[32];
	u32  ret;
	
	// No integrity check on dummy detectors
	func_queue[0] = (u32)&RunEncrypted_Dummy_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = 0;
	
	ret = executeFunctionQueue(&func_queue[0]);
	if (!(ret % PRIME_TRUE) && callback != NULL) {
		ret = (u32)((ArgFunc)callback)(param);
	}
	
	return ret;
}

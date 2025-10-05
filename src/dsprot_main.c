/* No dedicated header */

#include "dummy.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "mac_owner.h"
#include "nitro_types.h"
#include "primes.h"
#include "rom_test.h"

// Functions to be encrypted (cannot be called directly)
u32 DetectFlashcart(void* callback, void* param, u32 __unused);
u32 DetectNotFlashcart(void* callback, void* param, u32 __unused);
u32 DetectEmulator(void* callback, void* param, u32 __unused);
u32 DetectNotEmulator(void* callback, void* param, u32 __unused);
u32 DetectDummy(void* callback, void* param, u32 __unused);
u32 DetectNotDummy(void* callback, void* param, u32 __unused);

#define DSP_OBFS_OFFSET  (0x320)

#define FUNC_QUEUE_END  (0)

typedef u32 (*TaskFunc)(void);
typedef u32 (*CallbackFunc)(void*);

enum {
	EXPECT_FALSE,
	EXPECT_TRUE
};


// This was likely not originally an inline, but an inline is able to match here nicely
static inline u32 dsprotMain(u32* func_queue_ptr, int expected_result, void* callback, void* param) {
	u32 func_ret_total;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_TRUE * PRIME_FALSE;
	do {
		func_ret_total += ((TaskFunc)(*func_queue_ptr - ENC_VAL_1 - DSP_OBFS_OFFSET))();
		func_queue_ptr++;
	} while (*func_queue_ptr != FUNC_QUEUE_END);
	
	if (expected_result == EXPECT_TRUE) {
		if (!(func_ret_total % PRIME_TRUE)) {
			return ((CallbackFunc)callback)(param);
		}
	} else {
		if (func_ret_total % PRIME_FALSE) {
			return ((CallbackFunc)callback)(param);
		}
	}
	
	return func_ret_total;
}


u32 DetectFlashcart(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsBad, ENC_VAL_1) + DSP_OBFS_OFFSET;
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, callback, param);
}


u32 DetectNotFlashcart(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsGood, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsGood, ENC_VAL_1) + DSP_OBFS_OFFSET;
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, callback, param);
}


u32 DetectEmulator(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsBad, ENC_VAL_1) + DSP_OBFS_OFFSET;
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, callback, param);
}


u32 DetectNotEmulator(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsGood, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsGood, ENC_VAL_1) + DSP_OBFS_OFFSET;
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, callback, param);
}


u32 DetectDummy(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	// No integrity check on dummy detectors
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_Dummy_IsBad, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = FUNC_QUEUE_END;
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, callback, param);
}


u32 DetectNotDummy(void* callback, void* param, u32 __unused) {
	#pragma unused(__unused)
	
	u32 func_queue[32];
	
	// No integrity check on dummy detectors
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_Dummy_IsGood, ENC_VAL_1) + DSP_OBFS_OFFSET;
	func_queue[1] = FUNC_QUEUE_END;
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, callback, param);
}

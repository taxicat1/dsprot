/* No dedicated header */

#include "callback.h"
#include "dsprot_types.h"
#include "encoding_constants.h"
#include "failure_codes.h"
#include "integrity.h"
#include "mac_owner.h"
#include "nitro_types.h"
#include "primes.h"
#include "rom_test.h"

// Functions to be encrypted (cannot be called directly)
void* DetectFlashcartA(void* param1, void* param2);
void* DetectFlashcartB(void* param1, void* param2);
void* DetectEmulatorA(void* param1, void* param2);
void* DetectEmulatorB(void* param1, void* param2);

#define DSP_OBFS_OFFSET  (ENC_VAL_1 & 0xFFF)

#define FUNC_QUEUE_END  (0)

// This checksum value is derived from the first 9 instructions of the `run_encrypted_func` macro in asm_macro.inc:
//   e18fc00f    orr    ip, pc, pc
//   e01cc00c    ands   ip, ip, ip
//   03a0c000    moveq  ip, #0
//   128cc01c    addne  ip, ip, #28
//   e59cc014    ldr    ip, [ip, #20]
//   e24ccc17    sub    ip, ip, #5888  @ 0x1700
//   e92d1000    stmfd  sp!, {ip}
//   e18fc00f    orr    ip, pc, pc
//   e8bd8000    ldmfd  sp!, {pc}

#define DSP_CHECKSUM_INS       (9)
#define DSP_EXPECTED_CHECKSUM  (0x9FBB82E0)

typedef u32 (*DSProt_Task)(DSProt_Ctx*);

enum {
	EXPECT_FALSE,
	EXPECT_TRUE
};


static inline void populateCallbacks(DSProt_Ctx* ctx) {
	DSProt_Callback*  callback_tbl_ptr;
	u32*              callback_idx_ptr;
	u32               addr;
	u32               idx;
	
	addr = ADDR_PLUS_ADDEND(DSProt_CallbackIndex, ENC_VAL_1);
	addr -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	callback_idx_ptr = (u32*)(addr - DSP_OBFS_OFFSET);
	
	addr = ADDR_PLUS_ADDEND(DSProt_CallbackTable, ENC_VAL_1);
	addr -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	callback_tbl_ptr = (DSProt_Callback*)(addr - DSP_OBFS_OFFSET);
	
	idx = *callback_idx_ptr;
	
	ctx->success_callback = callback_tbl_ptr[idx];
	ctx->failure_callback = callback_tbl_ptr[idx ^ 1];
}


static inline void* dsprotMain(u32* func_queue_ptr, int expected_result, void* param1, void* param2) {
	DSProt_Ctx   work;
	u32          func_ret_total;
	DSProt_Task  task_func;
	u32          func_data_checksum;
	u32*         func_data_ptr;
	u32          func_ret;
	u32          i;
	u32          prime_bool;
	
	populateCallbacks(&work);
	
	work.callback_param_1        = param1;
	work.callback_param_2        = param2;
	work.failure_callback_return = NULL;
	work.failure_code            = FAILURE_CODE_NONE;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = DSP_CHECKSUM_INS;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return != NULL) {
				return work.failure_callback_return;
			} else {
				return work.failure_callback(param1, param2);
			}
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == FAILURE_CODE_NONE) {
			if (work.failure_callback_return != NULL) {
				return work.failure_callback_return;
			} else {
				return work.failure_callback(param1, param2);
			}
		}
		
		func_ret_total += func_ret;
		func_queue_ptr++;
	} while (*func_queue_ptr != FUNC_QUEUE_END);
	
	// Check if total matches expected result
	if (expected_result == EXPECT_TRUE) {
		prime_bool = PRIME_TRUE;
	} else {
		prime_bool = PRIME_FALSE;
	}
	
	if (!(func_ret_total % prime_bool)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code != FAILURE_CODE_NONE) {
			return work.failure_callback_return;
		} else {
			return work.failure_callback(param1, param2);
		}
	}
}


void* DetectFlashcartA(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsBad, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, param1, param2);
}


void* DetectFlashcartB(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsGood, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsGood, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, param1, param2);
}


void* DetectEmulatorA(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsBad, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, param1, param2);
}


void* DetectEmulatorB(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = FUNC_QUEUE_END;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsGood, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsGood, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, param1, param2);
}

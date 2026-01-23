/* No dedicated header */

#include "callback.h"
#include "dsprot_types.h"
#include "encoding_constants.h"
#include "error_codes.h"
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

// This checksum value is derived from the first 37 instructions of the `run_encrypted_func` macro in asm_macro.inc:
//   e18fc00f*   orr      ip, pc, pc
//   e01cc00c*   ands     ip, ip, ip
//   03a0c000*   moveq    ip, #0
//   128cc08c*   addne    ip, ip, #140  @ 0x8c
//   e59cc014*   ldr      ip, [ip, #20]
//   e24cc000    sub      ip, ip, #0
//   e92d001f    push     {r0, r1, r2, r3, r4}
//   e1a01d2c    lsr      r1, ip, #26
//   e0233003    eor      r3, r3, r3
//   e1a0c30c    lsl      ip, ip, #6
//   e1a0c32c    lsr      ip, ip, #6
//   e1a0000c    mov      r0, ip
//   e5902000    ldr      r2, [r0]
//   e1a04c22    lsr      r4, r2, #24
//   e35400ea    cmp      r4, #234  @ 0xea
//   135400eb    cmpne    r4, #235  @ 0xeb
//   102338e2    eorne    r3, r3, r2, ror #17
//   10833e62    addne    r3, r3, r2, ror #28
//   10233172    eorne    r3, r3, r2, ror r1
//   e2511001    subs     r1, r1, #1
//   e2800004    add      r0, r0, #4
//   1afffff5    bne      -36
//   e3a00402    mov      r0, #33554432  @ 0x2000000
//   e3801b02    orr      r1, r0, #2048  @ 0x800
//   e3a00301    mov      r0, #67108864  @ 0x4000000
//   e3800901    orr      r0, r0, #16384  @ 0x4000
//   e5900000    ldr      r0, [r0]
//   e2100001    ands     r0, r0, #1
//   13811901    orrne    r1, r1, #16384  @ 0x4000
//   e15c0001    cmp      ip, r1
//   a58f3018    strge    r3, [pc, #24]
//   b1a0c00e    movlt    ip, lr
//   a8bd001f    popge    {r0, r1, r2, r3, r4}
//   b8bd03e0    poplt    {r5, r6, r7, r8, r9}
//   a92d1000    stmfdge  sp!, {ip}
//   e18fc00f    orr      ip, pc, pc
//   e8bd8000    ldmfd    sp!, {pc}
// 
// * = considered 00000000 due to a bug in checksum calculation

#define DSP_CHECKSUM_INS       (37)
#define DSP_EXPECTED_CHECKSUM  (0x9F75A8D6)

typedef u32 (*DSProt_Task)(DSProt_Ctx*);

enum {
	EXPECT_FALSE,
	EXPECT_TRUE
};


static inline void initCtx(DSProt_Ctx* ctx, void* param1, void* param2) {
	DSProt_Callback*  callback_tbl_ptr;
	u32*              callback_idx_ptr;
	u32               addr;
	u32               idx;
	
	// Obfuscated loading of callback table and index data
	addr = ADDR_PLUS_ADDEND(DSProt_CallbackIndex, ENC_VAL_1);
	addr -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	callback_idx_ptr = (u32*)(addr - DSP_OBFS_OFFSET);
	
	addr = ADDR_PLUS_ADDEND(DSProt_CallbackTable, ENC_VAL_1);
	addr -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	callback_tbl_ptr = (DSProt_Callback*)(addr - DSP_OBFS_OFFSET);
	
	idx = *callback_idx_ptr;
	
	ctx->pass_callback = callback_tbl_ptr[idx];
	ctx->fail_callback = callback_tbl_ptr[idx ^ 1];
	
	ctx->callback_param1 = param1;
	ctx->callback_param2 = param2;
	
	ctx->fail_callback_ret = NULL;
	
	ctx->error_code = ERROR_CODE_NONE;
}


static inline BOOL decryptionWrapperChecksumMatches(void* addr) {
	u32   i;
	u32*  func_data_ptr;
	u32   checksum;
	
	func_data_ptr = (u32*)addr;
	i = DSP_CHECKSUM_INS;
	checksum = 0;
	
	do {
		// BUG: the first 5 loops have invalid shifts, resulting in 0 instead of the rotated instruction
		checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32 - i));
		func_data_ptr++;
	} while (--i != 0);
	
	return (checksum == DSP_EXPECTED_CHECKSUM);
}


static inline void* dsprotMain(u32* func_queue_ptr, int expected_result, void* param1, void* param2) {
	DSProt_Ctx   work;
	u32          func_ret_total;
	DSProt_Task  task_func;
	u32          func_ret;
	u32          prime_bool;
	
	initCtx(&work, param1, param2);
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		if (!decryptionWrapperChecksumMatches(task_func)) {
			if (work.fail_callback_ret != NULL) {
				return work.fail_callback_ret;
			} else {
				return work.fail_callback(param1, param2);
			}
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.error_code == ERROR_CODE_NONE) {
			if (work.fail_callback_ret != NULL) {
				return work.fail_callback_ret;
			} else {
				return work.fail_callback(param1, param2);
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
		return work.pass_callback(param1, param2);
	} else {
		if (work.error_code != ERROR_CODE_NONE) {
			return work.fail_callback_ret;
		} else {
			return work.fail_callback(param1, param2);
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

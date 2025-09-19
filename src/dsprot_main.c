/* No dedicated header */

#include "callback.h"
#include "dsprot_types.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "mac_owner.h"
#include "primes.h"
#include "rom_test.h"

// Functions to be encrypted (cannot be called directly)
void* DetectFlashcartA(void* param1, void* param2);
void* DetectFlashcartB(void* param1, void* param2);
void* DetectEmulatorA(void* param1, void* param2);
void* DetectEmulatorB(void* param1, void* param2);

#define DSP_OBFS_OFFSET  (ENC_VAL_1 & 0xFFF)

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


static inline void populateCallbacks(DSProt_Ctx* work) {
	// This part is very strange to match. May be a better way to do this
	void*             tmp;
	DSProt_Callback*  callback_tbl;
	u32               callback_idx;
	
	tmp = (void*)ADDR_PLUS_ADDEND(DSProt_CallbackIndex, ENC_VAL_1);
	tmp -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	
	callback_tbl = (DSProt_Callback*)(ADDR_PLUS_ADDEND(DSProt_CallbackTable, ENC_VAL_1) - ENC_VAL_1);
	callback_idx = *(u32*)(tmp - DSP_OBFS_OFFSET);
	
	// Temporary assignment required to match
	tmp = callback_tbl[callback_idx];
	work->success_callback = tmp;
	
	tmp = callback_tbl[callback_idx ^ 1];
	work->failure_callback = tmp;
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
	work.failure_callback_return = 0;
	work.failure_code            = 0;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = DSP_CHECKSUM_INS;
		func_data_checksum = 0;
		do {
			// BUG: the first 5 loops have invalid shifts, resulting in 0 instead of the rotated instruction
			func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			} else {
				return work.failure_callback(param1, param2);
			}
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == 0) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			} else {
				return work.failure_callback(param1, param2);
			}
		}
		
		func_ret_total += func_ret;
		func_queue_ptr++;
	} while (*func_queue_ptr != 0);
	
	// Check if total matches expected result
	if (expected_result == EXPECT_TRUE) {
		prime_bool = PRIME_TRUE;
	} else {
		prime_bool = PRIME_FALSE;
	}
	
	if (!(func_ret_total % prime_bool)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code) {
			return work.failure_callback_return;
		} else {
			return work.failure_callback(param1, param2);
		}
	}
}


void* DetectFlashcartA(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = 0;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsBad, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, param1, param2);
}


void* DetectFlashcartB(void* param1, void* param2) {
	u32 func_queue[32];

	func_queue[2] = 0;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsGood, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsGood, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, param1, param2);
}


void* DetectEmulatorA(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = 0;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsBad, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_FALSE, param1, param2);
}


void* DetectEmulatorB(void* param1, void* param2) {
	u32 func_queue[32];
	
	func_queue[2] = 0;
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsGood, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsGood, ENC_VAL_1);
	
	return dsprotMain(&func_queue[0], EXPECT_TRUE, param1, param2);
}

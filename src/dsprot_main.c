/* No dedicated header */

#include "crash.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "mac_owner.h"
#include "nitro_types.h"
#include "primes.h"
#include "rom_test.h"

// Function to be encrypted (cannot be called directly)
void* DetectAll(void* callback, void* param1, void* param2);

#define FUNC_QUEUE_END  (0)

// This checksum value is derived from the first 28 instructions of the `run_encrypted_func` macro in asm_macro.inc:
//   e18fc00f    orr      ip, pc, pc
//   e01cc00c    ands     ip, ip, ip
//   03a0c000    moveq    ip, #0
//   128cc068    addne    ip, ip, #104  @ 0x68
//   e59cc014    ldr      ip, [ip, #20]
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
//   058f3014    streq    r3, [pc, #20]
//   08bd001f    popeq    {r0, r1, r2, r3, r4}
//   18bd03e0    popne    {r5, r6, r7, r8, r9}
//   092d1000    stmfdeq  sp!, {ip}
//   e18fc00f    orr      ip, pc, pc
//   08bd8000    ldmfdeq  sp!, {pc}

#define DSP_CHECKSUM_INS       (28)
#define DSP_EXPECTED_CHECKSUM  (0x0786385F)

typedef u32 (*TaskFunc)(void*);
typedef void* (*CallbackFunc)(void*, void*);


void* DetectAll(void* callback, void* param1, void* param2) {
	u32       func_queue[5];
	void*     ret;
	u32       i;
	u32*      func_queue_ptr;
	u32*      func_data_ptr;
	u32       func_data_checksum;
	u32       func_ret;
	TaskFunc  queued_func;
	u32       func_ret_total;
	
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1);
	func_queue[2] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1);
	func_queue[3] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsBad, ENC_VAL_1);
	func_queue[4] = FUNC_QUEUE_END;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		queued_func = (TaskFunc)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)queued_func;
		i = DSP_CHECKSUM_INS;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			// The goto is useless, but required to match
			ret = DSProt_Crash(NULL, NULL); // No return
			goto EXIT;
		}
		
		func_ret = queued_func(NULL);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0) {
			// The goto is useless, but required to match
			ret = DSProt_Crash(NULL, NULL); // No return
			goto EXIT;
		}
		
		func_ret_total += func_ret;
		func_queue_ptr++;
	} while (*func_queue_ptr != FUNC_QUEUE_END);
	
	if (!(func_ret_total % PRIME_FALSE)) {
		if (callback != NULL) {
			ret = ((CallbackFunc)callback)(param1, param2);
		} else {
			ret = NULL;
		}
	} else {
		ret = DSProt_Crash(NULL, NULL);
	}
	
EXIT:
	return ret;
}

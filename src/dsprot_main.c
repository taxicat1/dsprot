/* No dedicated header */

#include "crash.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "nitro_types.h"
#include "mac_owner.h"
#include "primes.h"
#include "rom_test.h"

// Function to be encrypted (cannot be called directly)
void* DetectAll(void* callback, void* param1, void* param2);

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
	func_queue[4] = 0;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		queued_func = (TaskFunc)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)queued_func;
		i = DSP_CHECKSUM_INS;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
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
	} while (*func_queue_ptr != 0);
	
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

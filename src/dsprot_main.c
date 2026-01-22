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


static inline BOOL decryptionWrapperChecksumMatches(void* addr) {
	u32   i;
	u32*  func_data_ptr;
	u32   checksum;
	
	func_data_ptr = (u32*)addr;
	i = DSP_CHECKSUM_INS;
	checksum = 0;
	
	do {
		checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i != 0);
	
	return (checksum == DSP_EXPECTED_CHECKSUM);
}


static inline void* dsprotMain(u32* func_queue_ptr, void* callback, void* param1, void* param2) {
	u32       func_ret_total;
	TaskFunc  queued_func;
	u32       func_ret;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	do {
		queued_func = (TaskFunc)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		if (!decryptionWrapperChecksumMatches(queued_func)) {
			return DSProt_Crash(NULL, NULL);
		}
		
		func_ret = queued_func(NULL);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0) {
			return DSProt_Crash(NULL, NULL);
		}
		
		func_ret_total += func_ret;
		func_queue_ptr++;
	} while (*func_queue_ptr != FUNC_QUEUE_END);
	
	if (!(func_ret_total % PRIME_FALSE)) {
		if (callback != NULL) {
			return ((CallbackFunc)callback)(param1, param2);
		} else {
			return NULL;
		}
	} else {
		return DSProt_Crash(NULL, NULL);
	}
}


void* DetectAll(void* callback, void* param1, void* param2) {
	u32 func_queue[5];
	
	func_queue[0] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_MACOwner_IsBad, ENC_VAL_1);
	func_queue[1] = ADDR_PLUS_ADDEND(RunEncrypted_MACOwner_IsBad, ENC_VAL_1);
	func_queue[2] = ADDR_PLUS_ADDEND(RunEncrypted_ROMTest_IsBad, ENC_VAL_1);
	func_queue[3] = ADDR_PLUS_ADDEND(RunEncrypted_Integrity_ROMTest_IsBad, ENC_VAL_1);
	func_queue[4] = FUNC_QUEUE_END;
	
	return dsprotMain(&func_queue[0], callback, param1, param2);
}

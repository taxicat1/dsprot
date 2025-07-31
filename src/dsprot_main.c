/* No dedicated header */

#include "types.h"

#include "primes.h"
#include "encoding_constants.h"
#include "crash.h"
#include "integrity.h"
#include "rom_test.h"
#include "mac_owner.h"

// Function to be encrypted (cannot be called directly)
void* DetectAll(void* callback, void* param1, void* param2);


#define DSP_EXPECTED_CHECKSUM  (0x2FBB82E1)

typedef u32 (*U32Func)(u32);
typedef void* (*CallbackFunc)(void*, void*);

void* DetectAll(void* callback, void* param1, void* param2) {
	u32      func_queue[5];
	void*    ret;
	u32      i;
	u32*     func_queue_ptr;
	u32*     func_data_ptr;
	u32      func_data_checksum;
	u32      func_ret;
	U32Func  queued_func;
	u32      func_ret_total;
	
	func_queue[0] = (u32)&RunEncrypted_Integrity_MACOwner_IsBad[ENC_VAL_1];
	func_queue[1] = (u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1];
	func_queue[2] = (u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1];
	func_queue[3] = (u32)&RunEncrypted_Integrity_ROMTest_IsBad[ENC_VAL_1];
	func_queue[4] = 0;
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		queued_func = (U32Func)(*func_queue_ptr - ENC_VAL_1);
		
		func_data_ptr = (u32*)queued_func;
		i = 9;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			ret = DSProt_Crash(0, 0);
			goto EXIT;
		}
		
		func_ret = queued_func(0);
		if (func_ret == 0) {
			ret = DSProt_Crash(0, 0);
			goto EXIT;
		} else {
			func_ret_total += func_ret;
		}
	} while (*++func_queue_ptr != 0);
	
	if (!(func_ret_total % PRIME_FALSE)) {
		if (callback != NULL) {
			ret = ((CallbackFunc)callback)(param1, param2);
		} else {
			ret = NULL;
		}
	} else {
		ret = DSProt_Crash(0, 0);
	}
	
EXIT:
	return ret;
}

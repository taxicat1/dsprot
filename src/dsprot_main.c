/* No dedicated header */

#include "dsprot_types.h"
#include "callback.h"

#include "primes.h"
#include "encoding_constants.h"
#include "integrity.h"
#include "rom_test.h"
#include "mac_owner.h"

// Functions to be encrypted (cannot be called directly)
void* DetectFlashcartA(void* param1, void* param2);
void* DetectFlashcartB(void* param1, void* param2);
void* DetectEmulatorA(void* param1, void* param2);
void* DetectEmulatorB(void* param1, void* param2);

#define DSP_EXPECTED_CHECKSUM  (0x2FBB82E1)
#define DSP_OBFS_OFFSET        (0x100)

typedef u32 (*DSProt_Task)(DSProt_Ctx*);


void* DetectFlashcartA(void* param1, void* param2) {
	DSProt_Ctx        work;
	u32               func_queue[32];
	u32               tmp;
	DSProt_Callback*  callback_tbl;
	u32               callback_idx;
	u32               i;
	u32*              func_queue_ptr;
	u32*              func_data_ptr;
	u32               func_data_checksum;
	DSProt_Task       task_func;
	u32               func_ret_total;
	u32               func_ret;
	
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1];
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsBad[ENC_VAL_1];
	
	
	tmp = (u32)(&DSProt_CallbackIndex + ENC_VAL_1/sizeof(u32));
	tmp -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	
	callback_tbl = (DSProt_Callback*)((u32)&DSProt_CallbackTable[ENC_VAL_1/sizeof(u32)] - ENC_VAL_1);
	callback_idx = *(u32*)(tmp - DSP_OBFS_OFFSET);
	
	// Temporary assignment required to match
	tmp = (u32)callback_tbl[callback_idx];
	work.success_callback = (DSProt_Callback)tmp;
	
	tmp = (u32)callback_tbl[callback_idx^1];
	work.failure_callback = (DSProt_Callback)tmp;
	
	work.callback_param_1        = param1;
	work.callback_param_2        = param2;
	work.failure_callback_return = 0;
	work.failure_code            = 0;
	
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = 9;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == 0) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		} else {
			func_ret_total += func_ret;
		}
	} while(*++func_queue_ptr != 0);
	
	// Check if total is valid
	if (!(func_ret_total % PRIME_FALSE)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code) {
			return work.failure_callback_return;
		}
		
		// No failure code, so call failure callback instead
		return work.failure_callback(param1, param2);
	}
}


void* DetectFlashcartB(void* param1, void* param2) {
	DSProt_Ctx        work;
	u32               func_queue[32];
	u32               tmp;
	DSProt_Callback*  callback_tbl;
	u32               callback_idx;
	u32               i;
	u32*              func_queue_ptr;
	u32*              func_data_ptr;
	u32               func_data_checksum;
	DSProt_Task       task_func;
	u32               func_ret_total;
	u32               func_ret;
	
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsGood[ENC_VAL_1];
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsGood[ENC_VAL_1];
	
	
	tmp = (u32)(&DSProt_CallbackIndex + ENC_VAL_1/sizeof(u32));
	tmp -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	
	callback_tbl = (DSProt_Callback*)((u32)&DSProt_CallbackTable[ENC_VAL_1/sizeof(u32)] - ENC_VAL_1);
	callback_idx = *(u32*)(tmp - DSP_OBFS_OFFSET);
	
	// Temporary assignment required to match
	tmp = (u32)callback_tbl[callback_idx];
	work.success_callback = (DSProt_Callback)tmp;
	
	tmp = (u32)callback_tbl[callback_idx^1];
	work.failure_callback = (DSProt_Callback)tmp;
	
	work.callback_param_1        = param1;
	work.callback_param_2        = param2;
	work.failure_callback_return = 0;
	work.failure_code            = 0;
	
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = 9;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == 0) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		} else {
			func_ret_total += func_ret;
		}
	} while(*++func_queue_ptr != 0);
	
	// Check if total is valid
	if (!(func_ret_total % PRIME_TRUE)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code) {
			return work.failure_callback_return;
		}
		
		// No failure code, so call failure callback instead
		return work.failure_callback(param1, param2);
	}
}


void* DetectEmulatorA(void* param1, void* param2) {
	DSProt_Ctx        work;
	u32               func_queue[32];
	u32               tmp;
	DSProt_Callback*  callback_tbl;
	u32               callback_idx;
	u32               i;
	u32*              func_queue_ptr;
	u32*              func_data_ptr;
	u32               func_data_checksum;
	DSProt_Task       task_func;
	u32               func_ret_total;
	u32               func_ret;
	
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1];
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsBad[ENC_VAL_1];
	
	
	tmp = (u32)(&DSProt_CallbackIndex + ENC_VAL_1/sizeof(u32));
	tmp -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	
	callback_tbl = (DSProt_Callback*)((u32)&DSProt_CallbackTable[ENC_VAL_1/sizeof(u32)] - ENC_VAL_1);
	callback_idx = *(u32*)(tmp - DSP_OBFS_OFFSET);
	
	// Temporary assignment required to match
	tmp = (u32)callback_tbl[callback_idx];
	work.success_callback = (DSProt_Callback)tmp;
	
	tmp = (u32)callback_tbl[callback_idx^1];
	work.failure_callback = (DSProt_Callback)tmp;
	
	work.callback_param_1        = param1;
	work.callback_param_2        = param2;
	work.failure_callback_return = 0;
	work.failure_code            = 0;
	
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = 9;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == 0) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		} else {
			func_ret_total += func_ret;
		}
	} while(*++func_queue_ptr != 0);
	
	// Check if total is valid
	if (!(func_ret_total % PRIME_FALSE)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code) {
			return work.failure_callback_return;
		}
		
		// No failure code, so call failure callback instead
		return work.failure_callback(param1, param2);
	}
}


void* DetectEmulatorB(void* param1, void* param2) {
	DSProt_Ctx        work;
	u32               func_queue[32];
	u32               tmp;
	DSProt_Callback*  callback_tbl;
	u32               callback_idx;
	u32               i;
	u32*              func_queue_ptr;
	u32*              func_data_ptr;
	u32               func_data_checksum;
	DSProt_Task       task_func;
	u32               func_ret_total;
	u32               func_ret;
	
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsGood[ENC_VAL_1];
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsGood[ENC_VAL_1];
	
	
	tmp = (u32)(&DSProt_CallbackIndex + ENC_VAL_1/sizeof(u32));
	tmp -= (ENC_VAL_1 - DSP_OBFS_OFFSET);
	
	callback_tbl = (DSProt_Callback*)((u32)&DSProt_CallbackTable[ENC_VAL_1/sizeof(u32)] - ENC_VAL_1);
	callback_idx = *(u32*)(tmp - DSP_OBFS_OFFSET);
	
	// Temporary assignment required to match
	tmp = (u32)callback_tbl[callback_idx];
	work.success_callback = (DSProt_Callback)tmp;
	
	tmp = (u32)callback_tbl[callback_idx^1];
	work.failure_callback = (DSProt_Callback)tmp;
	
	work.callback_param_1        = param1;
	work.callback_param_2        = param2;
	work.failure_callback_return = 0;
	work.failure_code            = 0;
	
	
	func_ret_total = PRIME_DSPROT_MAIN * PRIME_FALSE * PRIME_TRUE;
	
	func_queue_ptr = &func_queue[0];
	do {
		task_func = (DSProt_Task)(*func_queue_ptr - ENC_VAL_1);
		
		// Preliminary integrity check
		func_data_ptr = (u32*)task_func;
		i = 9;
		func_data_checksum = 0;
		do {
			func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
			func_data_ptr++;
		} while (--i);
		
		if (func_data_checksum != DSP_EXPECTED_CHECKSUM) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		}
		
		// Run next inner function with context arg
		func_ret = task_func(&work);
		
		// `func_ret` should always be a prime-encoded Boolean
		// 0 would indicate tampering
		if (func_ret == 0 && work.failure_code == 0) {
			if (work.failure_callback_return) {
				return work.failure_callback_return;
			}
			
			return work.failure_callback(param1, param2);
		} else {
			func_ret_total += func_ret;
		}
	} while(*++func_queue_ptr != 0);
	
	// Check if total is valid
	if (!(func_ret_total % PRIME_TRUE)) {
		return work.success_callback(param1, param2);
	} else {
		if (work.failure_code) {
			return work.failure_callback_return;
		}
		
		// No failure code, so call failure callback instead
		return work.failure_callback(param1, param2);
	}
}

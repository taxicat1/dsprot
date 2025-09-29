#ifndef DSPROT_INSTANT_H
#define DSPROT_INSTANT_H

/* 
 * dsprot_instant.h
 * 
 * Header file for the DS Protect library
 * Version 2.05 Instant
 */

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32

#ifdef __cplusplus
extern "C" {
#endif

// See src/dsprot_main.c for information about this checksum procedure
#define DSP_CHECKSUM_INS       (37)
#define DSP_EXPECTED_CHECKSUM  (0x9F75A8D6)


/* 
 * void* DSProt_Crash(void* __unused1, void* __unused2)
 * 
 * Crash the system.
 * 
 * @param __unused1:    Unused
 * @param __unused2:    Unused
 * 
 * @returns:    Does not return
 */
extern void* DSProt_Crash(void* __unused1, void* __unused2);


/* 
 * void* DSProt_DetectAll(void* callback, void* param1, void* param2)
 * 
 * Detect if the current environment is an emulator, or flashcart,
 * or has otherwise been tampered with. If this is detected, crash the system.
 * 
 * @param callback:    Callback function to run if no emulator/flashcart/tampering is detected. May be NULL.
 * @param param1:      First parameter passed to the callback
 * @param param2:      Second parameter passed to the callback
 * 
 * @returns:    The return value of the callback, or NULL if one was not specified
 */
extern void* DSProt_DetectAll(void* callback, void* param1, void* param2);


/* 
 * void* DSProt_CheckAndDetectAll(void* callback, void* param1, void* param2)
 * 
 * Run a tamper-detection checksum, and then detect if the current
 * environment is an emulator, or flashcart, or has otherwise been
 * tampered with. If this is detected, or if the checksum fails,
 * crash the system.
 * 
 * @param callback:    Callback function to run if no emulator/flashcart/tampering is detected. May be NULL.
 * @param param1:      First parameter passed to the callback
 * @param param2:      Second parameter passed to the callback
 * 
 * @returns:    The return value of the callback, or NULL if one was not specified
 */
static inline void* DSProt_CheckAndDetectAll(void* callback, void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectAll;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		// BUG: the first 5 loops have invalid shifts, resulting in 0 instead of the rotated instruction
		func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectAll(callback, param1, param2);
	} else {
		return DSProt_Crash(NULL, NULL);
	}
}


#undef DSP_EXPECTED_CHECKSUM
#undef DSP_CHECKSUM_INS

#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public DSProt_Crash
.public DSProt_DetectAll

#endif /* SDK_ASM */

#endif /* DSPROT_INSTANT_H */

//=================================================================================================
/**
 * dsprot_instant.h
 * 
 * Header file for the DS Protect library
 * Version 2.00 Instant
 */
//=================================================================================================

#ifndef DSPROT_INSTANT_H
#define DSPROT_INSTANT_H

#define DSP_VERSION      (200)
#define DSP_VERSION_STR  "2.00s"

#ifndef SDK_ASM

#ifndef DSP_NO_NITRO

#include <nitro/types.h>  // For u32, NULL

#else /* DSP_NO_NITRO */

// Assumptions for convenience-- make sure this is matching if you use it!
typedef unsigned long  __dsp_u32;
#define u32  __dsp_u32

#ifndef NULL

#define DSP_DEF_NULL

#ifdef __cplusplus
#define NULL  (0)
#else /* __cplusplus */
#define NULL  ((void*)0)
#endif /* __cplusplus */

#endif /* NULL */

#endif /* DSP_NO_NITRO */

// See src/dsprot_main.c for information about this checksum procedure
#define DSP_CHECKSUM_INS       (9)
#define DSP_EXPECTED_CHECKSUM  (0x9FBB82E0)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// DS Protect functions to be called by inline
extern void* DSProt_Crash(void* __unused1, void* __unused2);
extern void* DSProt_DetectAll(void* callback, void* param1, void* param2);

#ifdef __cplusplus
}
#endif /* __cplusplus */


//=================================================================================================
/**
 * Run a tamper-detection checksum, and then detect if the current environment is
 * an emulator, or flashcart, or has otherwise been tampered with. If this is detected,
 * or if the checksum fails, crash the system.
 * 
 * @param callback Callback function to run if no emulator/flashcart/tampering is detected.
 *                 May be NULL.
 * @param param1 First parameter passed to the callback
 * @param param2 Second parameter passed to the callback
 * 
 * @return The return value of the callback, or NULL if none was specified
 */
//=================================================================================================
static inline void* DSProt_CheckAndDetectAll(void* callback, void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectAll;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
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

#ifdef DSP_NO_NITRO

#ifdef DSP_DEF_NULL

#undef NULL
#undef DSP_DEF_NULL

#endif /* DSP_DEF_NULL */

#undef u32

#endif /* DSP_NO_NITRO */

#else /* SDK_ASM */

.public DSProt_Crash
.public DSProt_DetectAll

#endif /* SDK_ASM */

#endif /* DSPROT_INSTANT_H */

//=================================================================================================
/**
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 1.28
 */
//=================================================================================================

#ifndef DSPROT_H
#define DSPROT_H

#define DSP_VERSION      (128)
#define DSP_VERSION_STR  "1.28"

#ifndef SDK_ASM

#ifndef DSP_NO_NITRO

#include <nitro/types.h>  // For u32

#else /* DSP_NO_NITRO */

// Assumption for convenience-- make sure this is matching if you use it!
typedef unsigned long  __dsp_u32;
#define u32  __dsp_u32

#endif /* DSP_NO_NITRO */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Internal DS Protect functions to be called by inlines
extern u32 __DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectEmulator(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectDummy(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);

// Internal wrapper function for exporting the DS Protect API
// Define DSP_EXT_HEADER_FUNC if other non-decompiled functions exist after it
#ifndef DSP_EXT_HEADER_FUNC

static u32 __DSProt_wrapper(void* callback);


static u32 __DSProt_wrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~(u32)callback;
}


#else /* DSP_EXT_HEADER_FUNC */

extern u32 __DSProt_wrapper(void* callback);

#endif /* DSP_EXT_HEADER_FUNC */

#ifdef __cplusplus
}
#endif /* __cplusplus */


//=================================================================================================
/**
 * Detect if the current environment is a flashcart.
 * 
 * @param callback Function to be called if the environment is determined to be a flashcart.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to be a flashcart, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectFlashcart(void* callback) {
	return __DSProt_DetectFlashcart(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is an emulator.
 * 
 * @param callback Function to be called if the environment is determined to be an emulator.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to be an emulator, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectEmulator(void* callback) {
	return __DSProt_DetectEmulator(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always fail.
 * 
 * @param callback Dummy callback function which will never be called. May be NULL.
 * 
 * @return 0
 */
//=================================================================================================
static inline u32 DSProt_DetectDummy(void* callback) {
	return __DSProt_DetectDummy(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is NOT a flashcart.
 * 
 * @param callback Function to be called if the environment is determined to NOT be a flashcart.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to NOT be a flashcart, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectNotFlashcart(void* callback) {
	return __DSProt_DetectNotFlashcart(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is NOT an emulator.
 * 
 * @param callback Function to be called if the environment is determined to NOT be an emulator.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to NOT be an emulator, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectNotEmulator(void* callback) {
	return __DSProt_DetectNotEmulator(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always succeed.
 * 
 * @param callback Dummy callback function which will always be called. May be NULL.
 * 
 * @return 1
 */
//=================================================================================================
static inline u32 DSProt_DetectNotDummy(void* callback) {
	return __DSProt_DetectNotDummy(__DSProt_wrapper, callback, 0) == ~(u32)callback;
}


#ifdef DSP_NO_NITRO

#undef u32

#endif /* DSP_NO_NITRO */

#else /* SDK_ASM */

.public __DSProt_DetectFlashcart
.public __DSProt_DetectNotFlashcart
.public __DSProt_DetectEmulator
.public __DSProt_DetectNotEmulator
.public __DSProt_DetectDummy
.public __DSProt_DetectNotDummy

#endif /* SDK_ASM */

#endif /* DSPROT_H */

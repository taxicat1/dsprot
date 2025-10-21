#ifndef DSPROT_H
#define DSPROT_H

//=================================================================================================
/**
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 1.27
 */
//=================================================================================================

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32

#ifdef __cplusplus
extern "C" {
#endif

// Internal DS Protect functions to be called by inlines
extern u32 __DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectEmulator(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectDummy(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);
extern u32 __DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);

// Internal wrapper function for exporting the DS Protect API
static u32 __DSProt_wrapper(void* callback);


static u32 __DSProt_wrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~(u32)callback;
}


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


#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public __DSProt_DetectFlashcart
.public __DSProt_DetectNotFlashcart
.public __DSProt_DetectEmulator
.public __DSProt_DetectNotEmulator
.public __DSProt_DetectDummy
.public __DSProt_DetectNotDummy

#endif /* SDK_ASM */

#endif /* DSPROT_H */

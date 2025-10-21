#ifndef DSPROT_H
#define DSPROT_H

//=================================================================================================
/**
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 1.28
 */
//=================================================================================================

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32

#ifdef __cplusplus
extern "C" {
#endif


//=================================================================================================
/**
 * Detect if the current environment is a flashcart.
 * 
 * @param callback Function to be called if the environment is determined to be a flashcart
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return If the callback was run, the return of the callback.
 *         Otherwise, some other value (unimportant).
 */
//=================================================================================================
extern u32 DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);


//=================================================================================================
/**
 * Detect if the current environment is an emulator.
 * 
 * @param callback Function to be called if the environment is determined to be an emulator
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return If the callback was run, the return of the callback.
 *         Otherwise, some other value (unimportant).
 */
//=================================================================================================
extern u32 DSProt_DetectEmulator(void* callback, void* param, u32 __unused);


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always fail.
 * 
 * @param callback Dummy callback function which will never be called
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return Some integer value (unimportant)
 */
//=================================================================================================
extern u32 DSProt_DetectDummy(void* callback, void* param, u32 __unused);


//=================================================================================================
/**
 * Detect if the current environment is NOT a flashcart.
 * 
 * @param callback Function to be called if the environment is determined to NOT be a flashcart
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return If the callback was run, the return of the callback.
 *         Otherwise, some other value (unimportant).
 */
//=================================================================================================
extern u32 DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);


//=================================================================================================
/**
 * Detect if the current environment is NOT an emulator.
 * 
 * @param callback Function to be called if the environment is determined to NOT be an emulator
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return If the callback was run, the return of the callback.
 *         Otherwise, some other value (unimportant).
 */
//=================================================================================================
extern u32 DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always succeed.
 * 
 * @param callback Dummy callback function which will always be called
 * @param param Parameter to be passed to the callback
 * @param __unused Unused
 * 
 * @return The return of the callback
 */
//=================================================================================================
extern u32 DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);


// Internal function for emulating the old DS Protect API (many games will use this feature)
static u32 __DSProt_compatibilityWrapper(void* callback);


static u32 __DSProt_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is a flashcart.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Function to be called if the environment is determined to be a flashcart.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to be a flashcart, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectFlashcart_Old(void* callback) {
	return DSProt_DetectFlashcart(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is an emulator.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Function to be called if the environment is determined to be an emulator.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to be an emulator, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectEmulator_Old(void* callback) {
	return DSProt_DetectEmulator(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always fail.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Dummy callback function which will never be called. May be NULL.
 * 
 * @return 0
 */
//=================================================================================================
static inline u32 DSProt_DetectDummy_Old(void* callback) {
	return DSProt_DetectDummy(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is NOT a flashcart.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Function to be called if the environment is determined to NOT be a flashcart.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to NOT be a flashcart, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectNotFlashcart_Old(void* callback) {
	return DSProt_DetectNotFlashcart(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Detect if the current environment is NOT an emulator.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Function to be called if the environment is determined to NOT be an emulator.
 *                 May be NULL.
 * 
 * @return 1 if the environment is determined to NOT be an emulator, 0 otherwise
 */
//=================================================================================================
static inline u32 DSProt_DetectNotEmulator_Old(void* callback) {
	return DSProt_DetectNotEmulator(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


//=================================================================================================
/**
 * Dummy environment detection function that does not do anything. Will always succeed.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback Dummy callback function which will always be called. May be NULL.
 * 
 * @return 1
 */
//=================================================================================================
static inline u32 DSProt_DetectNotDummy_Old(void* callback) {
	return DSProt_DetectNotDummy(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public DSProt_DetectFlashcart
.public DSProt_DetectNotFlashcart
.public DSProt_DetectEmulator
.public DSProt_DetectNotEmulator
.public DSProt_DetectDummy
.public DSProt_DetectNotDummy

#endif /* SDK_ASM */

#endif /* DSPROT_H */

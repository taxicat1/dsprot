#ifndef DSPROT_H
#define DSPROT_H

/* 
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 1.26
 */

/* 
 * Expected return values if no flashcart/emulator/tampering was detected
 */
#define DSP_DETECTFLASHCART_OK     (1830601)
#define DSP_DETECTNOTFLASHCART_OK  (1831551)
#define DSP_DETECTEMULATOR_OK      (1830203)
#define DSP_DETECTNOTEMULATOR_OK   (1830859)
#define DSP_DETECTDUMMY_OK         (1828014)
#define DSP_DETECTNOTDUMMY_OK      (1829648)

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32

#ifdef __cplusplus
extern "C" {
#endif


/* 
 * u32 DSProt_DetectFlashcart(void* callback, void* param, u32 __unused)
 * 
 * Detect if the current environment is a flashcart.
 * 
 * @param callback:    Function to be called if the environment is determined to be a flashcart. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:    If the callback was run, the return of the callback. If a flashcart was not detected, DSP_DETECTFLASHCART_OK. Otherwise, some other value
 */
extern u32 DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);


/* 
 * DSProt_DetectEmulator(void* callback, void* param, u32 __unused)
 * 
 * Detect if the current environment is an emulator.
 * 
 * @param callback:    Function to be called if the environment is determined to be an emulator. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:     If the callback was run, the return of the callback. If an emulator was not detected, DSP_DETECTEMULATOR_OK. Otherwise, some other value
 */
extern u32 DSProt_DetectEmulator(void* callback, void* param, u32 __unused);


/* 
 * u32 DSProt_DetectDummy(void* callback, void* param, u32 __unused)
 * 
 * Dummy environment detection function that does not do anything. Will always fail.
 * 
 * @param callback:    Dummy callback function which will never be called. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:    DSP_DETECTDUMMY_OK
 */
extern u32 DSProt_DetectDummy(void* callback, void* param, u32 __unused);


/* 
 * u32 DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused)
 * 
 * Detect if the current environment is NOT a flashcart.
 * 
 * @param callback:    Function to be called if the environment is determined to NOT be a flashcart. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:    If the callback was run, the return of the callback. If a flashcart was not detected, DSP_DETECTNOTFLASHCART_OK. Otherwise, some other value
 */
extern u32 DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);


/* 
 * u32 DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused)
 * 
 * Detect if the current environment is NOT an emulator.
 * 
 * @param callback:    Function to be called if the environment is determined to NOT be an emulator. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:    If the callback was run, the return of the callback. If an emulator was not detected, DSP_DETECTNOTEMULATOR_OK. Otherwise, some other value
 */
extern u32 DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);


/* 
 * DSProt_DetectNotDummy(void* callback, void* param, u32 __unused)
 * 
 * Dummy environment detection function that does not do anything. Will always succeed.
 * 
 * @param callback:    Dummy callback function which will always be called. May be NULL.
 * @param param:       Parameter to be passed to the callback
 * @param __unused:    Unused
 * 
 * @returns:    If a callback was provided, the return of the callback. Otherwise, DSP_DETECTNOTDUMMY_OK
 */
extern u32 DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);


/* 
 * Internal functions for emulating the old DS Protect API (many games will use this feature)
 */
static u32 __DSProt_DetectFlashcart_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectEmulator_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectDummy_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotFlashcart_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotEmulator_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotDummy_compatibilityWrapper(void* callback);


static u32 __DSProt_DetectFlashcart_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTFLASHCART_OK;
}


static u32 __DSProt_DetectEmulator_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTEMULATOR_OK;
}


static u32 __DSProt_DetectDummy_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTDUMMY_OK;
}


static u32 __DSProt_DetectNotFlashcart_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return DSP_DETECTNOTFLASHCART_OK;
}


static u32 __DSProt_DetectNotEmulator_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return DSP_DETECTNOTEMULATOR_OK;
}


static u32 __DSProt_DetectNotDummy_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return DSP_DETECTNOTDUMMY_OK;
}


/* 
 * u32 DSProt_DetectFlashcart_Old(void* callback)
 * 
 * Detect if the current environment is a flashcart.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Function to be called if the environment is determined to be a flashcart. May be NULL.
 * 
 * @returns:    1 if the environment is determined to be a flashcart, 0 otherwise
 */
static inline u32 DSProt_DetectFlashcart_Old(void* callback) {
	return DSProt_DetectFlashcart(__DSProt_DetectFlashcart_compatibilityWrapper, callback, 0) == ~DSP_DETECTFLASHCART_OK;
}


/* 
 * u32 DSProt_DetectEmulator_Old(void* callback)
 * 
 * Detect if the current environment is an emulator.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Function to be called if the environment is determined to be an emulator. May be NULL.
 * 
 * @returns:    1 if the environment is determined to be an emulator, 0 otherwise
 */
static inline u32 DSProt_DetectEmulator_Old(void* callback) {
	return DSProt_DetectEmulator(__DSProt_DetectEmulator_compatibilityWrapper, callback, 0) == ~DSP_DETECTEMULATOR_OK;
}


/* 
 * u32 DSProt_DetectDummy_Old(void* callback)
 * 
 * Dummy environment detection function that does not do anything. Will always fail.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Dummy callback function which will never be called. May be NULL.
 * 
 * @returns:    0
 */
static inline u32 DSProt_DetectDummy_Old(void* callback) {
	return DSProt_DetectDummy(__DSProt_DetectDummy_compatibilityWrapper, callback, 0) == ~DSP_DETECTDUMMY_OK;
}


/* 
 * u32 DSProt_DetectNotFlashcart_Old(void* callback)
 * 
 * Detect if the current environment is NOT a flashcart.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Function to be called if the environment is determined to NOT be a flashcart. May be NULL.
 * 
 * @returns:    1 if the environment is determined to NOT be a flashcart, 0 otherwise
 */
static inline u32 DSProt_DetectNotFlashcart_Old(void* callback) {
	return DSProt_DetectNotFlashcart(__DSProt_DetectNotFlashcart_compatibilityWrapper, callback, 0) == DSP_DETECTNOTFLASHCART_OK;
}


/* 
 * u32 DSProt_DetectNotEmulator_Old(void* callback)
 * 
 * Detect if the current environment is NOT an emulator.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Function to be called if the environment is determined to NOT be an emulator. May be NULL.
 * 
 * @returns:    1 if the environment is determined to NOT be an emulator, 0 otherwise
 */
static inline u32 DSProt_DetectNotEmulator_Old(void* callback) {
	return DSProt_DetectNotEmulator(__DSProt_DetectNotEmulator_compatibilityWrapper, callback, 0) == DSP_DETECTNOTEMULATOR_OK;
}


/* 
 * u32 DSProt_DetectNotDummy_Old(void* callback)
 * 
 * Dummy environment detection function that does not do anything. Will always succeed.
 * Compatibility for the old DS Protect API.
 * 
 * @param callback:    Dummy callback function which will always be called. May be NULL.
 * 
 * @returns:    1
 */
static inline u32 DSProt_DetectNotDummy_Old(void* callback) {
	return DSProt_DetectNotDummy(__DSProt_DetectNotDummy_compatibilityWrapper, callback, 0) == DSP_DETECTNOTDUMMY_OK;
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

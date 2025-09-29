#ifndef DSPROT_H
#define DSPROT_H

/* 
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 2.01
 */

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32
#include <nitro/os.h>     // For OS_GetVBlankCount (inline function)

#ifdef __cplusplus
extern "C" {
#endif

// See src/dsprot_main.c for information about this checksum procedure
#define DSP_CHECKSUM_INS       (9)
#define DSP_EXPECTED_CHECKSUM  (0x2FBB82E1)

typedef void* (*DSProt_Callback)(void*, void*);


/* 
 * void DSProt_DecodeFunctions(void)
 * 
 * Decode other DS Protect functions from their encoded state.
 * This is required to be called before calling any other DS Protect functions.
 */
extern void DSProt_DecodeFunctions(void);


/* 
 * void* DSProt_DetectFlashcartA(void* param1, void* param2)
 * 
 * Detect if the current environment is a flashcart, using method A. Then, call
 * a registered callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
extern void* DSProt_DetectFlashcartA(void* param1, void* param2);


/* 
 * void* DSProt_DetectFlashcartB(void* param1, void* param2)
 * 
 * Detect if the current environment is a flashcart, using method B. Then, call
 * a registered callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
extern void* DSProt_DetectFlashcartB(void* param1, void* param2);


/* 
 * void* DSProt_DetectEmulatorA(void* param1, void* param2)
 * 
 * Detect if the current environment is an emulator, using method A. Then, call
 * a registered callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
extern void* DSProt_DetectEmulatorA(void* param1, void* param2);


/* 
 * void* DSProt_DetectEmulatorA(void* param1, void* param2)
 * 
 * Detect if the current environment is an emulator, using method B. Then, call
 * a registered callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
extern void* DSProt_DetectEmulatorB(void* param1, void* param2);


/* 
 * Global table where registered callbacks are stored.
 */
extern DSProt_Callback DSProt_CallbackTable[2];


/* 
 * Global index tracking the order of the callback table, which is randomized.
 */
extern u32 DSProt_CallbackIndex;


/* 
 * void DSProt_RegisterCallbacks(DSProt_Callback success_callback, DSProt_Callback failure_callback)
 * 
 * Register callbacks to be run according to the results of environment tests. Cannot specify NULL.
 * 
 * @param success_callback:    Callback to run if a test DOES NOT detect piracy or tampering
 * @param failure_callback:    Callback to run if a test DOES detect piracy or tampering
 */
static inline void DSProt_RegisterCallbacks(DSProt_Callback success_callback, DSProt_Callback failure_callback) {
	DSProt_CallbackIndex = OS_GetVBlankCount() & 1;
	DSProt_CallbackTable[DSProt_CallbackIndex    ] = success_callback;
	DSProt_CallbackTable[DSProt_CallbackIndex ^ 1] = failure_callback;
}


/* 
 * void* DSProt_CheckAndDetectFlashcartA(void* param1, void* param2)
 * 
 * Run a tamper-detection checksum, and then detect if the current
 * environment is a flashcart, using method A. Then, call a registered 
 * callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
static inline void* DSProt_CheckAndDetectFlashcartA(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectFlashcartA;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectFlashcartA(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


/* 
 * void* DSProt_CheckAndDetectFlashcartB(void* param1, void* param2)
 * 
 * Run a tamper-detection checksum, and then detect if the current
 * environment is a flashcart, using method B. Then, call a registered 
 * callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
static inline void* DSProt_CheckAndDetectFlashcartB(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectFlashcartB;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectFlashcartB(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


/* 
 * void* DSProt_CheckAndDetectEmulatorA(void* param1, void* param2)
 * 
 * Run a tamper-detection checksum, and then detect if the current
 * environment is a emulator, using method A. Then, call a registered 
 * callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
static inline void* DSProt_CheckAndDetectEmulatorA(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectEmulatorA;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectEmulatorA(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


/* 
 * void* DSProt_CheckAndDetectEmulatorB(void* param1, void* param2)
 * 
 * Run a tamper-detection checksum, and then detect if the current
 * environment is a emulator, using method B. Then, call a registered 
 * callback function depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1:    First parameter passed to the callback
 * @param param2:    Second parameter passed to the callback
 * 
 * @returns:    Return value of the callback
 */
static inline void* DSProt_CheckAndDetectEmulatorB(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectEmulatorB;
	i = DSP_CHECKSUM_INS;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectEmulatorB(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


#undef DSP_EXPECTED_CHECKSUM
#undef DSP_CHECKSUM_INS

#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public DSProt_CallbackTable
.public DSProt_CallbackIndex

.public DSProt_DecodeFunctions
.public DSProt_DetectFlashcartA
.public DSProt_DetectFlashcartB
.public DSProt_DetectEmulatorA
.public DSProt_DetectEmulatorB

#endif /* SDK_ASM */

#endif /* DSPROT_H */

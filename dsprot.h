//=================================================================================================
/**
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 2.00
 */
//=================================================================================================

#ifndef DSPROT_H
#define DSPROT_H

#ifndef SDK_ASM

#ifndef DSP_NO_NITRO

#include <nitro/types.h>  // For u32
#include <nitro/os.h>     // For OS_GetVBlankCount (inline function)

#else /* DSP_NO_NITRO */

// Assumptions for convenience-- make sure this is matching if you use it!
typedef unsigned long  __dsp_u32;
#define u32  __dsp_u32

#define HW_VBLANK_COUNT_BUF  (0x02FFFC3C)


static inline volatile u32 __DSProt_GetVBlankCount(void) {
	return *(volatile u32*)HW_VBLANK_COUNT_BUF;
}


#define OS_GetVBlankCount  __DSProt_GetVBlankCount

#endif /* DSP_NO_NITRO */

// See src/dsprot_main.c for information about this checksum procedure
#define DSP_CHECKSUM_INS       (9)
#define DSP_EXPECTED_CHECKSUM  (0x9FBB82E0)

typedef void* (*DSProt_Callback)(void*, void*);

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


//=================================================================================================
/**
 * Decode other DS Protect functions from their encoded state.
 * This is required before calling any other DS Protect functions.
 */
//=================================================================================================
extern void DSProt_DecodeFunctions(void);


// DS Protect functions to be called by inlines
extern void* DSProt_DetectFlashcartA(void* param1, void* param2);
extern void* DSProt_DetectFlashcartB(void* param1, void* param2);
extern void* DSProt_DetectEmulatorA(void* param1, void* param2);
extern void* DSProt_DetectEmulatorB(void* param1, void* param2);

// Globals used to store registered callbacks
extern DSProt_Callback  DSProt_CallbackTable[2];
extern u32              DSProt_CallbackIndex;

#ifdef __cplusplus
}
#endif /* __cplusplus */


//=================================================================================================
/**
 * Register callbacks to be run according to the results of environment tests. Cannot specify NULL.
 * 
 * @param pass_callback Callback to run if a test DOES NOT detect piracy or tampering
 * @param fail_callback Callback to run if a test DOES detect piracy or tampering
 */
//=================================================================================================
static inline void DSProt_RegisterCallbacks(DSProt_Callback pass_callback, DSProt_Callback fail_callback) {
	DSProt_CallbackIndex = OS_GetVBlankCount() & 1;
	DSProt_CallbackTable[DSProt_CallbackIndex    ] = pass_callback;
	DSProt_CallbackTable[DSProt_CallbackIndex ^ 1] = fail_callback;
}


//=================================================================================================
/**
 * Run a tamper-detection checksum, then detect if the current environment
 * is a flashcart using method A. Call a registered callback function
 * depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1 First parameter passed to the callback
 * @param param2 Second parameter passed to the callback
 * 
 * @return Return value of the callback
 */
//=================================================================================================
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


//=================================================================================================
/**
 * Run a tamper-detection checksum, then detect if the current environment
 * is a flashcart using method B. Call a registered callback function
 * depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1 First parameter passed to the callback
 * @param param2 Second parameter passed to the callback
 * 
 * @return Return value of the callback
 */
//=================================================================================================
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


//=================================================================================================
/**
 * Run a tamper-detection checksum, then detect if the current environment
 * is an emulator using method A. Call a registered callback function
 * depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1 First parameter passed to the callback
 * @param param2 Second parameter passed to the callback
 * 
 * @return Return value of the callback
 */
//=================================================================================================
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


//=================================================================================================
/**
 * Run a tamper-detection checksum, then detect if the current environment
 * is an emulator using method B. Call a registered callback function
 * depending upon the result (see DSProt_RegisterCallbacks).
 * 
 * @param param1 First parameter passed to the callback
 * @param param2 Second parameter passed to the callback
 * 
 * @return Return value of the callback
 */
//=================================================================================================
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

#ifdef DSP_NO_NITRO

#undef OS_GetVBlankCount
#undef HW_VBLANK_COUNT_BUF
#undef u32

#endif /* DSP_NO_NITRO */

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

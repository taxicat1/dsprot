#ifndef DSPROT_H
#define DSPROT_H

#ifndef SDK_ASM

#include <nitro/types.h> // u32
#include <nitro/os.h> // OS_GetVBlankCount

#ifdef __cplusplus
extern "C" {
#endif

extern void DSProt_DecodeFunctions(void);
extern void* DSProt_DetectFlashcartA(void* param1, void* param2);
extern void* DSProt_DetectFlashcartB(void* param1, void* param2);
extern void* DSProt_DetectEmulatorA(void* param1, void* param2);
extern void* DSProt_DetectEmulatorB(void* param1, void* param2);

#define DSP_EXPECTED_CHECKSUM  (0x9F75A8D6)

typedef void* (*DSProt_Callback)(void*, void*);

extern DSProt_Callback DSProt_CallbackTable[2];
extern u32 DSProt_CallbackIndex;


static inline void DSProt_RegisterCallbacks(DSProt_Callback success_callback, DSProt_Callback failure_callback) {
	DSProt_CallbackIndex = OS_GetVBlankCount() & 1;
	DSProt_CallbackTable[DSProt_CallbackIndex    ] = success_callback;
	DSProt_CallbackTable[DSProt_CallbackIndex ^ 1] = failure_callback;
}


static inline void* DSProt_CheckAndDetectFlashcartA(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectFlashcartA;
	i = 37;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectFlashcartA(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


static inline void* DSProt_CheckAndDetectFlashcartB(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectFlashcartB;
	i = 37;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectFlashcartB(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


static inline void* DSProt_CheckAndDetectEmulatorA(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectEmulatorA;
	i = 37;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectEmulatorA(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


static inline void* DSProt_CheckAndDetectEmulatorB(void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectEmulatorB;
	i = 37;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> i) | (*func_data_ptr << (32-i));
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectEmulatorB(param1, param2);
	} else {
		return (DSProt_CallbackTable[DSProt_CallbackIndex ^ 1])(param1, param2);
	}
}


#undef DSP_EXPECTED_CHECKSUM

#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public DSProt_DecodeFunctions
.public DSProt_DetectFlashcartA
.public DSProt_DetectFlashcartB
.public DSProt_DetectEmulatorA
.public DSProt_DetectEmulatorB

#endif /* SDK_ASM */

#endif /* DSPROT_H */

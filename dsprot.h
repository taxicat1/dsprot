#ifndef DSPROT_H
#define DSPROT_H

#ifndef SDK_ASM

#include <nitro/types.h> // u32

#ifdef __cplusplus
extern "C" {
#endif

extern u32 DSProt_DetectFlashcart(void* callback, void* param);
extern u32 DSProt_DetectNotFlashcart(void* callback, void* param);
extern u32 DSProt_DetectEmulator(void* callback, void* param);
extern u32 DSProt_DetectNotEmulator(void* callback, void* param);
extern u32 DSProt_DetectDummy(void* callback, void* param);
extern u32 DSProt_DetectNotDummy(void* callback, void* param);

static u32 __DSProt_compatibility_wrapper(void* callback);


static u32 __DSProt_compatibility_wrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	
	return ~(u32)callback;
}


static inline u32 DSProt_DetectFlashcart_Old(void* callback) {
	return DSProt_DetectFlashcart(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
}


static inline u32 DSProt_DetectNotFlashcart_Old(void* callback) {
	return DSProt_DetectNotFlashcart(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
}


static inline u32 DSProt_DetectEmulator_Old(void* callback) {
	return DSProt_DetectEmulator(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
}


static inline u32 DSProt_DetectNotEmulator_Old(void* callback) {
	return DSProt_DetectNotEmulator(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
}


static inline u32 DSProt_DetectDummy_Old(void* callback) {
	return DSProt_DetectDummy(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
}


static inline u32 DSProt_DetectNotDummy_Old(void* callback) {
	return DSProt_DetectNotDummy(__DSProt_compatibility_wrapper, callback) == ~(u32)callback;
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

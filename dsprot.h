#ifndef DSPROT_H
#define DSPROT_H

// Expected return values if no flashcart/emulator/tampering was detected
#define DSP_DETECTFLASHCART_OK     3292783
#define DSP_DETECTNOTFLASHCART_OK  3299395
#define DSP_DETECTEMULATOR_OK      3297121
#define DSP_DETECTNOTEMULATOR_OK   3298087
#define DSP_DETECTDUMMY_OK         3249644
#define DSP_DETECTNOTDUMMY_OK      3249446

#ifndef SDK_ASM

#include <nitro/types.h> // u32

#ifdef __cplusplus
extern "C" {
#endif

extern u32 DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);
extern u32 DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);
extern u32 DSProt_DetectEmulator(void* callback, void* param, u32 __unused);
extern u32 DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);
extern u32 DSProt_DetectDummy(void* callback, void* param, u32 __unused);
extern u32 DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);

static u32 __DSProt_compatibilityWrapper(void* callback);


static u32 __DSProt_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~(u32)callback;
}


static inline u32 DSProt_DetectFlashcart_Old(void* callback) {
	return DSProt_DetectFlashcart(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


static inline u32 DSProt_DetectNotFlashcart_Old(void* callback) {
	return DSProt_DetectNotFlashcart(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


static inline u32 DSProt_DetectEmulator_Old(void* callback) {
	return DSProt_DetectEmulator(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


static inline u32 DSProt_DetectNotEmulator_Old(void* callback) {
	return DSProt_DetectNotEmulator(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


static inline u32 DSProt_DetectDummy_Old(void* callback) {
	return DSProt_DetectDummy(__DSProt_compatibilityWrapper, callback, 0) == ~(u32)callback;
}


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

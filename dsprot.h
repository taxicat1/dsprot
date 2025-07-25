#ifndef DSPROT_H
#define DSPROT_H

// Expected return values if no flashcart/emulator/tampering was detected
#define DSP_DETECTFLASHCART_OK     1830601
#define DSP_DETECTNOTFLASHCART_OK  1831551
#define DSP_DETECTEMULATOR_OK      1830203
#define DSP_DETECTNOTEMULATOR_OK   1830859
#define DSP_DETECTDUMMY_OK         1828014
#define DSP_DETECTNOTDUMMY_OK      1829648

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

static u32 __DSProt_DetectFlashcart_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotFlashcart_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectEmulator_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotEmulator_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectDummy_compatibilityWrapper(void* callback);
static u32 __DSProt_DetectNotDummy_compatibilityWrapper(void* callback);

// Each wrapper here needs a unique address
static u32 __DSProt_DetectFlashcart_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTFLASHCART_OK;
}


static u32 __DSProt_DetectNotFlashcart_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTNOTFLASHCART_OK;
}


static u32 __DSProt_DetectEmulator_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTEMULATOR_OK;
}


static u32 __DSProt_DetectNotEmulator_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTNOTEMULATOR_OK;
}


static u32 __DSProt_DetectDummy_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTDUMMY_OK;
}


static u32 __DSProt_DetectNotDummy_compatibilityWrapper(void* callback) {
	if (callback) {
		((void (*)(void))callback)();
	}
	return ~DSP_DETECTNOTDUMMY_OK;
}



static inline u32 DSProt_DetectFlashcart_Old(void* callback) {
	return DSProt_DetectFlashcart(__DSProt_DetectFlashcart_compatibilityWrapper, callback, 0) == ~DSP_DETECTFLASHCART_OK;
}


static inline u32 DSProt_DetectNotFlashcart_Old(void* callback) {
	return DSProt_DetectNotFlashcart(__DSProt_DetectNotFlashcart_compatibilityWrapper, callback, 0) == ~DSP_DETECTNOTFLASHCART_OK;
}


static inline u32 DSProt_DetectEmulator_Old(void* callback) {
	return DSProt_DetectEmulator(__DSProt_DetectEmulator_compatibilityWrapper, callback, 0) == ~DSP_DETECTEMULATOR_OK;
}


static inline u32 DSProt_DetectNotEmulator_Old(void* callback) {
	return DSProt_DetectNotEmulator(__DSProt_DetectNotEmulator_compatibilityWrapper, callback, 0) == ~DSP_DETECTNOTEMULATOR_OK;
}


static inline u32 DSProt_DetectDummy_Old(void* callback) {
	return DSProt_DetectDummy(__DSProt_DetectDummy_compatibilityWrapper, callback, 0) == ~DSP_DETECTDUMMY_OK;
}


static inline u32 DSProt_DetectNotDummy_Old(void* callback) {
	return DSProt_DetectNotDummy(__DSProt_DetectNotDummy_compatibilityWrapper, callback, 0) == ~DSP_DETECTNOTDUMMY_OK;
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

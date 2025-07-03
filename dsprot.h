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

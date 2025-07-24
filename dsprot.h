#ifndef DSPROT_H
#define DSPROT_H

#ifndef SDK_ASM

#include <nitro/types.h> // u32

#ifdef __cplusplus
extern "C" {
#endif

extern u32 __DSProt_DetectFlashcart(u32 callback_addr);
extern u32 __DSProt_DetectNotFlashcart(u32 callback_addr);
extern u32 __DSProt_DetectEmulator(u32 callback_addr);
extern u32 __DSProt_DetectNotEmulator(u32 callback_addr);
extern u32 __DSProt_DetectDummy(u32 callback_addr);
extern u32 __DSProt_DetectNotDummy(u32 callback_addr);

#define __DSP_OBFS_OFFSET  (0x320)
#define __DSP_OBFS_PTR(p)  (((u32)(p)) ^ __DSP_OBFS_OFFSET)

// Inlines do not match, only macros
#define DSProt_DetectFlashcart(callback)     (__DSProt_DetectFlashcart(__DSP_OBFS_PTR(callback)))
#define DSProt_DetectNotFlashcart(callback)  (__DSProt_DetectNotFlashcart(__DSP_OBFS_PTR(callback)))
#define DSProt_DetectEmulator(callback)      (__DSProt_DetectEmulator(__DSP_OBFS_PTR(callback)))
#define DSProt_DetectNotEmulator(callback)   (__DSProt_DetectNotEmulator(__DSP_OBFS_PTR(callback)))
#define DSProt_DetectDummy(callback)         (__DSProt_DetectDummy(__DSP_OBFS_PTR(callback)))
#define DSProt_DetectNotDummy(callback)      (__DSProt_DetectNotDummy(__DSP_OBFS_PTR(callback)))

#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

// Must apply the argument modification from the macro manually in assembly
.public __DSProt_DetectFlashcart
.public __DSProt_DetectNotFlashcart
.public __DSProt_DetectEmulator
.public __DSProt_DetectNotEmulator
.public __DSProt_DetectDummy
.public __DSProt_DetectNotDummy

#endif /* SDK_ASM */

#endif /* DSPROT_H */

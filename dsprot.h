#ifndef DSPROT_H
#define DSPROT_H

/* 
 * dsprot.h
 * 
 * Header file for the DS Protect library
 * Version 1.00/2 (unknown)
 */

#ifndef SDK_ASM

#include <nitro/types.h>  // For u32

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Internal DS Protect functions to be called by macros
 */
extern u32 __DSProt_DetectFlashcart(u32 callback_addr);
extern u32 __DSProt_DetectNotFlashcart(u32 callback_addr);
extern u32 __DSProt_DetectDummy(u32 callback_addr);
extern u32 __DSProt_DetectNotDummy(u32 callback_addr);

/* 
 * Internal macros for function pointer preparation as the internal functions expect
 */
#define __DSP_OBFS_OFFSET  (0x190)
#define __DSP_OBFS_PTR(p)  (((u32)(p)) ^ __DSP_OBFS_OFFSET)


/* 
 * u32 DSProt_DetectFlashcart(void* callback)
 * 
 * Detect if the current environment is a flashcart.
 * 
 * @param callback:    Function to be called if the environment is determined to be a flashcart. May be NULL.
 * 
 * @returns:    1 if the environment is determined to be a flashcart, 0 otherwise
 */
#define DSProt_DetectFlashcart(callback)  (__DSProt_DetectFlashcart(__DSP_OBFS_PTR(callback)))


/* 
 * u32 DSProt_DetectNotFlashcart(void* callback)
 * 
 * Detect if the current environment is NOT a flashcart.
 * 
 * @param callback:    Function to be called if the environment is determined to NOT be a flashcart. May be NULL.
 * 
 * @returns:    1 if the environment is determined to NOT be a flashcart, 0 otherwise
 */
#define DSProt_DetectNotFlashcart(callback)  (__DSProt_DetectNotFlashcart(__DSP_OBFS_PTR(callback)))


/* 
 * u32 DSProt_DetectDummy(void* callback)
 * 
 * Dummy environment detection function that does not do anything. Will always fail.
 * 
 * @param callback:    Dummy callback function which will never be called. May be NULL.
 * 
 * @returns:    0
 */
#define DSProt_DetectDummy(callback)  (__DSProt_DetectDummy(__DSP_OBFS_PTR(callback)))


/* 
 * u32 DSProt_DetectNotDummy(void* callback)
 * 
 * Dummy environment detection function that does not do anything. Will always succeed.
 * 
 * @param callback:    Dummy callback function which will always be called. May be NULL.
 * 
 * @returns:    1
 */
#define DSProt_DetectNotDummy(callback)  (__DSProt_DetectNotDummy(__DSP_OBFS_PTR(callback)))


#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

;/* Must apply the argument modification from the macro manually in assembly */

.public __DSProt_DetectFlashcart
.public __DSProt_DetectNotFlashcart
.public __DSProt_DetectDummy
.public __DSProt_DetectNotDummy

#endif /* SDK_ASM */

#endif /* DSPROT_H */

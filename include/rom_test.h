#ifndef ROM_TEST_H
#define ROM_TEST_H

#include "types.h"

// Nitro functions
// <nitro/os.h>
// <nitro/card.h>
extern s32 OS_GetLockID(void);
extern void CARD_LockRom(u16 lock_id);
extern void CARD_UnlockRom(u16 lock_id);
extern void OS_ReleaseLockID(u16 lock_id);

// Nitro function without header support (anymore)
extern void CARDi_ReadRom(u32 dma, const void *src, void *dst, u32 len, void* callback, void *arg, BOOL is_async);

// Assembly decryption wrappers
extern u32 RunEncrypted_ROMTest_IsBad(void);
extern u32 RunEncrypted_ROMTest_IsGood(void);

#endif

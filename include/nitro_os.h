#ifndef NITRO_OS_H
#define NITRO_OS_H

#include "nitro_types.h"

// <nitro/os.h>
extern s32 OS_GetLockID(void);

// BUG: OS_ReleaseLockID() is supposed to be called and never is
//extern void OS_ReleaseLockID(u16 lock_id);

extern void DC_StoreAll(void);
extern void IC_Disable(void);
extern void IC_Enable(void);

#endif

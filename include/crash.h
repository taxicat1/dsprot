#ifndef CRASH_H
#define CRASH_H

#include "types.h"

// Assembly decryption wrapper
extern u32 DSProt_Crash(u32 __unused1, u32 __unused2);

// Nitro functions
// <nitro/os.h>
extern void OS_Terminate(void);
// <nitro/mi.h>
extern void MIi_CpuClear32(register u32 data, register void *destp, register u32 size);

#endif

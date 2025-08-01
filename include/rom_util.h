#ifndef ROM_UTIL_H
#define ROM_UTIL_H

#include "types.h"

u32 ROMUtil_CRC32(void* buf, u32 size);

// Assembly decoder
extern void CoreTests_DecodeFunctions(void);

#endif

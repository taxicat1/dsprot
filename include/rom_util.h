#ifndef ROM_UTIL_H
#define ROM_UTIL_H

#include "nitro_types.h"

void ROMUtil_Read(void* dest, u32 addr, s32 num_bytes);
u32 ROMUtil_CRC32(void* buf, u32 size);

#endif

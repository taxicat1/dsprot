#ifndef ROM_UTIL_H
#define ROM_UTIL_H

#include "nitro_types.h"

// Assembly decryption wrapper
extern u32 RunEncrypted_ROMUtil_CRC32(void* buf, u32 size);

#endif

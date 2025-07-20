#ifndef ROM_UTIL_H
#define ROM_UTIL_H

#include "types.h"

// Assembly decryption wrappers
extern u32 RunEncrypted_ROMUtil_CRC32(void* buf, u32 size);

#endif

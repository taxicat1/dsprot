#ifndef RC4_H
#define RC4_H

#include "nitro_types.h"

typedef u32 (*FuncType_RC4_InitAndDecryptInstructions)(void* key, void* dst, void* src, u32 size);
typedef u32 (*FuncType_RC4_InitAndEncryptInstructions)(void* key, void* dst, void* src, u32 size);

extern const u32 Proxy_RC4_InitAndDecryptInstructions;
extern const u32 Proxy_RC4_InitAndEncryptInstructions;

#endif

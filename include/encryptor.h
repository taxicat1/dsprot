#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "nitro_types.h"

typedef struct {
	u32  obfs_addr;
	u32  obfs_size;
} FuncInfo;

void Encryptor_DecodeFunctionTable(FuncInfo* functions);
u32 Encryptor_DecryptionWrapperFragment(void);

#endif

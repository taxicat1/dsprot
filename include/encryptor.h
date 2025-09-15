#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "types.h"

typedef struct {
	u32  obfs_addr;
	u32  obfs_size;
} FuncInfo;

void Encryptor_DecodeFunctionTable(FuncInfo* functions);
u32 Encryptor_DecryptionWrapperFragment(void);

// Assembly decoder
extern void Encryptor_DecodeFunctions(void);

#endif

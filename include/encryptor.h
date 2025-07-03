#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "types.h"

typedef struct {
	void*  start_addr;
	u32    size;
} FuncInfo;

u32 Encryptor_CategorizeInstruction(u32 instruction);
void Encryptor_DecodeFunctionTable(FuncInfo* functions);
void* Encryptor_DecryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size);
u32 Encryptor_EncryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size);
u32 Encryptor_DecryptionWrapperFragment(void);

#endif

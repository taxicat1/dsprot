#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "types.h"

typedef struct {
	void*  start_addr;
	u32    size;
} FuncInfo;

void Encryptor_DecodeFunctionTable(FuncInfo* functions);
u32 Encryptor_DecryptionWrapperFragment(void);

#endif

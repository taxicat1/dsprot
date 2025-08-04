#ifndef HASH_H
#define HASH_H

#include "keydata.h"

typedef struct {
	char*  input_fname;
	char*  target_symbol;
	char*  output_fname;
} FuncHashTask;


void Hash_Instructions(uint32_t* instructions, int num, KeyData* out);

#endif

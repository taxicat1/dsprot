#ifndef KEYDATA_H
#define KEYDATA_H

#include <stdint.h>

typedef struct {
	uint8_t   hashed_instructions;
	uint32_t  key;
} KeyData;

int KeyData_Write(KeyData* key, char* output_fname);

#endif

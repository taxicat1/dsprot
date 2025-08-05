#include <stdio.h>
#include <stdlib.h>

#include "keydata.h"

int KeyData_Read(KeyData* key, char* input_fname) {
	if (input_fname == NULL) {
		return 1;
	}
	
	FILE* input = fopen(input_fname, "r");
	if (input == NULL) {
		return 1;
	}
	
	int reads = 0;
	reads += fread(&key->hashed_instructions, sizeof(uint8_t), 1, input);
	reads += fread(&key->key, sizeof(uint32_t), 1, input);
	
	fclose(input);
	
	if (reads != 2) {
		return 1;
	}
	
	return 0;
}

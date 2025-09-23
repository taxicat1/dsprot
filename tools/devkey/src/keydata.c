#include <stdio.h>
#include <stdlib.h>

#include "keydata.h"


int KeyData_Write(KeyData* key, char* output_fname) {
	if (output_fname == NULL) {
		// No file so print to stdout
		printf("Hashed instructions: %i\n", key->hashed_instructions);
		printf("Derived key: %08x\n", key->key);
		return 0;
	} else {
		FILE* output = fopen(output_fname, "w");
		if (output == NULL) {
			return 1;
		}
		
		fwrite(&key->hashed_instructions, sizeof(uint8_t), 1, output);
		fwrite(&key->key, sizeof(uint32_t), 1, output);
		
		fclose(output);
		return 0;
	}
}

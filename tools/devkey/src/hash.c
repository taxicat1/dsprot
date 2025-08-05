#include <stddef.h>

#include "hash.h"


static inline uint32_t ror(uint32_t x, unsigned int amt) {
	amt %= 32;
	return ( x >> amt) | (x << (32 - amt));
}

void Hash_Instructions(uint32_t* instructions, int num, KeyData* out) {
	uint32_t hash = 0;
	
	int i = num;
	do {
		uint32_t ins = *instructions++;
		
		switch (ins >> 24) {
			case 0xEA:
			case 0xEB:
				break;
			
			default:
				hash ^= ror(ins, 17);
				hash += ror(ins, 28);
				hash ^= ror(ins, i);
				break;
		}
	} while (--i);
	
	out->key = hash;
	out->hashed_instructions = num;
}

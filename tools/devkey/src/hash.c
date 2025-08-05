#include <stddef.h>

#include "hash.h"


void Hash_Instructions(uint32_t* instructions, int num, KeyData* out) {
	uint32_t hash = 0;
	
	for (int i = num; i >= 0; i--) {
		uint32_t ins = *instructions++;
		
		switch (ins >> 24) {
			case 0xEA:
			case 0xEB:
				break;
			
			default:
				hash ^= (ins >> 17) | (ins << (32-17));
				hash += (ins >> 28) | (ins << (32-28));
				hash ^= (ins >>  i) | (ins << (32- i));
				break;
		}
	}
	
	out->key = hash;
	out->hashed_instructions = num;
}

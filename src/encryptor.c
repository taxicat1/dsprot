#include "encryptor.h"

#include "nitro_os.h"
#include "rc4.h"


void Encryptor_StartRange(u32* addr) {
	u8   key[16];
	int  i;
	u32  key_ins;
	u8*  keyptr;
	u32  size;
	
	// First key is immediately prior to start address
	key_ins = addr[-1];
	
	// Derive RC4 key
	keyptr = &key[0];
	for (i = 0; i < 16; i++) {
		*keyptr = key_ins >> ((i % 4) * 8);
		if (i % 15 == 0) {
			*keyptr ^= 0xFF;
		}
		keyptr++;
	}
	
	// Search forward for second key to determine size
	size = 0;
	while (key_ins != addr[size]) {
		size++;
	}
	
	if (size) {
		RC4_InitAndDecryptInstructions(&key[0], addr, addr, size * 4);
	}
	
	DC_FlushRange(addr, size * 4);
	IC_InvalidateRange(addr, size * 4);
}


void Encryptor_EndRange(u32* addr) {
	u8   key[16];
	int  i;
	u32  key_ins;
	u8*  keyptr;
	u32  size;
	
	// Second key is immediately following the end address
	key_ins = addr[1];
	
	// Derive RC4 key
	keyptr = &key[0];
	for (i = 0; i < 16; i++) {
		*keyptr = key_ins >> ((i % 4) * 8);
		if (i % 15 == 0) {
			*keyptr ^= 0xFF;
		}
		keyptr++;
	}
	
	// Search backward for first key
	while (*addr != key_ins) {
		addr--;
	}
	
	// The start address comes immediately after the first key
	addr++;
	
	// Search forward from start to determine size
	size = 0;
	while (key_ins != addr[size]) {
		size++;
	}
	
	if (size) {
		RC4_InitAndEncryptInstructions(&key[0], addr, addr, size * 4);
	}
	
	DC_FlushRange(addr, size * 4);
	IC_InvalidateRange(addr, size * 4);
}

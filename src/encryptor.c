#include "encryptor.h"

#include "nitro_os.h"
#include "rc4.h"

static void setCacheDisabled(BOOL disable);


static void setCacheDisabled(BOOL disable) {
	if (disable) {
		DC_StoreAll();
		IC_Disable();
	} else {
		IC_Enable();
		DC_StoreAll();
	}
}


void Encryptor_StartRange(u32* addr) {
	u8   key[16];
	int  i;
	u32  key_ins;
	u8*  key_ptr;
	u32  size;
	
	// First key is immediately prior to start address
	key_ins = addr[-1];
	
	// Derive RC4 key
	key_ptr = &key[0];
	for (i = 0; i < 16; i++) {
		*key_ptr = key_ins >> ((i % 4) * 8);
		if (i % 15 == 0) {
			*key_ptr ^= 0xFF;
		}
		key_ptr++;
	}
	
	// Search forward for second key to determine size
	size = 0;
	while (key_ins != addr[size]) {
		size++;
	}
	
	if (size > 0) {
		RC4_InitAndDecryptInstructions(&key[0], addr, addr, size * 4);
	}
	
	setCacheDisabled(TRUE);
}


void Encryptor_EndRange(u32* addr) {
	u8   key[16];
	int  i;
	u32  key_ins;
	u8*  key_ptr;
	u32  size;
	
	// Second key is immediately following the end address
	key_ins = addr[1];
	
	// Derive RC4 key
	key_ptr = &key[0];
	for (i = 0; i < 16; i++) {
		*key_ptr = key_ins >> ((i % 4) * 8);
		if (i % 15 == 0) {
			*key_ptr ^= 0xFF;
		}
		key_ptr++;
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
	
	if (size > 0) {
		RC4_InitAndEncryptInstructions(&key[0], addr, addr, size * 4);
	}
	
	setCacheDisabled(FALSE);
}

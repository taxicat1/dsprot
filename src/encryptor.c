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
	u32  key[4];
	u32  size;
	u32  key_ins;
	
	// First key is immediately prior to start address
	key_ins = addr[-1];
	
	// Derive RC4 key
	key[0] = key_ins ^ 0x000000FF;
	key[1] = key_ins;
	key[2] = key_ins;
	key[3] = key_ins ^ 0xFF000000;
	
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
	u32  key[4];
	u32  size;
	u32  key_ins;
	
	// Second key is immediately following the end address
	key_ins = addr[1];
	
	// Derive RC4 key
	key[0] = key_ins ^ 0x000000FF;
	key[1] = key_ins;
	key[2] = key_ins;
	key[3] = key_ins ^ 0xFF000000;
	
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

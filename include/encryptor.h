#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "nitro_types.h"

void Encryptor_StartRange(u32* addr);
void Encryptor_EndRange(u32* addr);

// Encryption range macros
#define ENCRYPTION_START(enc_key) \
	asm {                              \
	    stmfd  sp!, {r0};              \
	    mov    r0, pc;                 \
	    add    r0, r0, #0x10;          \
	    bl     Encryptor_StartRange;   \
	    ldmia  sp!, {r0};              \
	    b      @_encstart ## enc_key;  \
	    dcd    0xEB000000 + enc_key;   \
	@_encstart ## enc_key:             \
	}

#define ENCRYPTION_END(enc_key) \
	asm {                             \
	    b      @_encend ## enc_key;   \
	    dcd    0xEB000000 + enc_key;  \
	@_encend ## enc_key:              \
	    stmfd  sp!, {r0};             \
	    mov    r0, pc;                \
	    sub    r0, r0, #0x14;         \
	    bl     Encryptor_EndRange;    \
	    ldmfd  sp!, {r0};             \
	}

#endif

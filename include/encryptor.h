#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include "types.h"

// Nitro functions
// <nitro/os.h>
extern void DC_StoreAll(void);
extern void IC_Disable(void);
extern void IC_Enable(void);

void Encryptor_StartRange(u32* addr);
void Encryptor_EndRange(u32* addr);

// Encryption range macros
#define ENCRYPTION_START(enc_key) \
	asm {                              \
	    stmfd  sp!, {r0};              \
	    mov    r0, #12;                \
	    add    r0, r0, pc;             \
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
	    sub    r0, r0, #20;           \
	    bl     Encryptor_EndRange;    \
	    ldmfd  sp!, {r0};             \
	}

#endif

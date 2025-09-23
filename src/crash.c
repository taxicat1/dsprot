#include "crash.h"

#include "encoding_constants.h"
#include "nitro_mi.h"
#include "nitro_os.h"

static void memClear(void* addr, u32 size);

// Function to be encrypted (cannot be called directly)
void* Crash(register void* __unused1, register void* __unused2);


asm void* Crash(register void* __unused1, register void* __unused2) {
	mov    r10, pc                      /* Copy `pc` out */
	orrs   r10, r10, r10                /* Checking if `pc` was 0 (should never be?) */
	eorne  lr, lr, lr                   /* If not 0, `lr` is cleared (which does nothing since `lr` is overwritten anyway) */
	subs   r10, r10, #8                 /* Subtract 8 to get start of this function */
	ldr    r9, =memClear+ENC_VAL_1      /* Load obfuscated `memClear` function address */
	mov    r0, sp                       /* Move stack pointer to first argument */
	sub    r9, r9, #ENC_VAL_1           /* Deobfuscate `memClear` address */
	mov    r1, #0x100                   /* Move 0x100 (256 bytes) to second argument */
	blx    r9                           /* Call memClear (this overwrites `lr`), clobbering 256 bytes of the stack */
	ldr    lr, =OS_Terminate+ENC_VAL_1  /* Load obfuscated `OS_Terminate` function address to `lr` */
	mov    r0, r10                      /* Move `r10` (the start of this function) to first argument */
	mov    r1, #0x1000                  /* Move 0x1000 (4096 bytes) to second argument */
	sub    lr, lr, #ENC_VAL_1           /* Deobfuscate `OS_Terminate` link return */
	bx     r9                           /* Jump to `memClear`, clobbering 4096 bytes of RAM, returning to `lr` (`OS_Terminate`) afterwards */
	/* No return */
}


// Unclear why this wrapper is needed
static void memClear(void* addr, u32 size) {
	MIi_CpuClear32(0, addr, size);
}

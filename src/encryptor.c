#include "encryptor.h"

#include "bss.h"
#include "encoding_constants.h"
#include "nitro_os.h"
#include "proxy_func.h"
#include "rc4.h"

#define ROTL(x, a)  ((a) == 0 ? (x) : (((x) << (a)) | ((x) >> (32 - (a)))))

// Functions to be encoded (cannot be static)
void* Encryptor_DecryptFunction(u32 key, u32 func_addr, u32 size);
u32 Encryptor_EncryptFunction(u32 key, u32 func_addr, u32 size);

const u32 Proxy_Encryptor_DecryptFunction = ADDR_PLUS_ADDEND(Encryptor_DecryptFunction, ENC_VAL_1);
const u32 Proxy_Encryptor_EncryptFunction = ADDR_PLUS_ADDEND(Encryptor_EncryptFunction, ENC_VAL_1);

// FuncTypes omitted since these are only called via assembly


static inline void clearDataAndInstructionCache(void) {
	// This function is an inlining and combination of DC_FlushAll, IC_InvalidateAll, and DC_WaitWriteBufferEmpty.
	// All of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c
	
	// This function must also be an asm literal inside a C function, not an asm function, in order to inline properly.
	
	asm {
		/* DC_FlushAll */
		mov  ip, #0
		mov  r1, #0
	@1:
		mov  r0, #0
	@2:
		orr  r2, r1, r0
		mcr  p15, 0, ip, c7, c10, 4  /* Wait write buffer empty */
		mcr  p15, 0, r2, c7, c14, 2  /* DC flush */
		
		add  r0, r0, #HW_CACHE_LINE_SIZE
		cmp  r0, #HW_DCACHE_SIZE/4
		blt  @2
		
		add  r1, r1, 1<<HW_C7_CACHE_SET_NO_SHIFT
		cmp  r1, #0
		bne  @1
		
		/* IC_InvalidateAll */
		mov  r0, #0
		mcr  p15, 0, r0, c7, c5, 0
		
		/* DC_WaitWriteBufferEmpty */
		mcr  p15, 0, ip, c7, c10, 4
	}
}


void Encryptor_DecodeFunctionTable(FuncInfo* functions) {
	u32*  addr;
	u32   size;
	u32*  end_addr;
	u32*  prevmem;
	u32   xorval;
	
	// Zero memory in the function callee
	prevmem = (u32*)functions - 3;
	prevmem[0] = prevmem[1] = prevmem[2] = 0;
	
	do {
		xorval = ENC_XOR_START;
		
		addr = (u32*)(functions->obfs_addr - ENC_VAL_1);
		size = functions->obfs_size - (u32)&BSS - ENC_VAL_1;
		
		end_addr = addr + (size / 4);
		
		for (; addr < end_addr; addr++) {
			*addr ^= xorval;
			xorval ^= *addr - (*addr >> 8);
		}
		
		// Zero memory in the argument data structure
		functions->obfs_addr = functions->obfs_size = 0;
		
		functions++;
	} while (functions->obfs_addr != 0);
	
	clearDataAndInstructionCache();
}


static inline void expandRC4Key(u32 seed_key, u32 size, u32* expanded_key) {
	expanded_key[0] = ROTL(seed_key,  0) ^ size;
	expanded_key[1] = ROTL(seed_key,  8) ^ size;
	expanded_key[2] = ROTL(seed_key, 16) ^ size;
	expanded_key[3] = ROTL(seed_key, 24) ^ size;
}


void* Encryptor_DecryptFunction(u32 key, u32 func_addr, u32 size) {
	u32    expanded_key[4];
	void*  func_ptr;
	
	// Deobfuscate arguments
	size -= (u32)&BSS + ENC_VAL_1;
	
	func_ptr = (void*)func_addr;
	func_ptr -= ENC_VAL_1;
	
	key -= (u32)&BSS + ENC_VAL_1;
	
	expandRC4Key(key, size, &expanded_key[0]);
	PROXY_FUNC(RC4_InitAndDecryptInstructions)(&expanded_key[0], func_ptr, func_ptr, size);
	clearDataAndInstructionCache();
	
	return func_ptr;
}


u32 Encryptor_EncryptFunction(u32 key, u32 func_addr, u32 size) {
	u32    expanded_key[4];
	void*  func_ptr;
	
	// Deobfuscate arguments and change key
	size -= (u32)&BSS + ENC_VAL_1;
	
	func_ptr = (void*)func_addr;
	func_ptr -= ENC_VAL_1;
	
	key -= (u32)&BSS + ENC_VAL_1;
	key += func_addr & 0x0000FFFF;
	
	expandRC4Key(key, size, &expanded_key[0]);
	PROXY_FUNC(RC4_InitAndEncryptInstructions)(&expanded_key[0], func_ptr, func_ptr, size);
	clearDataAndInstructionCache();
	
	// Re-obfuscate key
	key += (u32)&BSS + ENC_VAL_1;
	
	return key;
}


asm u32 Encryptor_DecryptionWrapperFragment(void) {
	/* This is a function intended only to be called from decryption wrappers after special setup. */
	/* Calling it in some other context will cause a crash. */
	
	/* This function needs to:
	   - Decrypt the inner function
	   - Call the decrypted inner function, with the arguments that were passed to the wrapper
	   - Save the return value of the inner function
	   - Re-encrypt the inner function, which changes the key
	   - Save the new key back to the callee
	   - Return back the value the inner function returned
	   
	   This is nontrivial, because you must preserve `r0`-`r3` and the stack pointer as they were before
	   this function was called. Preserving register values between calls typically means pushing them
	   onto the stack, however this is not an option as the stack pointer must be preserved for the inner
	   function to accept arguments from it.
	   
	   Instead, storage space within the instructional memory of the callee is allocated to be a temporary
	   location for register values. The stack may still be used to prepare arguments for the encryption and
	   decryption functions, and at any point after the inner function returns.
	   
	   Prior to calling, `ip` is set to the pointer of the data structure for the target function:
	       [00]  Storage space (dummy data initially)
	       [04]  Decryption key (obfuscated)
	       [08]  Function address (obfuscated)
	       [0C]  Function size in bytes (obfuscated)
	       [10]  Storage space
	*/
	
	stmfd  sp!, {r0-r3}                          /* Push inner function arguments onto the stack to save them for after decryption. */
	str    r10, [ip, #0x10]                      /* `r10` about to be used as temporary register, save it to second storage space. */
	mov    r10, ip                               /* `r10` now used for the pointer to the data structure. */
	ldr    ip, =Proxy_Encryptor_DecryptFunction  /* Load address for function decryptor proxy. */
	str    lr, [r10]                             /* `lr` (outer return address) saved to first storage space to return later. */
	ldr    ip, [ip]                              /* Load value of function decryptor proxy. */
	ldmib  r10, {r0-r2}                          /* Read function decryptor arguments from data structure (key, addr, size). */
	sub    ip, ip, #ENC_VAL_1                    /* Deobfuscate function decryptor address. */
	blx    ip                                    /* Call function decryptor, which returns de-obfuscated function address. */
	mov    ip, r0                                /* Move returned address to `ip` to free up `r0`. */
	ldmia  sp!, {r0-r3}                          /* Pop arguments to inner function (`r0`-`r3`) off the stack. Stack is now restored. */
	blx    ip                                    /* Call inner function. `r0`-`r3` and `sp` are correct for proper arguments. */
	ldr    ip, =Proxy_Encryptor_EncryptFunction  /* Load address for function encryptor proxy. */
	stmdb  sp!, {r4}                             /* `r4` about to be used as temporary register, preserve its current value on the stack. */
	ldr    ip, [ip]                              /* Load value of function encryptor proxy. */
	mov    r4, r0                                /* Preserve the return from the inner function in `r4`, move it back to `r0` later. */
	sub    ip, ip, #ENC_VAL_1                    /* Deobfuscate function decryptor address. */
	ldmib  r10, {r0-r2}                          /* Read function encryptor arguments from data structure (key, addr, size). */
	blx    ip                                    /* Call function encryptor, which returns obfuscated new key. */
	str    r0, [r10, #0x4]                       /* New key is stored back into data structure. */
	mov    r0, r4                                /* Return value from inner function is moved back to `r0` to return it. */
	ldmia  sp!, {r4}                             /* Original value of `r4` restored from the stack so we can properly return. */
	ldr    lr, [r10]                             /* Outer return address read back out from storage space into `lr`. */
	str    sp, [r10]                             /* Stack pointer overwrites storage space to hide its value (could be anything here?). */
	ldr    r10, [r10, #0x10]                     /* `r10` restored from second storage space. */
	bx     lr                                    /* Return to outer return address with return value of inner function. */
}

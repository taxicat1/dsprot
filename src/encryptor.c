#include "encryptor.h"

#include "encoding_constants.h"
#include "bss.h"
#include "rc4.h"

void* Encryptor_DecryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size);
u32 Encryptor_EncryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size);

static void clearDataAndInstructionCache(void);

const u32 Proxy_Encryptor_EncryptFunction = (u32)&Encryptor_EncryptFunction[ENC_VAL_1];
const u32 Proxy_Encryptor_DecryptFunction = (u32)&Encryptor_DecryptFunction[ENC_VAL_1];


static inline void clearDataAndInstructionCache(void) {
	// This function is an inlining and combination of DC_FlushAll, IC_InvalidateAll, and DC_WaitWriteBufferEmpty.
	// All of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c
	asm {
		/* DC_FlushAll */
		mov  ip, #0
		mov  r1, #0
	@1:
		mov  r0, #0
	@2:
		orr  r2, r1, r0
		mcr  p15, 0, ip, c7, c10, 4
		mcr  p15, 0, r2, c7, c14, 2
		
		add  r0, r0, #32
		cmp  r0, 0x400
		blt  @2
		
		add  r1, r1, 0x40000000
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
	u32*  prevmem;
	u32   addr;
	u32   size;
	u32   end_addr;
	u32   xorval;
	
	// Zero memory in the function callee
	prevmem = (u32*)functions - 3;
	prevmem[0] = prevmem[1] = prevmem[2] = 0;
	
	do {
		xorval = ENC_XOR_START;
		
		size = functions->size;
		addr = (u32)functions->start_addr;
		
		size -= (u32)&BSS;
		size -= ENC_VAL_1;
		addr -= ENC_VAL_1;
		
		end_addr = addr + ((size / 4) * 4);
		
		while (addr < end_addr) {
			u32 ins = *(u32*)addr;
			ins ^= xorval;
			*(u32*)addr = ins;
			
			addr += 4;
			xorval ^= ins - (ins >> 8);
		}
		
		// Zero memory in the argument data structure
		functions->size = 0;
		functions->start_addr = NULL;
		
		functions++;
	} while (functions->start_addr != 0);
	
	clearDataAndInstructionCache();
}


void* Encryptor_DecryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
	u32    expanded_key[4];
	u32    key;
	u32    size;
	void*  func_addr;
	u32    rc4_dec;
	
	rc4_dec = Proxy_RC4_InitAndDecryptInstructions;
	rc4_dec -= ENC_VAL_1;
	
	key  = obfs_key;
	size = obfs_size;
	key  -= (u32)&BSS + ENC_VAL_1;
	size -= (u32)&BSS + ENC_VAL_1;
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr = obfs_func_addr;
	func_addr -= ENC_VAL_1;
	
	((FuncType_RC4_InitAndDecryptInstructions)rc4_dec)(&expanded_key[0], func_addr, func_addr, size);
	
	clearDataAndInstructionCache();
	
	return func_addr;
}


// This function sucks. https://decomp.me/scratch/34NCb
// 
// This *should* be identical to `Encryptor_DecryptFunction` with the extra step
// of modifying the key, and calling the encryption function instead of decryption.
// But for some reason, all the instructions are in a totally different order.
// Something very stupid is happening.
// I suspect there is some sort of obfuscation that is being partially 
// optimized out, leaving behind only strange register patterns.
u32 Encryptor_EncryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
#ifdef NONMATCHING
	
	u32    expanded_key[4];
	u32    key;
	u32    size;
	void*  func_addr;
	u32    rc4_enc;
	
	rc4_enc = Proxy_RC4_InitAndEncryptInstructions;
	rc4_enc -= ENC_VAL_1;
	
	key  = obfs_key;
	size = obfs_size;
	key  -= (u32)&BSS + ENC_VAL_1;
	size -= (u32)&BSS + ENC_VAL_1;
	
	key += (u32)obfs_func_addr >> 20;
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr = obfs_func_addr;
	func_addr -= ENC_VAL_1;
	
	((FuncType_RC4_InitAndEncryptInstructions)rc4_enc)(&expanded_key[0], func_addr, func_addr, size);
	
	clearDataAndInstructionCache();
	
	return key + ((u32)&BSS + ENC_VAL_1);
	
#else /* NONMATCHING */
	
	// push {r4, r5, r6, lr}
	asm {
		sub  sp, sp, #16
		ldr  r3, =BSS
		mov  r4, r0
		add  r0, r3, #ENC_VAL_1
		sub  r4, r4, r0
		ldr  r5, =BSS
		add  r4, r4, r1, lsr #20
		ldr  r0, =Proxy_RC4_InitAndEncryptInstructions
		mov  r3, r2
		add  r6, r5, #ENC_VAL_1
		mov  r2, r1
		ldr  ip, [r0]
		mov  r5, r4, lsr #24
		mov  lr, r4, lsr #16
		sub  r3, r3, r6
		orr  r0, r5, r4, lsl #8
		eor  r0, r3, r0
		mov  r1, r4, lsr #8
		str  r0, [sp, #4]
		orr  r0, r1, r4, lsl #24
		eor  r1, r4, r3
		orr  lr, lr, r4, lsl #16
		str  r1, [sp]
		eor  r1, r3, lr
		eor  lr, r3, r0
		sub  r2, r2, #ENC_VAL_1
		str  r1, [sp, #8]
		add  r0, sp, #0
		mov  r1, r2
		sub  ip, ip, #ENC_VAL_1
		str  lr, [sp, #12]
		blx  ip
	}
	// Inlined
	clearDataAndInstructionCache();
	asm {
		ldr  r0, [pc, #12]
		add  r0, r0, #ENC_VAL_1
		add  r0, r4, r0
		add  sp, sp, #16
	}
	// pop  {r4, r5, r6, pc}
	
#endif /* NONMATCHING */
}


asm u32 Encryptor_DecryptionWrapperFragment(void) {
	// This is a function intended only to be called from decryption wrappers after special setup.
	// Calling it in some other context will cause a crash.
	
	// This function needs to:
	// - Decrypt the inner function
	// - Call the decrypted inner function, with the arguments that were passed to the wrapper
	// - Save the return value of the inner function
	// - Re-encrypt the inner function, which changes the key
	// - Save the new key back to the callee
	// - Return back the value the inner function returned
	//
	// This is nontrivial, because you must preserve `r0`-`r3` and the stack pointer as they were before
	// this function was called. Preserving register values between calls typically means pushing them
	// onto the stack, however this is not an option as the stack pointer must be preserved for the inner
	// function to accept arguments from it.
	//
	// Instead, storage space within the instructional memory of the callee is allocated to be a temporary
	// location for register values. The stack may still be used to prepare arguments for the encryption and
	// decryption functions, and at any point after the inner function returns.
	
	// Prior to calling, `ip` is set to the pointer of the data structure for the target function:
	//   +0x0   :  Storage space (dummy data initially)
	//   +0x4   :  Decryption key (obfuscated)
	//   +0x8   :  Function address (obfuscated)
	//   +0xC   :  Function size in bytes (obfuscated)
	//   +0x10  :  Storage space
	
	stmfd  sp!, {r0-r3}                          // Push inner function arguments onto the stack to save them for after decryption.
	str    r10, [ip, #0x10]                      // `r10` is saved to second storage space.
	mov    r10, ip                               // `r10` now used for the pointer to the data structure.
	ldr    ip, =Proxy_Encryptor_DecryptFunction  // Load address for function decryptor proxy
	str    lr, [r10]                             // `lr` (outer return address) saved to first storage space to return later.
	ldr    ip, [ip]                              // Load value of function decryptor proxy
	ldmib  r10, {r0-r2}                          // Read function decryptor arguments from data structure (key, addr, size).
	sub    ip, ip, #ENC_VAL_1                    // Deobfuscate function decryptor address
	blx    ip                                    // Call function decryptor, which returns de-obfuscated function address.
	mov    ip, r0                                // Move returned address to `ip` to free up `r0`.
	ldmia  sp!, {r0-r3}                          // Pop arguments to inner function (`r0`-`r3`) off the stack. Stack is now restored.
	blx    ip                                    // Call inner function. `r0`-`r3` and `sp` are correct for proper arguments.
	ldr    ip, =Proxy_Encryptor_EncryptFunction  // Load address for function encryptor proxy
	stmdb  sp!, {r4}                             // `r4` about to be used as temporary register, preserve its current value on the stack.
	ldr    ip, [ip]                              // Load value of function encryptor proxy
	mov    r4, r0                                // Preserve the return from the inner function in `r4`, move it back to `r0` later.
	sub    ip, ip, #ENC_VAL_1                    // Deobfuscate function decryptor address
	ldmib  r10, {r0-r2}                          // Read function encryptor arguments from data structure (key, addr, size).
	blx    ip                                    // Call function encryptor, which returns obfuscated new key.
	str    r0, [r10, #0x4]                       // New key is stored back into data structure.
	mov    r0, r4                                // Return value from inner function is moved back to `r0` to return it.
	ldmia  sp!, {r4}                             // Original value of `r4` restored from the stack so we can properly return.
	ldr    lr, [r10]                             // Outer return address read back out from storage space into `lr`.
	str    sp, [r10]                             // Stack pointer overwrites storage space to hide its value (could be anything here?).
	ldr    r10, [r10, #0x10]                     // `r10` restored from second storage space.
	bx     lr                                    // Return to outer return address with return value of inner function.
}

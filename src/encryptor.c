#include "encryptor.h"

#include "encoding_constants.h"
#include "bss.h"
#include "rc4.h"

void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes);


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
        orr r2, r1, r0
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


u32 Encryptor_CategorizeInstruction(u32 instruction) {
	u8 upper_byte;
	
	upper_byte = (instruction >> 24) & 0xFF;
	
	if ((upper_byte & 0x0E) == 0x0A) {
		if ((upper_byte & 0xF0) == 0xF0) {
			return 1;
		}
		
		if (upper_byte & 0x01) {
			return 2;
		} else {
			return 3;
		}
	}
	
	return 0;
}


void Encryptor_DecodeFunctionTable(FuncInfo* functions) {
	u32   addr;
	u32   end_addr;
	u32   xorval;
	u32   size;
	u32*  prevmem;
	u32   upper;
	u32   lower;
	
	// This overwrites the instructions in the callee, erasing them
	prevmem = (u32*)functions - 3;
	// Must be in this compound assignment to match
	prevmem[0] = prevmem[1] = prevmem[2] = 0;
	
	do {
		addr = (u32)(functions->start_addr - ENC_VAL_1);
		size = functions->size - (u32)&BSS - ENC_VAL_1;
		
		end_addr = addr + ((size >> 2) << 2);
		
		xorval = ENC_XOR_START;
		
		for (; addr < end_addr; addr += 4) {
			switch (Encryptor_CategorizeInstruction(*(u32*)addr)) {
				case 1:
				case 3:
					upper = ((*(u32*)addr & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF;
					lower = ((*(u32*)addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24));
					*(u32*)addr = lower | upper;
					
					xorval ^= *(u32*)addr >> 24;
					xorval &= 0x00FFFFFF;
					break;
				
				case 2:
					*(u32*)addr ^= (ENC_OPCODE_1 << 24);
				
				default:
					*(u32*)addr ^= xorval;
					xorval ^= *(u32*)addr;
					xorval ^= *(u32*)addr >> 8;
					xorval &= 0x00FFFFFF;
			}
		}
		
		clearDataAndInstructionCache();
		// Must be like this to match
		functions->start_addr = (void*)(functions->size = 0);
		functions++;
		
	} while (functions->start_addr != 0);
}


void* Encryptor_DecryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
	u32    expanded_key[4];
	u32    key;
	u32    size;
	void*  func_addr;
	
	key = obfs_key;
	key -= (u32)&BSS + ENC_VAL_1;
	
	size = obfs_size;
	size -= (u32)&BSS + ENC_VAL_1;
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr = obfs_func_addr;
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndDecryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache();
	
	return func_addr;
}


// This function sucks. https://decomp.me/scratch/D8nhP
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
	
	func_addr = obfs_func_addr;
	
	key = obfs_key;
	key -= (u32)&BSS + ENC_VAL_1;;
	key += (u32)func_addr & 0x0000FFFF;
	
	size = obfs_size;
	size -= (u32)&BSS + ENC_VAL_1;;
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndEncryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache(func_addr, size);
	
	return key + ((u32)&BSS + ENC_VAL_1);
	
#else /* NONMATCHING */
	
	// push {r3, r4, r5, lr}
	asm {
		sub  sp, sp, #16
		ldr  r3, =BSS
		ldr  ip, =0x0000FFFF
		mov  r4, r0
		add  r0, r3, #ENC_VAL_1
		ldr  r5, =BSS
		sub  r4, r4, r0
		and  r0, r1, ip
		add  r4, r4, r0
		mov  r3, r2
		mov  r2, r1
		add  r5, r5, #ENC_VAL_1
		lsr  ip, r4, #24
		lsr  r1, r4, #16
		lsr  r0, r4, #8
		sub  r3, r3, r5
		orr  r1, r1, r4, lsl #16
		eor  r5, r4, r3
		eor  lr, r3, r1
		sub  r2, r2, #ENC_VAL_1
		orr  ip, ip, r4, lsl #8
		str  r5, [sp]
		eor  r5, r3, ip
		orr  r0, r0, r4, lsl #24
		eor  ip, r3, r0
		add  r0, sp, #0
		mov  r1, r2
		str  r5, [sp, #4]
		str  lr, [sp, #8]
		str  ip, [sp, #12]
		bl   RC4_InitAndEncryptInstructions
	}
	clearDataAndInstructionCache();
	asm {
		ldr  r0, =bss
		add  r0, r0, #0x1000
		add  r0, r4, r0
		add  sp, sp, #0x10
	}
	// pop {r3, r4, r5, pc}
	// .word BSS
	// .word 0x0000FFFF
	
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
	
	stmfd  sp!, {r0-r3}               // Push inner function arguments onto the stack to save them for after decryption.
	str    r10, [ip, #0x10]           // `r10` is saved to second storage space.
	mov    r10, ip                    // `r10` now used for the pointer to the data structure.
	str    lr, [r10]                  // `lr` (outer return address) saved to first storage space to return later.
	ldmib  r10, {r0-r2}               // Read function decryptor arguments from data structure (key, addr, size).
	bl     Encryptor_DecryptFunction  // Call function decryptor, which returns de-obfuscated function address.
	mov    ip, r0                     // Move returned address to `ip` to free up `r0`.
	ldmia  sp!, {r0-r3}               // Pop arguments to inner function (`r0`-`r3`) off the stack. Stack is now restored.
	blx    ip                         // Call inner function. `r0`-`r3` and `sp` are correct for proper arguments.
	stmdb  sp!, {r4}                  // `r4` about to be used as temporary register, preserve its current value on the stack.
	mov    r4, r0                     // Preserve the return from the inner function in `r4`, move it back to `r0` later.
	ldmib  r10, {r0-r2}               // Read function encryptor arguments from data structure (key, addr, size).
	bl     Encryptor_EncryptFunction  // Call function encryptor, which returns obfuscated new key.
	str    r0, [r10, #0x4]            // New key is stored back into data structure.
	mov    r0, r4                     // Return value from inner function is moved back to `r0` to return it.
	ldmia  sp!, {r4}                  // Original value of `r4` restored from the stack so we can properly return.
	ldr    lr, [r10]                  // Outer return address read back out from storage space into `lr`.
	str    sp, [r10]                  // Stack pointer overwrites storage space to hide its value (could be anything here?).
	ldr    r10, [r10, #0x10]          // `r10` restored from second storage space.
	bx     lr                         // Return to outer return address with return value of inner function.
}

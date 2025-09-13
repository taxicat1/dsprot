#include "encryptor.h"

#include "encoding_constants.h"
#include "bss.h"
#include "rc4.h"

#define ROTL(x, a)  ((a) == 0 ? (x) : (((x) << (a)) | ((x) >> (32 - (a)))))

void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes);


asm void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes) {
	// This function is an inlining and combination of DC_FlushRange and IC_InvalidateRange.
	// Both of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c
	
	add  r1, r1, r0
	mov  ip, #0
	bic  r0, r0, #31
	
@1:
	mcr  p15, 0, r0, c7, c5, 1
	mcr  p15, 0, ip, c7, c10, 4
	mcr  p15, 0, r0, c7, c14, 1
	
	add  r0, r0, #32
	cmp  r0, r1
	blt  @1
	
	bx   lr
}


u32 Encryptor_CategorizeInstruction(u32 instruction) {
	u8 upper_byte;
	
	upper_byte = (instruction >> 24) & 0xFF;
	
	if ((upper_byte & 0x0E) == 0x0A) {
		if ((upper_byte & 0xF0) == 0xF0) {
			return INS_TYPE_BLX;
		}
		
		if (upper_byte & 0x01) {
			return INS_TYPE_BL;
		} else {
			return INS_TYPE_B;
		}
	}
	
	return INS_TYPE_OTHER;
}


void Encryptor_DecodeFunctionTable(FuncInfo* functions) {
	u32   size;
	u32*  end_addr;
	u32   xorval;
	u32   bss_addr;
	u32*  addr;
	u32*  prevmem;
	
	bss_addr = (u32)&BSS;
	
	// This overwrites the instructions in the callee, erasing them
	prevmem = (u32*)functions - 3;
	// Must be in this compound assignment to match
	prevmem[0] = prevmem[1] = prevmem[2] = 0;
	
	do {
		addr = functions->start_addr - ENC_VAL_1;
		size = functions->size - bss_addr - ENC_VAL_1;
		
		end_addr = addr + (size / 4);
		
		xorval = ENC_XOR_START;
		
		for (; addr < end_addr; addr++) {
			switch (Encryptor_CategorizeInstruction(*addr)) {
				case INS_TYPE_BLX:
				case INS_TYPE_B:
					*addr = ((*addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) |
					        (((*addr & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF);
					
					xorval ^= *addr >> 24;
					xorval &= 0x00FFFFFF;
					break;
				
				case INS_TYPE_BL:
					// Link bit
					*addr ^= (ENC_OPCODE_1 << 24);
					// Fall through
				default:
					*addr ^= xorval;
					xorval ^= *addr;
					xorval ^= *addr >> 8;
					xorval &= 0x00FFFFFF;
			}
		}
		
		clearDataAndInstructionCache(functions->start_addr - ENC_VAL_1, size);
		functions->size = 0;
		functions->start_addr = NULL;
		functions++;
		
	} while (functions->start_addr != 0);
}


void* Encryptor_DecryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
	u32    expanded_key[4];
	u32    literal_obfs_offset;
	u32    key;
	u32    size;
	void*  func_addr;
	
	literal_obfs_offset = (u32)&BSS + ENC_VAL_1;
	
	key = obfs_key;
	key -= literal_obfs_offset;
	
	size = obfs_size;
	size -= literal_obfs_offset;
	
	expanded_key[0] = ROTL(key,  0) ^ size;
	expanded_key[1] = ROTL(key,  8) ^ size;
	expanded_key[2] = ROTL(key, 16) ^ size;
	expanded_key[3] = ROTL(key, 24) ^ size;
	
	func_addr = obfs_func_addr;
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndDecryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache(func_addr, size);
	
	return func_addr;
}


u32 Encryptor_EncryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
	u32    expanded_key[4];
	u32    literal_obfs_offset;
	u32    new_key;
	u32    size;
	void*  func_addr;
	
	literal_obfs_offset = (u32)&BSS + ENC_VAL_1;
	
	func_addr = obfs_func_addr;
	
	obfs_size = obfs_size - literal_obfs_offset;
	size = obfs_size;
	
	obfs_key = obfs_key - literal_obfs_offset + ((u32)func_addr >> 20);
	new_key = obfs_key;
	
	expanded_key[0] = ROTL(new_key,  0) ^ size;
	expanded_key[1] = ROTL(new_key,  8) ^ size;
	expanded_key[2] = ROTL(new_key, 16) ^ size;
	expanded_key[3] = ROTL(new_key, 24) ^ size;
	
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndEncryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache(func_addr, size);
	
	return new_key + literal_obfs_offset;
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

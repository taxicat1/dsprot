#include "encryptor.h"

#include "bss.h"
#include "encoding_constants.h"
#include "nitro_os.h"
#include "rc4.h"

#define ROTL(x, a)  ((a) == 0 ? (x) : (((x) << (a)) | ((x) >> (32 - (a)))))

static void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes);


static asm void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes) {
	/* This function is an inlining and combination of DC_FlushRange and IC_InvalidateRange. */
	/* Both of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c */
	
	mov  ip, #0
	add  r1, r1, r0
	bic  r0, r0, #HW_CACHE_LINE_SIZE - 1
	
@1:
	mcr  p15, 0, ip, c7, c10, 4  /* Wait write buffer empty */
	
	mcr  p15, 0, r0, c7, c14, 1  /* DC flush */
	mcr  p15, 0, r0, c7, c5, 1   /* IC invalidate */
	
	add  r0, r0, #HW_CACHE_LINE_SIZE
	cmp  r0, r1
	blt  @1
	
	bx   lr
}


u32 Encryptor_CategorizeInstruction(u32 instruction) {
	u8 opcode;
	
	opcode = instruction >> INS_OPCODE_SHIFT;
	
	// Branch instruction
	if ((opcode & 0x0E) == 0x0A) {
		// BLX immediate type
		if ((opcode & 0xF0) == 0xF0) {
			return INS_TYPE_BLXIMM;
		}
		
		// Link bit
		if (opcode & INS_OPCODE_LINKBIT) {
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
	
	if (functions == NULL || functions->obfs_addr == 0) {
		return;
	}
	
	bss_addr = (u32)&BSS;
	
	do {
		xorval = ENC_XOR_START;
		
		size = functions->obfs_size - bss_addr - ENC_VAL_1;
		
		if (functions->obfs_addr == 0) {
			return;
		}
		
		addr = (u32*)(functions->obfs_addr - ENC_VAL_1);
		end_addr = addr + (size / 4);
		
		for (; addr < end_addr; addr++) {
			switch (Encryptor_CategorizeInstruction(*addr)) {
				case INS_TYPE_BLXIMM:
				case INS_TYPE_B:
					{
						u32 opcode = (*addr & INS_OPCODE_MASK) ^ (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
						u32 operands = ((*addr & INS_OPERANDS_MASK) - ENC_VAL_2) & INS_OPERANDS_MASK;
						
						*addr = opcode | operands;
					}
					break;
				
				case INS_TYPE_BL:
					// Link bit
					*addr ^= (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
					// Fall through
				default:
					*addr ^= xorval;
					
					xorval <<= 1;
					xorval += *addr;
					xorval &= ENC_XOR_MASK;
					break;
			}
		}
		
		clearDataAndInstructionCache((void*)(functions->obfs_addr - ENC_VAL_1), size);
		functions++;
	} while (functions->obfs_addr != 0);
}


void* Encryptor_DecryptFunction(u32 key, u32 func_addr, u32 size) {
	u32    expanded_key[4];
	void*  func_ptr;
	
	// Deobfuscate arguments 
	size -= (u32)&BSS + ENC_VAL_1;
	
	key -= (u32)&BSS + ENC_VAL_1;
	
	func_ptr = (void*)func_addr;
	func_ptr -= ENC_VAL_1;
	
	// Derive RC4 key
	expanded_key[0] = ROTL(key,  0) ^ size;
	expanded_key[1] = ROTL(key,  8) ^ size;
	expanded_key[2] = ROTL(key, 16) ^ size;
	expanded_key[3] = ROTL(key, 24) ^ size;
	
	RC4_InitAndDecryptInstructions(&expanded_key[0], func_ptr, func_ptr, size);
	clearDataAndInstructionCache(func_ptr, size);
	
	return func_ptr;
}


u32 Encryptor_EncryptFunction(u32 key, u32 func_addr, u32 size) {
	u32    expanded_key[4];
	void*  func_ptr;
	
	// Deobfuscate arguments and change key
	size -= (u32)&BSS + ENC_VAL_1;
	
	key -= (u32)&BSS + ENC_VAL_1;
	key += func_addr >> 20;
	
	func_ptr = (void*)func_addr;
	func_ptr -= ENC_VAL_1;
	
	// Derive RC4 key
	expanded_key[0] = ROTL(key,  0) ^ size;
	expanded_key[1] = ROTL(key,  8) ^ size;
	expanded_key[2] = ROTL(key, 16) ^ size;
	expanded_key[3] = ROTL(key, 24) ^ size;
	
	RC4_InitAndEncryptInstructions(&expanded_key[0], func_ptr, func_ptr, size);
	clearDataAndInstructionCache(func_ptr, size);
	
	// Re-obfuscate key
	key += (u32)&BSS + ENC_VAL_1;
	
	return key;
}

#include "encryptor.h"

#include "encoding_constants.h"
#include "bss.h"
#include "rc4.h"

#define ROTL(x, a)  ((a) == 0 ? (x) : (((x) << (a)) | ((x) >> (32 - (a)))))

void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes);


asm void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes) {
	// This function is an inlining and combination of DC_FlushRange and IC_InvalidateRange.
	// Both of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c
	
	mov  ip, #0
	add  r1, r1, r0
	bic  r0, r0, #31
	
@1:
	mcr  p15, 0, ip, c7, c10, 4
	mcr  p15, 0, r0, c7, c14, 1
	mcr  p15, 0, r0, c7, c5, 1
	
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
			return INS_TYPE_BLXIMM;
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
	
	if (functions == NULL || functions->start_addr == NULL) {
		return;
	}
	
	bss_addr = (u32)&BSS;
	
	do {
		xorval = ENC_XOR_START;
		
		size = functions->size - bss_addr - ENC_VAL_1;
		
		if (functions->start_addr == NULL) {
			return;
		}
		
		addr = functions->start_addr - ENC_VAL_1;
		end_addr = addr + (size / 4);
		
		for (; addr < end_addr; addr++) {
			switch (Encryptor_CategorizeInstruction(*addr)) {
				case INS_TYPE_BLXIMM:
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
					break;
			}
		}
		
		clearDataAndInstructionCache(functions->start_addr - ENC_VAL_1, size);
		functions++;
	} while (functions->start_addr != NULL);
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

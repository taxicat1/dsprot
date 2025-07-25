#include "encryptor.h"

#include "encoding_constants.h"
#include "bss.h"
#include "rc4.h"

void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes);


asm void clearDataAndInstructionCache(register void* start_addr, register u32 num_bytes) {
	// This function is an inlining and combination of DC_FlushRange and IC_InvalidateRange.
	// Both of these functions are implemented as asm functions in Nitro SDK: build/libraries/os/ARM9/src/os_cache.c
	
	add  r1, r1, r0
	mov  ip, #0
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
	u32  size;
	u32  end_addr;
	u32  xorval;
	u32  bss_addr;
	u32  addr;
	
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
		
		addr = (u32)(functions->start_addr - ENC_VAL_1);
		end_addr = addr + (size & ~3);
		
		for (; addr < end_addr; addr += 4) {
			switch (Encryptor_CategorizeInstruction(*(u32*)addr)) {
				case 1:
				case 3:
					*(u32*)addr = ((*(u32*)addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) |
					              (((*(u32*)addr & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF);
					
					xorval ^= *(u32*)addr >> 24;
					xorval &= 0x00FFFFFF;
					break;
				
				case 2:
					*(u32*)addr ^= (ENC_OPCODE_1 << 24);
					// Fall through
				default:
					*(u32*)addr ^= xorval;
					
					xorval ^= *(u32*)addr;
					xorval ^= *(u32*)addr >> 8;
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
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr = obfs_func_addr;
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndDecryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache(func_addr, size);
	
	return func_addr;
}


// This function sucks. https://decomp.me/scratch/I41ac
// 
// This *should* be identical to `Encryptor_DecryptFunction` with the extra step
// of modifying the key, and calling the encryption function instead of decryption.
// But for some reason, all the instructions are in a totally different order.
// You can match the instruction order with some weird dummy lines, but then
// the registers just never line up. Something very stupid is happening.
// I suspect there is some sort of obfuscation that is being partially 
// optimized out, leaving behind only strange register patterns.
u32 Encryptor_EncryptFunction(u32 obfs_key, void* obfs_func_addr, u32 obfs_size) {
#ifdef NONMATCHING
	
	u32    expanded_key[4];
	u32    literal_obfs_offset;
	u32    key;
	u32    size;
	void*  func_addr;
	
	literal_obfs_offset = (u32)&BSS + ENC_VAL_1;
	
	func_addr = obfs_func_addr;
	
	key = obfs_key;
	key -= literal_obfs_offset;
	key += (u32)func_addr >> 20;
	
	size = obfs_size;
	size -= literal_obfs_offset;
	
	expanded_key[0] = key ^ size;
	expanded_key[1] = ((key <<  8) | (key >> 24)) ^ size;
	expanded_key[2] = ((key << 16) | (key >> 16)) ^ size;
	expanded_key[3] = ((key << 24) | (key >>  8)) ^ size;
	
	func_addr -= ENC_VAL_1;
	
	RC4_InitAndEncryptInstructions(&expanded_key[0], func_addr, func_addr, size);
	clearDataAndInstructionCache(func_addr, size);
	
	return key + literal_obfs_offset;
	
#else /* NONMATCHING */
	
	// push {r3, r4, r5, r6, r7, lr}
	asm {
		sub sp, sp, #16
	}
	u32 bss_addr = (u32)&BSS; // ldr r3, [pc, #124]
	asm {
		mov r7, r0
		add r4, bss_addr, #ENC_VAL_1
		mov r6, r1
		sub r0, r7, r4
		add r7, r0, r6, lsr #20
		mov r5, r2
		mov r2, r7, lsr #24
		sub r5, r5, r4
		mov r0, r7, lsr #8
		orr r3, r2, r7, lsl #8
		mov r1, r7, lsr #16
		orr r2, r1, r7, lsl #16
		eor lr, r5, r3
		eor ip, r7, r5
		eor r3, r5, r2
		sub r1, r6, #ENC_VAL_1
		str r3, [sp, #8]
		orr r0, r0, r7, lsl #24
		str ip, [sp]
		eor ip, r5, r0
		add r0, sp, #0
		mov r2, r1
		mov r3, r5
		str lr, [sp, #4]
		str ip, [sp, #12]
		bl RC4_InitAndEncryptInstructions
		mov r1, r5
		sub r0, r6, #ENC_VAL_1
		bl clearDataAndInstructionCache
		add r0, r7, r4
		add sp, sp, #16
	}
	// pop {r3, r4, r5, r6, r7, pc}
	// .word BSS
	
#endif /* NONMATCHING */
}

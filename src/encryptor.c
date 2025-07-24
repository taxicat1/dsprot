#include "encryptor.h"

#include "bss.h"
#include "rc4.h"
#include "encoding_constants.h"

static void clearDataAndInstructionCache(void* start_addr, u32 num_bytes);


static void clearDataAndInstructionCache(void* start_addr, u32 num_bytes) {
	DC_FlushRange(start_addr, num_bytes);
	IC_InvalidateRange(start_addr, num_bytes);
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
	u32  addr;
	u32  end_addr;
	u32  a, b, c, d;
	
	if (functions == NULL) {
		return;
	}
	
	for (; functions->start_addr != NULL; functions++) {
		size = functions->size - (u32)&BSS - ENC_VAL_1;
		
		addr = (u32)functions->start_addr;
		if (addr == 0) {
			break;
		}
		
		// Cast required to match. Likely a macro here to remove the obfuscation
		addr = (u32)addr - ENC_VAL_1;
		
		end_addr = addr + (size & ~3);
		for (; addr < end_addr; addr += 4) {
			switch (Encryptor_CategorizeInstruction(*(u32*)addr)) {
				case 1:
				case 2:
					*(u32*)addr = ((*(u32*)addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) |
					              (((*(u32*)addr & 0x00FFFFFF) - ENC_VAL_1) & 0x00FFFFFF);
					break;
				
				case 3:
					*(u32*)addr = ((*(u32*)addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) |
					              (((*(u32*)addr & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF);
					break;
				
				default:
					a = ((u8*)addr)[0] ^ ENC_BYTE_A;
					b = ((u8*)addr)[1] ^ ENC_BYTE_B;
					c = ((u8*)addr)[2] ^ ENC_BYTE_C;
					d = ((u8*)addr)[3] ^ ENC_OPCODE_2;
					*(u32*)addr = a | (b << 8) | (c << 16) | (d << 24);
					break;
			}
		}
		
		clearDataAndInstructionCache(functions->start_addr - ENC_VAL_1, size);
	}
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

#include "rc4.h"

#include "encoding_constants.h"
#include "encryptor.h"


void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len) {
	u8    tmp1;
	u8    tmp2;
	int   i;
	int   Si;
	int   Ki;
	u32*  s_start;
	u32*  s_end;
	u32   x;
	u32   y;
	
	// Must be like this to match
	Si = Ki = 0;
	
	ctx->x = 0xAA;
	ctx->i = 0;
	ctx->j = 0;
	
	// Optimized way to init the RC4 state 4 bytes at a time
	s_start = (u32*)&ctx->S[0];
	s_end = (u32*)&ctx->S[256];
	x = 0x03020100;
	y = 0x04040404;
	do {
		*s_start++ = x;
		x += y;
	} while(s_start < s_end);
	
	// Modification to RC4: i = 255 -> 0, instead of 0 -> 255
	for (i = 255; i >= 0; i--) {
		tmp1 = ctx->S[i];
		Si = (Si + ((u8*)key)[Ki] + tmp1) & 0xFF;
		tmp2 = ctx->S[Si];
		
		ctx->S[Si] = tmp1;
		ctx->S[i] = tmp2;
		
		Ki++;
		if (Ki >= key_len) {
			Ki = 0;
		}
	}
}


u8 RC4_Byte(RC4_Ctx* ctx) {
	u8   i;
	u8*  S;
	u8   jval;
	u8   ival;
	u32  j;
	u8   out_idx;
	
	// Modification to RC4: i and j both increased by new variable x
	i = ctx->i + 1 + ctx->x;
	j = ctx->x;
	
	S = ctx->S;
	
	ival = S[i];
	j += ival + ctx->j;
	jval = S[j & 0xFF];
	
	ctx->i = i;
	ctx->j = j & 0xFF;
	
	S[j & 0xFF] = ival;
	S[i] = jval;
	
	out_idx = ival + jval;
	return ctx->S[out_idx];
}


u32 RC4_InitSBox(u8* sbox) {
	// S[i] = i ^ 0x3F (optimized to write 4 bytes at a time)
	u32   x;
	u32   y;
	u32*  sbox_start;
	u32*  sbox_end;
	
	x = 0x03020100;
	y = 0x04040404;
	sbox_start = (u32*)&sbox[0];
	sbox_end = (u32*)&sbox[256];
	do {
		*sbox_start++ = x ^ 0x3F3F3F3F;
		x += y;
	} while(sbox_start < sbox_end);
	
	return 0;
}


u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u8   sbox[256];
	u8*  src_bytes;
	u8*  dst_bytes;
	u32  idx;
	u32  ins_word;
	u8   ins_byte;
	u8   rand_byte;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	RC4_InitSBox(&sbox[0]);
	
	for (idx = 0; idx < size; idx += 4) {
		ins_word = *(u32*)(src_bytes + idx);
		switch (Encryptor_CategorizeInstruction(ins_word)) {
			case 1:
			case 2:
				*(u32*)(dst + idx) = *(u32*)(src_bytes + idx);
				*(u32*)(dst + idx) = ((*(u32*)(dst + idx) & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) | 
				                     (((*(u32*)(dst + idx) & 0x00FFFFFF) + ENC_VAL_2) & 0x00FFFFFF);
				break;
			
			case 3:
				// Error correction: this should never happen, should be a type-0 instruction
				*(u32*)(src_bytes + idx) ^= (ENC_OPCODE_1 << 24);
				// Fall through
			default:
				// First byte
				rand_byte = RC4_Byte(ctx);
				ins_byte = src_bytes[idx];
				ins_byte ^= rand_byte;
				ctx->x = ins_byte;
				dst_bytes[idx] = ins_byte;
				
				// Second byte
				rand_byte = RC4_Byte(ctx);
				ins_byte = src_bytes[idx+1];
				ins_byte ^= rand_byte;
				ctx->x = ins_byte;
				dst_bytes[idx+1] = ins_byte;
				
				// Third byte
				dst_bytes[idx+2] = sbox[ src_bytes[idx+2] ];
				
				// Fourth byte
				dst_bytes[idx+3] = src_bytes[idx+3];
				break;
		}
	}
	
	return 0;
}


// For some reason this inline is required to match
static inline u8 getInsByte(u8 *ins_byte_ptr, u32 offset, u32 byte);
static inline u8 getInsByte(u8 *ins_byte_ptr, u32 offset, u32 byte) {
	return ins_byte_ptr[offset + byte];
}


u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u8   sbox[256];
	u8*  src_bytes;
	u8*  dst_bytes;
	u32  idx;
	u32  ins_word;
	u8   ins_byte;
	u8   rand_byte;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	RC4_InitSBox(&sbox[0]);
	
	for (idx = 0; idx < size; idx += 4) {
		ins_word = *(u32*)(src_bytes + idx);
		switch (Encryptor_CategorizeInstruction(ins_word)) {
			case 1:
			case 3:
				*(u32*)(dst + idx) = ((ins_word & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) | 
				                     (((ins_word & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF);
				
				break;
			
			case 2:
				// Error correction: this should never happen, should be a type-0 instruction
				*(u32*)(src_bytes + idx) ^= (ENC_OPCODE_1 << 24);
				// Fall through
			default:
				// First byte
				ins_byte = src_bytes[idx];
				rand_byte = RC4_Byte(ctx);
				ctx->x = ins_byte;
				dst_bytes[idx] = ins_byte ^ rand_byte;
				
				// Second byte
				ins_byte = getInsByte(src_bytes, idx, 1);
				rand_byte = RC4_Byte(ctx);
				ctx->x = ins_byte;
				dst_bytes[idx+1] = ins_byte ^ rand_byte;
				
				// Third byte
				dst_bytes[idx+2] = sbox[ src_bytes[idx+2] ];
				
				// Fourth byte
				dst_bytes[idx+3] = src_bytes[idx+3];
				break;
		}
	}
	
	return 0;
}


u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	RC4_Init(&ctx, key, 16);
	// Must coerce output to -1 or 0 like this to match
	return RC4_EncryptInstructions(&ctx, dst, src, size) == -1 ? -1 : 0;
}


u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	RC4_Init(&ctx, key, 16);
	// Must coerce output to -1 or 0 like this to match
	return RC4_DecryptInstructions(&ctx, dst, src, size) == -1 ? -1 : 0;
}

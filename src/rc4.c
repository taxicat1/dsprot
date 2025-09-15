#include "rc4.h"

#include "encoding_constants.h"
#include "encryptor.h"

#define RC4_KEY_SIZE  (16)

typedef struct {
	int  x;
	int  i;
	int  j;
	u8   S[256];
} RC4_Ctx;

u32 RC4_CategorizeInstruction(u32 instruction);
void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len);
u8 RC4_Byte(RC4_Ctx* ctx);
u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size);
u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size);

// These variables must be declared in this exact order to maintain rodata layout.
// Must also be compiled with `-ipa file`
//
//  [5] .rodata
//      00  Proxy_RC4_InitAndDecryptInstructions
//  [7] .rodata
//      00  Proxy_RC4_InitAndEncryptInstructions
//  [9] .rodata
//      00  Proxy_RC4_CategorizeInstruction
//      04  Proxy_RC4_EncryptInstructions
//      08  Proxy_RC4_DecryptInstructions
//      0C  Proxy_RC4_Byte
//      10  Proxy_RC4_Init

const u32 Proxy_RC4_Byte                       = (u32)&RC4_Byte[ENC_VAL_1];
const u32 Proxy_RC4_DecryptInstructions        = (u32)&RC4_DecryptInstructions[ENC_VAL_1];
const u32 Proxy_RC4_EncryptInstructions        = (u32)&RC4_EncryptInstructions[ENC_VAL_1];
const u32 Proxy_RC4_CategorizeInstruction      = (u32)&RC4_CategorizeInstruction[ENC_VAL_1];
const u32 Proxy_RC4_InitAndEncryptInstructions = (u32)&RC4_InitAndEncryptInstructions[ENC_VAL_1];
const u32 Proxy_RC4_InitAndDecryptInstructions = (u32)&RC4_InitAndDecryptInstructions[ENC_VAL_1];
const u32 Proxy_RC4_Init                       = (u32)&RC4_Init[ENC_VAL_1];

typedef u8  (*FuncType_RC4_Byte)(RC4_Ctx*);
typedef u32 (*FuncType_RC4_EncryptInstructions)(RC4_Ctx*, void*, void*, u32);
typedef u32 (*FuncType_RC4_DecryptInstructions)(RC4_Ctx*, void*, void*, u32);
typedef u32 (*FuncType_RC4_CategorizeInstruction)(u32);
typedef u32 (*FuncType_RC4_Init)(RC4_Ctx*, void*, u32);

enum {
	INS_TYPE_OTHER = 0,
	INS_TYPE_BLXIMM,
	INS_TYPE_BL,
	INS_TYPE_B
};


static u32 RC4_CategorizeInstruction(u32 instruction) {
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
	
	Ki = 0;
	Si = 0;
	
	ctx->x = ENC_RC4_X_START;
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
	} while (s_start < s_end);
	
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
	u8  i;
	u8  ival;
	u8  j;
	u8  jval;
	
	// Modification to RC4: i and j both increased by new variable x
	i = ctx->i + 1 + ctx->x;
	ival = ctx->S[i];
	j = ival + ctx->j + ctx->x;
	jval = ctx->S[j];
	
	ctx->i = i;
	ctx->j = j;
	
	ctx->S[j] = ival;
	ctx->S[i] = jval;
	
	return ctx->S[(ival + jval) & 0xFF];
}


u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u32                idx;
	u32                ins_word;
	u8*                src_bytes;
	u8*                dst_bytes;
	u32                rc4_byte_addr;
	FuncType_RC4_Byte  rc4_byte;
	u8                 ins_byte;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	for (idx = 0; idx < size; idx += 4) {
		ins_word = *(u32*)(src_bytes + idx);
		
		switch (((FuncType_RC4_CategorizeInstruction)(Proxy_RC4_CategorizeInstruction - ENC_VAL_1))(ins_word)) {
			case INS_TYPE_BLXIMM:
			case INS_TYPE_BL:
				{
					u32 upper, lower;
					u32* src_addr = (u32*)(src_bytes + idx);
					u32* dst_addr = (u32*)(dst_bytes + idx);
					
					*dst_addr = *src_addr;
					
					upper = ((*dst_addr & 0xFF000000) ^ (ENC_OPCODE_1 << 24));
					lower = (((*dst_addr & 0x00FFFFFF) + ENC_VAL_2) & 0x00FFFFFF);
					
					ctx->x += upper >> 24;
					
					*dst_addr = upper | lower;
				}
				break;
			
			case INS_TYPE_B:
				// Link bit
				*(u32*)(src_bytes + idx) ^= (ENC_OPCODE_1 << 24);
				// Fall through
			default:
				rc4_byte_addr = Proxy_RC4_Byte;
				rc4_byte_addr -= ENC_VAL_1;
				rc4_byte = (FuncType_RC4_Byte)rc4_byte_addr;
				
				// First byte
				{
					int rand_byte = rc4_byte(ctx);
					int ins_byte = src_bytes[idx];
					ins_byte ^= rand_byte;
					ctx->x = ins_byte;
					dst_bytes[idx] = ins_byte;
				}
				
				// Second byte
				{
					int rand_byte = rc4_byte(ctx);
					int ins_byte = src_bytes[idx+1];
					ins_byte ^= rand_byte;
					ctx->x = ins_byte;
					dst_bytes[idx+1] = ins_byte;
				}
				
				// Third byte
				{
					int rand_byte = rc4_byte(ctx);
					int ins_byte = src_bytes[idx+2];
					ins_byte ^= rand_byte;
					ctx->x = ins_byte;
					dst_bytes[idx+2] = ins_byte;
				}
				
				// Fourth byte (temporary assignment is required to match)
				ins_byte = src_bytes[idx+3];
				dst_bytes[idx+3] = ins_byte;
				
				// Update `x`
				ctx->x -= ins_byte;
				break;
		}
	}
	
	return 0;
}


u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u32                idx;
	u32                ins_word;
	u32                rc4_byte_addr;
	FuncType_RC4_Byte  rc4_byte;
	u8                 ins_byte;
	u8*                src_bytes;
	u8*                dst_bytes;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	for (idx = 0; idx < size; idx += 4) {
		ins_word = *(u32*)(src_bytes + idx);
		
		switch (((FuncType_RC4_CategorizeInstruction)(Proxy_RC4_CategorizeInstruction - ENC_VAL_1))(ins_word)) {
			case INS_TYPE_BLXIMM:
			case INS_TYPE_B:
				{
					u32* dst_addr = (u32*)(dst_bytes + idx);
					ctx->x += ins_word >> 24; 
					*dst_addr = ((ins_word & 0xFF000000) ^ (ENC_OPCODE_1 << 24)) |
					            (((ins_word & 0x00FFFFFF) - ENC_VAL_2) & 0x00FFFFFF);
				}
				break;
			
			case INS_TYPE_BL:
				rc4_byte_addr = Proxy_RC4_Byte;
				rc4_byte_addr -= ENC_VAL_1;
				
				// First byte
				{
					int ins_byte = src_bytes[idx];
					int rand_byte = ((FuncType_RC4_Byte)rc4_byte_addr)(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx] = ins_byte ^ rand_byte;
				}
				
				// Second byte
				{
					ins_byte = src_bytes[idx+1];
					int rand_byte = ((FuncType_RC4_Byte)rc4_byte_addr)(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx+1] = ins_byte ^ rand_byte;
				}
				
				// Third byte
				{
					ins_byte = src_bytes[idx+2];
					int rand_byte = ((FuncType_RC4_Byte)rc4_byte_addr)(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx+2] = ins_byte ^ rand_byte;
				}
				
				// Fourth byte
				dst_bytes[idx+3] = src_bytes[idx+3];
				
				// Update `x`
				ctx->x -= src_bytes[idx+3];
				
				// Link bit
				*(u32*)(src_bytes + idx) ^= (ENC_OPCODE_1 << 24);
				break;
			
			default:
				rc4_byte_addr = Proxy_RC4_Byte;
				rc4_byte_addr -= ENC_VAL_1;
				rc4_byte = (FuncType_RC4_Byte)rc4_byte_addr;
				
				// First byte
				{
					int ins_byte = src_bytes[idx];
					int rand_byte = rc4_byte(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx] = ins_byte ^ rand_byte;
				}
				
				// Second byte
				{
					int ins_byte = src_bytes[idx+1];
					int rand_byte = rc4_byte(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx+1] = ins_byte ^ rand_byte;
				}
				
				// Third byte
				{
					ins_byte = src_bytes[idx+2];
					int rand_byte = rc4_byte(ctx);
					ctx->x = ins_byte;
					dst_bytes[idx+2] = ins_byte ^ rand_byte;
				}
				
				// Update `x`
				ctx->x -= src_bytes[idx+3];
				
				// Fourth byte
				dst_bytes[idx+3] = src_bytes[idx+3];
				break;
		}
	}
	
	return 0;
}


u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx  ctx;
	u32      rc4_init;
	u32      rc4_encrypt;
	u32      enc_ret;
	
	rc4_init = Proxy_RC4_Init;
	rc4_init -= ENC_VAL_1;
	((FuncType_RC4_Init)rc4_init)(&ctx, key, RC4_KEY_SIZE);
	
	rc4_encrypt = Proxy_RC4_EncryptInstructions;
	rc4_encrypt -= ENC_VAL_1;
	enc_ret = ((FuncType_RC4_EncryptInstructions)rc4_encrypt)(&ctx, dst, src, size);
	
	// Must coerce return to -1 or 0
	return enc_ret == -1 ? -1 : 0;
}


u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx  ctx;
	u32      rc4_init;
	u32      rc4_encrypt;
	u32      enc_ret;
	
	rc4_init = Proxy_RC4_Init;
	rc4_init -= ENC_VAL_1;
	((FuncType_RC4_Init)rc4_init)(&ctx, key, RC4_KEY_SIZE);
	
	rc4_encrypt = Proxy_RC4_DecryptInstructions;
	rc4_encrypt -= ENC_VAL_1;
	enc_ret = ((FuncType_RC4_DecryptInstructions)rc4_encrypt)(&ctx, dst, src, size);
	
	// Must coerce return to -1 or 0
	return enc_ret == -1 ? -1 : 0;
}

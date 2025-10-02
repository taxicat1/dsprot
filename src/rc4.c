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

// Functions to be encoded (cannot be static)
void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len);
u8 RC4_Byte(RC4_Ctx* ctx);
u32 RC4_InitSBox(u8* sbox);
u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);


void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len) {
	u8    tmp1;
	u8    tmp2;
	int   i;
	u8    Si;
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
		Si = Si + ((u8*)key)[Ki] + tmp1;
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


static inline void RC4_EncryptByte(RC4_Ctx* ctx, u8* src, u8* dst) {
	int encrypted_byte;
	encrypted_byte = RC4_Byte(ctx) ^ *src;
	ctx->x = encrypted_byte;
	*dst = encrypted_byte;
}


static inline void RC4_DecryptByte(RC4_Ctx* ctx, u8* src, u8* dst) {
	int encrypted_byte;
	encrypted_byte = RC4_Byte(ctx) ^ *src;
	ctx->x = *src;
	*dst = encrypted_byte;
}


u32 RC4_InitSBox(u8* sbox) {
	// S[i] = i ^ 0xFF (optimized to write 4 bytes at a time)
	u32   x;
	u32   y;
	u32*  sbox_start;
	u32*  sbox_end;
	
	x = 0x03020100;
	y = 0x04040404;
	sbox_start = (u32*)&sbox[0];
	sbox_end = (u32*)&sbox[256];
	do {
		*sbox_start++ = x ^ ((ENC_SBOX_XOR << 24) | (ENC_SBOX_XOR << 16) | (ENC_SBOX_XOR << 8) | ENC_SBOX_XOR);
		x += y;
	} while (sbox_start < sbox_end);
	
	return 0;
}


u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u8   sbox[256];
	u32  offset;
	u32  ins_word;
	u8*  src_bytes;
	u8*  dst_bytes;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	RC4_InitSBox(&sbox[0]);
	
	for (offset = 0; offset < size; offset += 4) {
		ins_word = *(u32*)(src_bytes + offset);
		
		switch (Encryptor_CategorizeInstruction(ins_word)) {
			case INS_TYPE_BLXIMM:
			case INS_TYPE_BL:
				{
					u32  opcode;
					u32  operands;
					u32* src_addr = (u32*)(src_bytes + offset);
					u32* dst_addr = (u32*)(dst_bytes + offset);
					
					*dst_addr = *src_addr;
					
					opcode = (*dst_addr & INS_OPCODE_MASK) ^ (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
					operands = ((*dst_addr & INS_OPERANDS_MASK) + ENC_VAL_2) & INS_OPERANDS_MASK;
					
					ctx->x += (opcode >> INS_OPCODE_SHIFT);
					
					*dst_addr = opcode | operands;
				}
				break;
			
			case INS_TYPE_B:
				// Link bit
				*(u32*)(src_bytes + offset) ^= (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
				// Fall through
			default:
				// First two bytes
				RC4_EncryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_EncryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				
				// Third byte
				dst_bytes[offset + 2] = sbox[ src_bytes[offset + 2] ];
				
				// Fourth byte
				dst_bytes[offset + 3] = src_bytes[offset + 3];
				
				// Update `x`
				ctx->x = (ctx->x * dst_bytes[offset + 2]) - dst_bytes[offset + 3];
				break;
		}
	}
	
	return 0;
}


u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u8   sbox[256];
	u32  offset;
	u32  ins_word;
	u8*  src_bytes;
	u8*  dst_bytes;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	RC4_InitSBox(&sbox[0]);
	
	for (offset = 0; offset < size; offset += 4) {
		ins_word = *(u32*)(src_bytes + offset);
		
		switch (Encryptor_CategorizeInstruction(ins_word)) {
			case INS_TYPE_BLXIMM:
			case INS_TYPE_B:
				{
					u32  opcode;
					u32  operands;
					u32* dst_addr = (u32*)(dst_bytes + offset);
					
					ctx->x += (ins_word >> INS_OPCODE_SHIFT);
					
					opcode = (ins_word & INS_OPCODE_MASK) ^ (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
					operands = ((ins_word & INS_OPERANDS_MASK) - ENC_VAL_2) & INS_OPERANDS_MASK;
					
					*dst_addr = opcode | operands;
				}
				break;
			
			case INS_TYPE_BL:
				// First two bytes
				RC4_DecryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_DecryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				
				// Update `x`
				ctx->x = (src_bytes[offset + 2] * ctx->x) - src_bytes[offset + 3];
				
				// Third byte
				dst_bytes[offset + 2] = sbox[ src_bytes[offset + 2] ];
				
				// Fourth byte
				dst_bytes[offset + 3] = src_bytes[offset + 3];
				
				// Link bit
				*(u32*)(src_bytes + offset) ^= (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
				break;
			
			default:
				// First two bytes
				RC4_DecryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_DecryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				
				// Update `x`
				ctx->x = (src_bytes[offset + 2] * ctx->x) - src_bytes[offset + 3];
				
				// Third byte
				dst_bytes[offset + 2] = sbox[ src_bytes[offset + 2] ];
				
				// Fourth byte
				dst_bytes[offset + 3] = src_bytes[offset + 3];
				break;
		}
	}
	
	return 0;
}


u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	RC4_Init(&ctx, key, RC4_KEY_SIZE);
	// Must coerce output to -1 or 0 like this to match
	return RC4_EncryptInstructions(&ctx, dst, src, size) == -1 ? -1 : 0;
}


u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	RC4_Init(&ctx, key, RC4_KEY_SIZE);
	// Must coerce output to -1 or 0 like this to match
	return RC4_DecryptInstructions(&ctx, dst, src, size) == -1 ? -1 : 0;
}

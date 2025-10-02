#include "rc4.h"

#include "encoding_constants.h"
#include "encryptor.h"
#include "proxy_func.h"

#define RC4_KEY_SIZE  (16)

typedef struct {
	int  x;
	int  i;
	int  j;
	u8   S[256];
} RC4_Ctx;

// Functions to be encoded (cannot be static)
u32 RC4_CategorizeInstruction(u32 instruction);
void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len);
u8 RC4_Byte(RC4_Ctx* ctx);
u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size);
u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size);

typedef u8  (*FuncType_RC4_Byte)(RC4_Ctx*);
typedef u32 (*FuncType_RC4_EncryptInstructions)(RC4_Ctx*, void*, void*, u32);
typedef u32 (*FuncType_RC4_DecryptInstructions)(RC4_Ctx*, void*, void*, u32);
typedef u32 (*FuncType_RC4_CategorizeInstruction)(u32);
typedef u32 (*FuncType_RC4_Init)(RC4_Ctx*, void*, u32);

// These variables must be declared in this exact order to maintain rodata layout.
// Must also be compiled with `-ipa file`
// 
//  [5] .rodata
//      00  Proxy_RC4_InitAndEncryptInstructions
//  [7] .rodata
//      00  Proxy_RC4_CategorizeInstruction
//      04  Proxy_RC4_EncryptInstructions
//      08  Proxy_RC4_DecryptInstructions
//      0C  Proxy_RC4_Byte
//      10  Proxy_RC4_Init
//  [9] .rodata
//      00  Proxy_RC4_InitAndDecryptInstructions
const u32 Proxy_RC4_InitAndDecryptInstructions = ADDR_PLUS_ADDEND(RC4_InitAndDecryptInstructions, ENC_VAL_1);
const u32 Proxy_RC4_Byte                       = ADDR_PLUS_ADDEND(RC4_Byte, ENC_VAL_1);
const u32 Proxy_RC4_DecryptInstructions        = ADDR_PLUS_ADDEND(RC4_DecryptInstructions, ENC_VAL_1);
const u32 Proxy_RC4_EncryptInstructions        = ADDR_PLUS_ADDEND(RC4_EncryptInstructions, ENC_VAL_1);
const u32 Proxy_RC4_CategorizeInstruction      = ADDR_PLUS_ADDEND(RC4_CategorizeInstruction, ENC_VAL_1);
const u32 Proxy_RC4_InitAndEncryptInstructions = ADDR_PLUS_ADDEND(RC4_InitAndEncryptInstructions, ENC_VAL_1);
const u32 Proxy_RC4_Init                       = ADDR_PLUS_ADDEND(RC4_Init, ENC_VAL_1);

enum {
	INS_TYPE_OTHER = 0,
	INS_TYPE_BLXIMM,
	INS_TYPE_BL,
	INS_TYPE_B
};


u32 RC4_CategorizeInstruction(u32 instruction) {
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
	encrypted_byte = PROXY_FUNC(RC4_Byte)(ctx) ^ *src;
	ctx->x = encrypted_byte;
	*dst = encrypted_byte;
}


static inline void RC4_DecryptByte(RC4_Ctx* ctx, u8* src, u8* dst) {
	int encrypted_byte;
	encrypted_byte = PROXY_FUNC(RC4_Byte)(ctx) ^ *src;
	ctx->x = *src;
	*dst = encrypted_byte;
}


u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u32  offset;
	u32  ins_word;
	u8*  src_bytes;
	u8*  dst_bytes;
	u8   prev_opcode;
	
	prev_opcode = 0x00;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	for (offset = 0; offset < size; offset += 4) {
		ins_word = *(u32*)(src_bytes + offset);
		
		switch (PROXY_FUNC(RC4_CategorizeInstruction)(ins_word)) {
			case INS_TYPE_BLXIMM:
				// Link bit
				src_bytes[offset + 3] ^= INS_OPCODE_LINKBIT;
				// Fall through
			case INS_TYPE_BL:
				{
					u32  opcode;
					u32  operands;
					u32* src_addr = (u32*)(src_bytes + offset);
					u32* dst_addr = (u32*)(dst_bytes + offset);
					
					*dst_addr = *src_addr;
					
					opcode = (*dst_addr & INS_OPCODE_MASK) ^ (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
					operands = ((*dst_addr & INS_OPERANDS_MASK) + ENC_VAL_2) & INS_OPERANDS_MASK;
					
					*dst_addr = opcode | operands;
				}
				break;
			
			case INS_TYPE_B:
				// Link bit
				*(u32*)(src_bytes + offset) ^= (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
				// Fall through
			default:
				// First three bytes
				RC4_EncryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_EncryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				RC4_EncryptByte(ctx, src_bytes + offset + 2, dst_bytes + offset + 2);
				break;
		}
		
		// Fourth byte (opcode) encoded separately
		dst_bytes[offset + 3] = src_bytes[offset + 3] ^ prev_opcode;
		
		prev_opcode = dst_bytes[offset + 3];
		
		// Update `x`
		ctx->x -= prev_opcode;
	}
	
	return 0;
}


u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u32  offset;
	u8   curr_opcode;
	u8   prev_opcode;
	u32  ins_word;
	u8*  src_bytes;
	u8*  dst_bytes;
	
	prev_opcode = 0x00;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	for (offset = 0; offset < size; offset += 4) {
		// Decode opcode first
		curr_opcode = src_bytes[offset + 3];
		src_bytes[offset + 3] ^= prev_opcode;
		prev_opcode = curr_opcode;
		
		ins_word = *(u32*)(src_bytes + offset);
		
		switch (PROXY_FUNC(RC4_CategorizeInstruction)(ins_word)) {
			case INS_TYPE_BLXIMM:
				// Link bit
				src_bytes[offset + 3] ^= INS_OPCODE_LINKBIT;
				// Fall through
			case INS_TYPE_B:
				{
					u32  opcode;
					u32  operands;
					u32* dst_addr = (u32*)(dst_bytes + offset);
					
					opcode = (ins_word & INS_OPCODE_MASK) ^ (INS_OPCODE_LINKBIT << INS_OPCODE_SHIFT);
					operands = ((ins_word & INS_OPERANDS_MASK) - ENC_VAL_2) & INS_OPERANDS_MASK;
					
					*dst_addr = opcode | operands;
				}
				break;
			
			case INS_TYPE_BL:
				// First three bytes
				RC4_DecryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_DecryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				RC4_DecryptByte(ctx, src_bytes + offset + 2, dst_bytes + offset + 2);
				
				// Fourth byte + link bit
				dst_bytes[offset + 3] = src_bytes[offset + 3] ^ INS_OPCODE_LINKBIT;
				break;
			
			default:
				// First three bytes
				RC4_DecryptByte(ctx, src_bytes + offset,     dst_bytes + offset);
				RC4_DecryptByte(ctx, src_bytes + offset + 1, dst_bytes + offset + 1);
				RC4_DecryptByte(ctx, src_bytes + offset + 2, dst_bytes + offset + 2);
				
				// Fourth byte
				dst_bytes[offset + 3] = src_bytes[offset + 3];
				break;
		}
		
		// Update `x`
		ctx->x -= prev_opcode;
	}
	
	return 0;
}


u32 RC4_InitAndEncryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	PROXY_FUNC(RC4_Init)(&ctx, key, RC4_KEY_SIZE);
	// Must coerce return to -1 or 0
	return PROXY_FUNC(RC4_EncryptInstructions)(&ctx, dst, src, size) == -1 ? -1 : 0;
}


u32 RC4_InitAndDecryptInstructions(void* key, void* dst, void* src, u32 size) {
	RC4_Ctx ctx;
	PROXY_FUNC(RC4_Init)(&ctx, key, RC4_KEY_SIZE);
	// Must coerce return to -1 or 0
	return PROXY_FUNC(RC4_DecryptInstructions)(&ctx, dst, src, size) == -1 ? -1 : 0;
}

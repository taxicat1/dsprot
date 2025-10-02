#include "rc4.h"

#define RC4_KEY_SIZE  (16)

#define RC4_SBOX_XOR  (0x01)

typedef struct {
	int  i;
	int  j;
	u8   S[256];
} RC4_Ctx;

static void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len);
static u8 RC4_Byte(RC4_Ctx* ctx);
static u32 RC4_InitSBox(u8* sbox);
static u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);
static u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size);


static void RC4_Init(RC4_Ctx* ctx, const void* key, u32 key_len) {
	u8   tmp1;
	u8   tmp2;
	int  Ki;
	u8   Si;
	int  i;
	int  j;
	
	Ki = 0;
	Si = 0;
	ctx->i = 0;
	ctx->j = 0;
	
	for (j = 0; j < 256; j++) {
		ctx->S[j] = j;
	}
	
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


static u8 RC4_Byte(RC4_Ctx* ctx) {
	u8  i;
	u8  ival;
	u8  j;
	u8  jval;
	
	i = ctx->i + 1;
	ival = ctx->S[i];
	j = ival + ctx->j;
	jval = ctx->S[j];
	
	ctx->i = i;
	ctx->j = j;
	
	ctx->S[j] = ival;
	ctx->S[i] = jval;
	
	return ctx->S[(ival + jval) & 0xFF];
}


static u32 RC4_InitSBox(u8* sbox) {
	int i;
	for (i = 0; i < 256; i++) {
		sbox[i] = (u8)i ^ RC4_SBOX_XOR;
	}
	
	return 0;
}


static u32 RC4_EncryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	u8   sbox[256];
	u32  offset;
	u8*  src_bytes;
	u8*  dst_bytes;
	
	if (size & 3) {
		return -1;
	}
	
	src_bytes = (u8*)src;
	dst_bytes = (u8*)dst;
	
	RC4_InitSBox(&sbox[0]);
	
	for (offset = 0; offset < size; offset += 4) {
		dst_bytes[offset]     = src_bytes[offset]     ^ RC4_Byte(ctx);
		dst_bytes[offset + 1] = src_bytes[offset + 1] ^ RC4_Byte(ctx);
		dst_bytes[offset + 2] = sbox[ src_bytes[offset + 2] ];
		dst_bytes[offset + 3] = src_bytes[offset + 3];
	}
	
	return 0;
}


static u32 RC4_DecryptInstructions(RC4_Ctx* ctx, void* src, void* dst, u32 size) {
	// Identical to encryption
	return RC4_EncryptInstructions(ctx, src, dst, size);
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

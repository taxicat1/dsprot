#include <stddef.h>

#include "encoder.h"

#include "encoding_constants.h"

enum {
	INS_TYPE_OTHER = 0,
	INS_TYPE_BLX,
	INS_TYPE_BL,
	INS_TYPE_B
};


static int categorizeOpCode(unsigned int opcode) {
	if ((opcode & 0x0E) == 0x0A) {
		if ((opcode & 0xF0) == 0xF0) {
			return INS_TYPE_BLX;
		}
		
		if (opcode & 0x01) {
			return INS_TYPE_BL;
		} else {
			return INS_TYPE_B;
		}
	}
	
	return INS_TYPE_OTHER;
}


void Encode_Init(Encoding_Ctx* ctx, EncodingTask* task) {
	ctx->xor_val = ENC_XOR_START;
	ctx->prev_opcode = 0;
}


void Encode_Instruction(Encoding_Ctx* ctx, Instruction* ins, RC4_Ctx* rc4) {
	int optype = categorizeOpCode(ins->opcode);
	
	if (rc4 == NULL) {
		uint32_t ins_raw = Instruction_GetFull(ins);
		uint32_t original = ins_raw;
		ins_raw ^= ctx->xor_val;
		Instruction_SetFull(ins, ins_raw);
		ctx->xor_val ^= original - (original >> 8);
	} else {
		uint8_t a, b, c, d;
		switch (optype) {
			case INS_TYPE_BLX:
			case INS_TYPE_BL:
				ins->opcode ^= ENC_OPCODE_1;
				ins->operands += ENC_VAL_2;
				break;
			
			case INS_TYPE_B:
				ins->opcode ^= ENC_OPCODE_1;
				// Fall through
			case INS_TYPE_OTHER:
				a = ins->operands;
				b = ins->operands >> 8;
				c = ins->operands >> 16;
				d = ins->opcode;
				
				a ^= RC4_Byte(rc4);
				rc4->x = a;
				
				b ^= RC4_Byte(rc4);
				rc4->x = b;
				
				c ^= RC4_Byte(rc4);
				rc4->x = c;
				
				d = d;
				
				ins->opcode = d;
				ins->operands = (c << 16) | (b << 8) | a;
				break;
		}
		
		ins->opcode += ctx->prev_opcode;
		ctx->prev_opcode = ins->opcode;
		
		rc4->x = ((uint32_t)rc4->x - ctx->prev_opcode) & 0xFF;
	}
}


void Encode_Relocation(Elf32_Rela* reloc) {
	reloc->r_addend += ENC_VAL_1 + 8;
}


void Decode_Instruction(Encoding_Ctx* ctx, Instruction* ins, RC4_Ctx* rc4) {
	if (rc4 == NULL) {
		uint32_t ins_raw = Instruction_GetFull(ins);
		ins_raw ^= ctx->xor_val;
		Instruction_SetFull(ins, ins_raw);
		ctx->xor_val ^= ins_raw - (ins_raw >> 8);
	} else {
		uint8_t a, b, c, d, tmp;
		
		int curr_opcode = ins->opcode;
		ins->opcode -= ctx->prev_opcode;
		ctx->prev_opcode = curr_opcode;
		
		int optype = categorizeOpCode(ins->opcode);
		switch (optype) {
			case INS_TYPE_BLX:
				ins->opcode ^= 1;
			case INS_TYPE_B:
				ins->opcode ^= ENC_OPCODE_1;
				ins->operands -= ENC_VAL_2;
				break;
			
			case INS_TYPE_OTHER:
			case INS_TYPE_BL:
				a = ins->operands;
				b = ins->operands >> 8;
				c = ins->operands >> 16;
				d = ins->opcode;
				
				tmp = a;
				a ^= RC4_Byte(rc4);
				rc4->x = tmp;
				
				tmp = b;
				b ^= RC4_Byte(rc4);
				rc4->x = tmp;
				
				tmp = c;
				c ^= RC4_Byte(rc4);
				rc4->x = tmp;
				
				d = d;
				
				if (optype == 2) {
					d ^= ENC_OPCODE_1;
				}
				
				ins->opcode = d;
				ins->operands = (c << 16) | (b << 8) | a;
				break;
		}
		
		rc4->x = ((uint32_t)rc4->x - ctx->prev_opcode) & 0xFF;
	}
}


void Decode_Relocation(Elf32_Rela* reloc) {
	reloc->r_addend -= ENC_VAL_1 + 8;
}

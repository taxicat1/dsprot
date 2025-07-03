#ifndef ENCODER_H
#define ENCODER_H

#include <stdio.h>

#include "elf.h"
#include "instruction.h"
#include "rc4.h"

enum {
	ENC_ENCODE,
	ENC_DECODE,
	ENC_INVALID
};

typedef struct {
	char**    inputs;
	int       encoding_type;
	char*     decryption_symbol;
	char*     encryption_symbol;
	int       verbose;
} EncodingTask;

void Encode_Instruction(Instruction* ins, RC4_Ctx* rc4);
void Decode_Instruction(Instruction* ins, RC4_Ctx* rc4);

#endif

#ifndef ENCODING_CONSTANTS_H
#define ENCODING_CONSTANTS_H

#define INS_OPCODE_LINKBIT  (0x01)
#define INS_OPCODE_MASK     (0xFF000000)
#define INS_OPCODE_SHIFT    (24)
#define INS_OPERANDS_MASK   (0x00FFFFFF)

#define ADDR_PLUS_ADDEND(ref, addend)  ((u32)(&ref + ((addend) / sizeof(ref))))

#define ENC_VAL_1  (0x1000)
#define ENC_VAL_2  ((ENC_VAL_1 >> 2) + 2)

#define ENC_SBOX_XOR  (0xFF)

#define ENC_XOR_START  (0xF0B9A2EA)
#define ENC_XOR_MASK   (0x00FFFFFF)

#define ENC_RC4_X_START  (0xAA)

#endif

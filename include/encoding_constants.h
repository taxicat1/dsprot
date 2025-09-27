#ifndef ENCODING_CONSTANTS_H
#define ENCODING_CONSTANTS_H

#define INS_OPCODE_LINKBIT  (0x01)
#define INS_OPCODE_MASK     (0xFF000000)
#define INS_OPCODE_SHIFT    (24)
#define INS_OPERANDS_MASK   (0x00FFFFFF)

#define ADDR_PLUS_ADDEND(ref, addend)  ((u32)(&ref + ((addend) / sizeof(ref))))

#define ENC_VAL_1  (0x3200)
#define ENC_VAL_2  ((ENC_VAL_1 >> 2) + 2)

#define ENC_XOR_START  (0x0976AFCC)

#define ENC_RC4_X_START  (0xAA)

#endif

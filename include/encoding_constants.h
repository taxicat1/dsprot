#ifndef ENCODING_CONSTANTS_H
#define ENCODING_CONSTANTS_H

#define ENC_VAL_1  (0x3200)
#define ENC_VAL_2  ((ENC_VAL_1 >> 2) + 2)

#define ENC_OPCODE_1  (0x01)

#define ADDR_PLUS_ADDEND(ref, addend)  ((u32)(&ref + ((addend) / sizeof(*&ref))))

#define ENC_XOR_START  (0x0976AFCC)

#define ENC_RC4_X_START  (0xAA)

#endif

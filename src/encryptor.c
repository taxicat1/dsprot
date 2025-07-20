#include "encryptor.h"

#include "rc4.h"


void Encryptor_StartRange(u32* addr) {
    u8   key[16];
    int  i;
    u32  key_ins;
    u8*  keyptr;
    u32  end;
    u32  size;
    
    key_ins = addr[-1];
    
    keyptr = &key[0];
    for (i = 0; i < 16; i++) {
        *keyptr = key_ins >> ((i % 4) * 8);
        if (i % 15 == 0) {
            *keyptr ^= 0xff;
        }
        keyptr++;
    }
    
    end = addr[0];
    size = 0;
    while (key_ins != end) {
        size++;
        end = addr[size];
    }
    
    if (size) {
        RC4_InitAndDecryptInstructions(&key[0], addr, addr, size * 4);
    }
    
	DC_FlushRange(addr, size * 4);
	IC_InvalidateRange(addr, size * 4);
}


void Encryptor_EndRange(u32* addr) {
    u8   key[16];
    int  i;
    u32  key_ins;
    u8*  keyptr;
    u32  end;
    u32  size;
    
    key_ins = addr[1];
    
    keyptr = &key[0];
    for (i = 0; i < 16; i++) {
        *keyptr = key_ins >> ((i % 4) * 8);
        if (i % 15 == 0) {
            *keyptr ^= 0xff;
        }
        keyptr++;
    }
    
    end = addr[0];
    while (end != key_ins) {
        end = *--addr;
    }
    end = addr[1];
    
    size = 0;
    while (key_ins != end) {
        size++;
        end = addr[size + 1];
    }
    addr++;
    
    if (size) {
        RC4_InitAndEncryptInstructions(&key[0], addr, addr, size * 4);
    }
    
    DC_FlushRange(addr, size * 4);
	IC_InvalidateRange(addr, size * 4);
}

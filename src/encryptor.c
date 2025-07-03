#include "encryptor.h"

#include "rc4.h"


void Encryptor_StartRange(u32 addr) {
    u8   key[16];
    int  i;
    u32  key_ins;
    u8*  keyptr;
    u32  end;
    u32  size;
    
    key_ins = ((u32*)addr)[-1];
    
    keyptr = &key[0];
    for (i = 0; i < 16; i++) {
        *keyptr = key_ins >> ((i % 4) * 8);
        if (i % 15 == 0) {
            *keyptr ^= 0xff;
        }
        keyptr++;
    }
    
    end = *(u32*)addr;
    size = 0;
    while (key_ins != end) {
        size++;
        end = ((u32*)addr)[size];
    }
    size *= 4;
    
    if (size) {
        RC4_InitAndDecryptInstructions(&key[0], (void*)addr, (void*)addr, size);
    }
    
    DC_FlushRange((void*)addr, size);
    IC_InvalidateRange((void*)addr, size);
}


void Encryptor_EndRange(u32 addr) {
    u8   key[16];
    int  i;
    u32  key_ins;
    u8*  keyptr;
    u32  end;
    u32  size;
    
    key_ins = ((u32*)addr)[1];
    
    keyptr = &key[0];
    for (i = 0; i < 16; i++) {
        *keyptr = key_ins >> ((i % 4) * 8);
        if (i % 15 == 0) {
            *keyptr ^= 0xff;
        }
        keyptr++;
    }
    
    end = *(u32*)addr;
    while (end != key_ins) {
        end = *(u32*)(addr -= 4);
    }
    end = ((u32*)addr)[1];
    
    size = 0;
    while (key_ins != end) {
        size++;
        end = ((u32*)addr + size)[1];
    }
    size *= 4;
    addr += 4;
    
    if (size) {
        RC4_InitAndEncryptInstructions(&key[0], (void*)addr, (void*)addr, size);
    }
    
    DC_FlushRange((void*)addr, size);
    IC_InvalidateRange((void*)addr, size);
}

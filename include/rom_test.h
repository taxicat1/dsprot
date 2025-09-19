#ifndef ROM_TEST_H
#define ROM_TEST_H

#include "nitro_types.h"
#include "dsprot_types.h"

// Assembly decryption wrappers
extern u32 RunEncrypted_ROMTest_IsBad(DSProt_Ctx* ctx);
extern u32 RunEncrypted_ROMTest_IsGood(DSProt_Ctx* ctx);

// Assembly decoder
extern void CoreTests_DecodeFunctions(void);

#endif

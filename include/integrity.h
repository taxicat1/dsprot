#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "nitro_types.h"
#include "dsprot_types.h"

// Assembly decryption wrappers
extern u32 RunEncrypted_Integrity_MACOwner_IsBad(DSProt_Ctx* __unused);
extern u32 RunEncrypted_Integrity_MACOwner_IsGood(DSProt_Ctx* __unused);
extern u32 RunEncrypted_Integrity_ROMTest_IsBad(DSProt_Ctx* __unused);
extern u32 RunEncrypted_Integrity_ROMTest_IsGood(DSProt_Ctx* __unused);

// Assembly decoder
extern void Integrity_DecodeFunctions(void);

#endif

#ifndef MAC_OWNER_H
#define MAC_OWNER_H

#include "nitro_types.h"
#include "dsprot_types.h"

// Assembly decryption wrappers
extern u32 RunEncrypted_MACOwner_IsBad(DSProt_Ctx* ctx);
extern u32 RunEncrypted_MACOwner_IsGood(DSProt_Ctx* ctx);

// Assembly decoder
extern void CoreTests_DecodeFunctions(void);

#endif

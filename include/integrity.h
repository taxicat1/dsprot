#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "types.h"

// Assembly decryption wrappers
extern u32 RunEncrypted_Integrity_MACOwner_IsBad(void* __unused);
extern u32 RunEncrypted_Integrity_ROMTest_IsBad(void* __unused);

#endif

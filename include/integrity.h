#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "types.h"

u32 Integrity_MACOwner_IsBad(void);
u32 Integrity_MACOwner_IsGood(void);
u32 Integrity_ROMTest_IsBad(void);
u32 Integrity_ROMTest_IsGood(void);

#endif

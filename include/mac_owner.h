#ifndef MAC_OWNER_H
#define MAC_OWNER_H

#include "types.h"

// Copy of Nitro struct
// <nitro/os.h>
typedef struct {
	u8   language;
	u8   favoriteColor;
	struct {
		u8  month;
		u8  day;
	}  birthday;
	u16  nickName[11];
	u16  nickNameLength;
	u16  comment[27];
	u16  commentLength;
} OSOwnerInfo;

// Nitro functions
// <nitro/os.h>
extern void OS_GetMacAddress(u8* mac_addr);
extern void OS_GetOwnerInfo(OSOwnerInfo* info);

u32 MACOwner_IsBad(void);
u32 MACOwner_IsGood(void);

#endif

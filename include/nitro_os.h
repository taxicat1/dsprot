#ifndef NITRO_OS_H
#define NITRO_OS_H

#include "nitro_types.h"

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

extern s32 OS_GetLockID(void);
extern void OS_ReleaseLockID(u16 lock_id);
extern void OS_GetMacAddress(u8* mac_addr);
extern void OS_GetOwnerInfo(OSOwnerInfo* info);
extern void DC_StoreAll(void);
extern void IC_Disable(void);
extern void IC_Enable(void);

#endif

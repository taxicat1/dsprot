#ifndef NITRO_OS_H
#define NITRO_OS_H

#include "nitro_types.h"

// <nitro/os.h>
#define HW_CACHE_LINE_SIZE        (32)
#define HW_C7_CACHE_SET_NO_SHIFT  (30)
#define HW_DCACHE_SIZE            (0x1000)

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

#endif

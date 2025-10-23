// All symbols must be resolved to properly link
#define DUMMY_FUNC(name)  \
	void name(void);      \
	void name(void) { }

#define ENTRY  __startup

DUMMY_FUNC(CARD_LockRom)
DUMMY_FUNC(CARD_UnlockRom)
DUMMY_FUNC(CARDi_ReadRom)
DUMMY_FUNC(OS_GetLockID)
DUMMY_FUNC(OS_GetMacAddress)
DUMMY_FUNC(OS_GetOwnerInfo)
DUMMY_FUNC(OS_ReleaseLockID)

DUMMY_FUNC(ENTRY)

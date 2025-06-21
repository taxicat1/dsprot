#include "mac_owner.h"

// Functions to be encrypted (cannot be called directly)
u32 MACOwner_IsBad(void);
u32 MACOwner_IsGood(void);

static const u8 bad_mac_addr[6] = { /* _02260BD4 */
	// 00:09:BF:00:00:31 after bit flipping
	0xFF, 0xF6, 0x40, 0xFF, 0xFF, 0xCE
};


u32 MACOwner_IsBad(void) { /* ov123_0225FFE8 */
	int          i;
	u8           mac_addr[6];
	OSOwnerInfo  owner_info;
	
	OS_GetMacAddress(&mac_addr[0]);
	for (i = 0; i < 6; i++) {
		if (bad_mac_addr[i] != (mac_addr[i] ^ 0xFF)) {
			break;
		}
	}
	
	OS_GetOwnerInfo(&owner_info);
	if (
		i == 6 && 
		owner_info.birthday.month == 1 && 
		owner_info.birthday.day   == 1 && 
		owner_info.nickNameLength == 0
	) {
		return 1;
	}
	
	for (i = 0; i < 6; i++) {
		if (mac_addr[i] != 0x00) {
			return 0;
		}
	}
	
	return 1;
}


u32 MACOwner_IsGood(void) { /* ov123_02260098 */
	int          i;
	u8           mac_addr[6];
	OSOwnerInfo  owner_info;
	
	OS_GetMacAddress(&mac_addr[0]);
	for (i = 0; i < 6; i++) {
		if (bad_mac_addr[i] != (mac_addr[i] ^ 0xFF)) {
			break;
		}
	}
	
	OS_GetOwnerInfo(&owner_info);
	if (
		i == 6 &&
		owner_info.birthday.month == 1 &&
		owner_info.birthday.day   == 1 &&
		owner_info.nickNameLength == 0
	) {
		return 0;
	}
	
	for (i = 0; i < 6; i++) {
		if (mac_addr[i] != 0x00) {
			return 1;
		}
	}
	
	return 0;
}

#include "mac_owner.h"

#include "encryptor.h"

static const u8 bad_mac_addr[6] = {
	// 00:09:BF:00:00:31 after bit flipping
	0xFF, 0xF6, 0x40, 0xFF, 0xFF, 0xCE
};

#define MAC_ADDR_SIZE  (6)


u32 MACOwner_IsBad(void) {
	u8           mac_addr[MAC_ADDR_SIZE];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[0]);
	
	ENCRYPTION_START(0x0F57);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[i] ^ 0xFF)) {
			break;
		}
	}
	
	ENCRYPTION_END(0x0F57);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(0x0D8B);
	
	if (
		i == MAC_ADDR_SIZE && 
		owner_info.birthday.month == 1 && 
		owner_info.birthday.day   == 1 && 
		owner_info.nickNameLength == 0
	) {
		ret = 1;
		goto EXIT;
	}
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (mac_addr[i] != 0x00) {
			ret = 0;
			goto EXIT;
		}
	}
	
	ret = 1;
	
EXIT:
	ENCRYPTION_END(0x0D8B);
	
	return ret;
}


u32 MACOwner_IsGood(void) {
	u8           mac_addr[MAC_ADDR_SIZE];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[0]);
	
	ENCRYPTION_START(0x0314);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[i] ^ 0xFF)) {
			break;
		}
	}
	
	ENCRYPTION_END(0x0314);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(0x7EF6);
	
	if (
		i == MAC_ADDR_SIZE && 
		owner_info.birthday.month == 1 && 
		owner_info.birthday.day   == 1 && 
		owner_info.nickNameLength == 0
	) {
		ret = 0;
		goto EXIT;
	}
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (mac_addr[i] != 0x00) {
			ret = 1;
			goto EXIT;
		}
	}
	
	ret = 0;
	
EXIT:
	ENCRYPTION_END(0x7EF6);
	
	return ret;
}

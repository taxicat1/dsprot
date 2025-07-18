#include "mac_owner.h"

#include "encryptor.h"

static const u8 bad_mac_addr[6] = {
	// 00:09:BF:00:00:31 after bit flipping
	0xFF, 0xF6, 0x40, 0xFF, 0xFF, 0xCE
};

#define MAC_ADDR_SIZE    (6)
#define MAC_ADDR_OFFSET  (2)


u32 MACOwner_IsBad(void) {
	// Oddly the MAC address buffer is offset like this. Obfuscation?
	u8           mac_addr[MAC_ADDR_OFFSET+MAC_ADDR_SIZE+MAC_ADDR_OFFSET];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[MAC_ADDR_OFFSET]);
	
	ENCRYPTION_START(0x3B74);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[MAC_ADDR_OFFSET+i] ^ 0xFF)) {
			break;
		}
	}
	
	ENCRYPTION_END(0x3B74);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(0x67FA);
	
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
		if (mac_addr[MAC_ADDR_OFFSET+i] != 0x00) {
			ret = 0;
			goto EXIT;
		}
	}
	
	ret = 1;
	
EXIT:
	ENCRYPTION_END(0x67FA);
	
	return ret;
}


u32 MACOwner_IsGood(void) {
	// Oddly the MAC address buffer is offset like this. Obfuscation?
	u8           mac_addr[MAC_ADDR_OFFSET+MAC_ADDR_SIZE+MAC_ADDR_OFFSET];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[MAC_ADDR_OFFSET]);
	
	ENCRYPTION_START(0x239B);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[MAC_ADDR_OFFSET+i] ^ 0xFF)) {
			break;
		}
	}
	
	ENCRYPTION_END(0x239B);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(0x298C);
	
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
		if (mac_addr[MAC_ADDR_OFFSET+i] != 0x00) {
			ret = 1;
			goto EXIT;
		}
	}
	
	ret = 0;
	
EXIT:
	ENCRYPTION_END(0x298C);
	
	return ret;
}

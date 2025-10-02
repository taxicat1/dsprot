#include "mac_owner.h"

#include "encryptor.h"
#include "keys.h"
#include "nitro_os.h"

#define MAC_ADDR_SIZE  (6)

#define MAC_ADDR_OFFSET  (2)

#define ENC_MAC_ADDR_BYTE  (0xFF)

static const u8 bad_mac_addr[MAC_ADDR_SIZE] = {
	0x00 ^ ENC_MAC_ADDR_BYTE,
	0x09 ^ ENC_MAC_ADDR_BYTE,
	0xBF ^ ENC_MAC_ADDR_BYTE,
	0x00 ^ ENC_MAC_ADDR_BYTE,
	0x00 ^ ENC_MAC_ADDR_BYTE,
	0x31 ^ ENC_MAC_ADDR_BYTE
};


u32 MACOwner_IsBad(void) {
	// Oddly the MAC address buffer is offset like this. Obfuscation?
	u8           mac_addr[MAC_ADDR_OFFSET + MAC_ADDR_SIZE + MAC_ADDR_OFFSET];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[MAC_ADDR_OFFSET]);
	
	ENCRYPTION_START(KEY_MAC_OWNER_1);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[MAC_ADDR_OFFSET + i] ^ ENC_MAC_ADDR_BYTE)) {
			break;
		}
	}
	
	ENCRYPTION_END(KEY_MAC_OWNER_1);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(KEY_MAC_OWNER_2);
	
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
		if (mac_addr[MAC_ADDR_OFFSET + i] != 0x00) {
			ret = 0;
			goto EXIT;
		}
	}
	
	ret = 1;
	
EXIT:
	ENCRYPTION_END(KEY_MAC_OWNER_2);
	
	return ret;
}


u32 MACOwner_IsGood(void) {
	// Oddly the MAC address buffer is offset like this. Obfuscation?
	u8           mac_addr[MAC_ADDR_OFFSET + MAC_ADDR_SIZE + MAC_ADDR_OFFSET];
	OSOwnerInfo  owner_info;
	int          i;
	u32          ret;
	
	OS_GetMacAddress(&mac_addr[MAC_ADDR_OFFSET]);
	
	ENCRYPTION_START(KEY_MAC_OWNER_3);
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[MAC_ADDR_OFFSET + i] ^ ENC_MAC_ADDR_BYTE)) {
			break;
		}
	}
	
	ENCRYPTION_END(KEY_MAC_OWNER_3);
	
	OS_GetOwnerInfo(&owner_info);
	
	ENCRYPTION_START(KEY_MAC_OWNER_4);
	
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
		if (mac_addr[MAC_ADDR_OFFSET + i] != 0x00) {
			ret = 1;
			goto EXIT;
		}
	}
	
	ret = 0;
	
EXIT:
	ENCRYPTION_END(KEY_MAC_OWNER_4);
	
	return ret;
}

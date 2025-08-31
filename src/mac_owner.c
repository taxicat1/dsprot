#include "mac_owner.h"

#include "crash.h"
#include "primes.h"
#include "encoding_constants.h"

// Function to be encrypted (cannot be called directly)
u32 MACOwner_IsBad(void);

#define MAC_ADDR_SIZE  (6)

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
	int          i;
	u8           mac_addr[MAC_ADDR_SIZE];
	OSOwnerInfo  owner_info;
	u32          mul;
	
	OS_GetMacAddress(&mac_addr[0]);
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (bad_mac_addr[i] != (mac_addr[i] ^ ENC_MAC_ADDR_BYTE)) {
			break;
		}
	}
	
	OS_GetOwnerInfo(&owner_info);
	if (
		i == MAC_ADDR_SIZE &&
		owner_info.birthday.month == 1 &&
		owner_info.birthday.day   == 1 &&
		owner_info.nickNameLength == 0
	) {
		DSProt_Crash(0, 0);
		mul = PRIME_TRUE;
		goto EXIT;
	}
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (mac_addr[i] != 0x00) {
			mul = PRIME_FALSE;
			goto EXIT;
		}
	}
	
	DSProt_Crash(0, 0);
	mul = PRIME_TRUE;
	
EXIT:
	return mul * PRIME_MAC_OWNER;
}

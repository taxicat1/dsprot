#include "mac_owner.h"

#include "primes.h"
#include "failure_codes.h"
#include "encoding_constants.h"

// Functions to be encrypted (cannot be called directly)
u32 MACOwner_IsBad(DSProt_Ctx* ctx);
u32 MACOwner_IsGood(DSProt_Ctx* ctx);

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


u32 MACOwner_IsBad(DSProt_Ctx* ctx) {
	u8           mac_addr[MAC_ADDR_SIZE];
	OSOwnerInfo  owner_info;
	int          i;
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
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		mul = PRIME_TRUE;
		ctx->failure_code = FAILURE_CODE_MAC_OWNER_1;
		goto EXIT;
	}
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (mac_addr[i] != 0x00) {
			mul = PRIME_FALSE;
			goto EXIT;
		}
	}
	
	ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
	mul = PRIME_TRUE;
	ctx->failure_code = FAILURE_CODE_MAC_OWNER_1;
	
EXIT:
	return mul * PRIME_MAC_OWNER_1;
}


u32 MACOwner_IsGood(DSProt_Ctx* ctx) {
	u8           mac_addr[MAC_ADDR_SIZE];
	OSOwnerInfo  owner_info;
	int          i;
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
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		mul = PRIME_FALSE;
		ctx->failure_code = FAILURE_CODE_MAC_OWNER_2;
		goto EXIT;
	}
	
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (mac_addr[i] != 0x00) {
			mul = PRIME_TRUE;
			goto EXIT;
		}
	}
	
	ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
	mul = PRIME_FALSE;
	ctx->failure_code = FAILURE_CODE_MAC_OWNER_3;
	
EXIT:
	return mul * PRIME_MAC_OWNER_2;
}

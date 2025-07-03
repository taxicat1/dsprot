#include "dummy.h"

#include "primes.h"

// Functions to be encrypted (cannot be called directly)
u32 Dummy_IsBad(void);
u32 Dummy_IsGood(void);


u32 Dummy_IsBad(void) {
	return PRIME_DUMMY_1 * PRIME_FALSE;
}

u32 Dummy_IsGood(void) {
	return PRIME_DUMMY_2 * PRIME_TRUE;
}

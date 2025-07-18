/* No dedicated header */

#include "types.h"

#include "integrity.h"
#include "rom_test.h"
#include "mac_owner.h"
#include "encoding_constants.h"

#ifndef POKEHEARTGOLD_COMPATABILITY

// Functions to be encrypted (cannot be called directly)
u32 DetectFlashcart(void* callback);
u32 DetectNotFlashcart(void* callback);
u32 DetectEmulator(void* callback);
u32 DetectNotEmulator(void* callback);
u32 DetectDummy(void* callback);
u32 DetectNotDummy(void* callback);

#else /* POKEHEARTGOLD_COMPATABILITY */

// Functions to be encrypted (cannot be called directly)
// pokeheartgold-compatible names
u32 _0225F430(void* callback);
u32 _0225F4A8(void* callback);
u32 _0225F520(void* callback);
u32 _0225F598(void* callback);
u32 _0225F610(void* callback);
u32 _0225F688(void* callback);

#endif /* POKEHEARTGOLD_COMPATABILITY */

static inline BOOL executeFunctionQueue(u32* func_queue, int compare_type);

#define DSP_OBFS_OFFSET  (0x320)

enum {
	DETECT_POSITIVE,
	DETECT_NEGATIVE
};

typedef u32 (*U32Func)(void);
typedef void (*VoidFunc)(void);


// This was likely not originally an inline, but an inline is able to match here nicely
static inline BOOL executeFunctionQueue(u32* func_queue, int compare_type) {
	BOOL  func_result;
	s32   compare_sum;
	u32   i;
	s32   func_result_sum;
	
	// These two bit arrays must be signed to match
	compare_sum = 0;
	func_result_sum = 0;
	
	for (i = 0; func_queue[i] != 0; i++) {
		func_result = ((U32Func)(func_queue[i] - ENC_VAL_1 - DSP_OBFS_OFFSET))() != 0;
		
		func_result_sum += func_result;
		func_result_sum <<= 1;
		
		compare_sum += 1;
		compare_sum <<= 1;
	}
	
	if (compare_type == DETECT_NEGATIVE) {
		return (func_result_sum >> 1) == (compare_sum >> 1);
	} else {
		return ((func_result_sum & compare_sum) >> 1) != 0;
	}
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectFlashcart(void* callback) { /* ov123_0225F020 */
#else
u32 _0225F430(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_POSITIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectNotFlashcart(void* callback) { /* ov123_0225F0D8 */
#else
u32 _0225F4A8(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_ROMTest_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_ROMTest_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_NEGATIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectEmulator(void* callback) { /* ov123_0225F190 */
#else
u32 _0225F520(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsBad[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_POSITIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectNotEmulator(void* callback) { /* ov123_0225F248 */
#else
u32 _0225F598(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	func_queue[2] = 0;
	func_queue[0] = (u32)&RunEncrypted_MACOwner_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	func_queue[1] = (u32)&RunEncrypted_Integrity_MACOwner_IsGood[ENC_VAL_1] + DSP_OBFS_OFFSET;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_NEGATIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectDummy(void* callback) { /* ov123_0225F300 */
#else
u32 _0225F610(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	// Prevent optimization of the function queue processing
	*(u32*)&func_queue[0] = 0;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_POSITIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}


#ifndef POKEHEARTGOLD_COMPATABILITY
u32 DetectNotDummy(void* callback) { /* ov123_0225F398 */
#else
u32 _0225F688(void* callback) {
#endif
	u32   func_queue[32];
	BOOL  ret;
	
	// Prevent optimization of the function queue processing
	*(u32*)&func_queue[0] = 0;
	
	ret = executeFunctionQueue(&func_queue[0], DETECT_NEGATIVE);
	
	if (callback != NULL && ret != 0) {
		((VoidFunc)callback)();
	}
	
	return (u32)ret;
}

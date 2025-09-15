#ifndef DSPROT_INSTANT_H
#define DSPROT_INSTANT_H

#ifndef SDK_ASM

#include <nitro/types.h> // u32

#ifdef __cplusplus
extern "C" {
#endif

extern void* DSProt_Crash(void* __unused1, void* __unused2);
extern void* DSProt_DetectAll(void* callback, void* param1, void* param2);

#define DSP_EXPECTED_CHECKSUM  (0x9FBB82E0)


static inline void* DSProt_CheckAndDetectAll(void* callback, void* param1, void* param2) {
	u32*  func_data_ptr;
	u32   func_data_checksum;
	u32   i;
	
	func_data_ptr = (u32*)DSProt_DetectAll;
	i = 9;
	func_data_checksum = 0;
	do {
		func_data_checksum ^= (*func_data_ptr >> 5) | (*func_data_ptr << 27);
		func_data_ptr++;
	} while (--i);
	
	if (func_data_checksum == DSP_EXPECTED_CHECKSUM) {
		return DSProt_DetectAll(callback, param1, param2);
	} else {
		return DSProt_Crash(NULL, NULL);
	}
}

#undef DSP_EXPECTED_CHECKSUM

#ifdef __cplusplus
}
#endif

#else /* SDK_ASM */

.public DSProt_Crash
.public DSProt_DetectAll

#endif /* SDK_ASM */

#endif /* DSPROT_INSTANT_H */

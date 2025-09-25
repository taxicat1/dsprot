#ifndef NITRO_MI_H
#define NITRO_MI_H

#include "nitro_types.h"

// <nitro/mi.h>
extern void MIi_CpuClear32(u32 data, void* destp, u32 size);


static inline void MI_CpuFill32(void* dest, u32 data, u32 size) {
	MIi_CpuClear32(data, dest, size);
}


static inline void MI_CpuClear32(void* dest, u32 size) {
	MI_CpuFill32(dest, 0, size);
}


#endif

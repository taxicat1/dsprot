#ifndef NITRO_MI_H
#define NITRO_MI_H

#include "nitro_types.h"

// <nitro/mi.h>
extern void MI_CpuFill8(void* dest, u8 data, u32 size);


static inline void MI_CpuClear8(void* dest, u32 size) {
	MI_CpuFill8(dest, 0, size);
}


#endif
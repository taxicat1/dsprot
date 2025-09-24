#ifndef NITRO_CARD_H
#define NITRO_CARD_H

#include "nitro_types.h"

// <nitro/card.h>
#define CARD_ROM_PAGE_SIZE  (0x200)

#define MI_DMA_NOT_USE  (0xFFFFFFFF)

extern void CARD_LockRom(u16 lock_id);
extern void CARD_UnlockRom(u16 lock_id);
extern void CARDi_ReadRom(u32 dma, const void* src, void* dst, u32 len, void* callback, void* arg, BOOL is_async);


static inline void CARD_ReadRom(u32 dma, const void *src, void *dst, u32 len) {
    CARDi_ReadRom(dma, src, dst, len, NULL, NULL, FALSE);
}


// Not available in all Nitro versions
#define CARDMST_ENABLE  (0x80)

#define CARD_DATA_READY    (0x00800000)
#define CARD_COMMAND_PAGE  (0x01000000)
#define CARD_COMMAND_MASK  (0x07000000)
#define CARD_RESET_HI      (0x20000000)
#define CARD_READ_MODE     (0x00000000)
#define CARD_START         (0x80000000)

#define MROMOP_G_READ_PAGE  (0xB7000000)

#endif

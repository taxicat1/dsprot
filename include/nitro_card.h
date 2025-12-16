#ifndef NITRO_CARD_H
#define NITRO_CARD_H

#include "nitro_types.h"

// <nitro/card.h>
#define CARD_ROM_PAGE_SIZE  (0x200)

#define MI_DMA_NOT_USE  (0xFFFFFFFF)

typedef struct {
	u32  offset;
	u32  length;
} CARDRomRegion;

typedef struct {
	char  game_name[12];
	u32   game_code;
	u16   maker_code;
	u8    product_id;
	u8    device_type;
	u8    device_size;
	u8    reserved_A[9];
	u8    game_version;
	u8    property;
	
	void*  main_rom_offset;
	void*  main_entry_address;
	void*  main_ram_address;
	u32    main_size;
	void*  sub_rom_offset;
	void*  sub_entry_address;
	void*  sub_ram_address;
	u32    sub_size;
	
	CARDRomRegion  fnt;
	CARDRomRegion  fat;
	
	CARDRomRegion  main_ovt;
	CARDRomRegion  sub_ovt;
	
	u8   rom_param_A[8];
	u32  banner_offset;
	u16  secure_crc;
	u8   rom_param_B[2];
	
	void*  main_autoload_done;
	void*  sub_autoload_done;
	
	u8   rom_param_C[8];
	u32  rom_size;
	u32  header_size;
	u8   reserved_B[0x38];
	
	u8   logo_data[0x9C];
	u16  logo_crc;
	u16  header_crc;
} CARDRomHeader;

extern void CARD_LockRom(u16 lock_id);
extern void CARD_UnlockRom(u16 lock_id);
extern void CARDi_ReadRom(u32 dma, const void* src, void* dst, u32 len, void* callback, void* arg, BOOL is_async);
extern const u8* CARD_GetRomHeader(void);


static inline void CARD_ReadRom(u32 dma, const void* src, void* dst, u32 len) {
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

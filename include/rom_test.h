#ifndef ROM_TEST_H
#define ROM_TEST_H

#include "types.h"
#include "dsprot_types.h"

// TWL functions
// <nitro/os.h>
// <nitro/card.h>
extern s32 OS_GetLockID(void);
extern void CARD_LockRom(u16 lock_id);
extern void CARD_UnlockRom(u16 lock_id);
extern void OS_ReleaseLockID(u16 lock_id);
extern const u8* CARD_GetRomHeader(void);

// Copy of TWL structs
typedef struct {
	u32  offset;
	u32  length;
} CARDRomRegion;

typedef struct {
	char    game_name[12];             /* Software title name*/
	u32     game_code;                 /* initial code*/
	u16     maker_code;                /* maker code*/
	u8      product_id;                /* system code*/
	u8      device_type;               /* Device type*/
	u8      device_size;               /* device capacity*/
	u8      reserved_A[9];             /* system reserve A*/
	u8      game_version;              /* software version*/
	u8      property;                  /* internal use flag*/
	
	void   *main_rom_offset;           /* ARM9 transfer source ROM offset*/
	void   *main_entry_address;        /* ARM9 execution start address (un-mounted)*/
	void   *main_ram_address;          /* ARM9 transfer destination RAM offset*/
	u32     main_size;                 /* ARM9 distribution size*/
	void   *sub_rom_offset;            /* ARM7 transfer source ROM offset*/
	void   *sub_entry_address;         /* ARM7 execution start address (un-mounted)*/
	void   *sub_ram_address;           /* ARM7 transfer destination RAM offset*/
	u32     sub_size;                  /* ARM7 distribution size*/
	
	CARDRomRegion  fnt;                /* File Name Table*/
	CARDRomRegion  fat;                /* File allocation table.*/
	
	CARDRomRegion  main_ovt;           /* ARM9 overlay header table*/
	CARDRomRegion  sub_ovt;            /* ARM7 overlay header table*/
	
	u8      rom_param_A[8];            /* Mask ROM control parameter A*/
	u32     banner_offset;             /* Banner file ROM offset*/
	u16     secure_crc;                /* Secure environment CRC*/
	u8      rom_param_B[2];            /* Mask ROM control parameter B*/
	
	void   *main_autoload_done;        /* ARM9 auto load hook address*/
	void   *sub_autoload_done;         /* ARM7 auto load hook address*/
	
	u8      rom_param_C[8];            /* Mask ROM control parameter C*/
	u32     rom_size;                  /* Application final ROM offset*/
	u32     header_size;               /* ROM header size*/
	u8      reserved_B[0x38];          /* System reserve B*/
	
	u8      logo_data[0x9C];           /* NINTENDO logo image data*/
	u16     logo_crc;                  /* NINTENDO logo CRC*/
	u16     header_crc;                /* ROM internal register data CRC*/
} CARDRomHeader;

// TWL function without header support (anymore)
extern void CARDi_ReadRom(u32 dma, const void *src, void *dst, u32 len, void* callback, void *arg, BOOL is_async);

// Assembly decryption wrappers
extern u32 RunEncrypted_ROMTest_IsBad(DSProt_Ctx* ctx);
extern u32 RunEncrypted_ROMTest_IsGood(DSProt_Ctx* ctx);

// Assembly decoder
extern void CoreTests_DecodeFunctions(void);

#endif

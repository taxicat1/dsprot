#include "rom_util.h"

#include "encryptor.h"
#include "keys.h"
#include "nitro_card.h"
#include "nitro_io_reg.h"
#include "nitro_os.h"

// Not actually available from standard Nitro includes
#define REG_CARD_MASTER_CNT_OFFSET  (0x1A1)
#define REG_CARDCNT_OFFSET          (0x1A4)
#define REG_CARD_CMD_OFFSET         (0x1A8)
#define REG_CARD_DATA_OFFSET        (0x100010)

#define CARDMST_ENABLE      (0x80)

#define CARD_DATA_READY     (0x00800000)
#define CARD_COMMAND_PAGE   (0x01000000)
#define CARD_COMMAND_MASK   (0x07000000)
#define CARD_RESET_HI       (0x20000000)
#define CARD_ACCESS_MODE    (0x40000000)
#define CARD_READ_MODE      (0x00000000)
#define CARD_START          (0x80000000)

#define MROMOP_G_READ_PAGE  (0xB7000000)


void ROMUtil_Read(void* dest, u32 addr, s32 num_bytes) {
	// This function is executing an obfuscated manual cartridge ROM read.
	// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
	//
	// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
	//
	// Most/all convoluted syntax here must be that way to match.
	// Some of the comment documentation may be inaccurate here.
	
	u32         register_base;
	REGType8v*  card_cmd;
	s32         addr_offset;
	u8          buffer[8];
	u16         lock_id;
	u16         ext_mem_register_val_original;
	u32         output;
	u32         reg_mi_exmemcnt;
	int         i;
	s32         card_ctrl_cmd;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	ENCRYPTION_START(KEY_ROM_UTIL_READ_1);
	
	// Alias for register base (0x04000000)
	register_base = 1;
	register_base <<= 26;
	
	// Card command register (0x040001A8)
	card_cmd = (REGType8v*)(register_base + REG_CARD_CMD_OFFSET);
	
	// External memory control register (0x04000204)
	reg_mi_exmemcnt = 1;
	reg_mi_exmemcnt <<= 26;
	reg_mi_exmemcnt += REG_EXMEMCNT_OFFSET;
	
	// Save value to rewrite later
	ext_mem_register_val_original = *(REGType16v*)reg_mi_exmemcnt;
	
	// Set current processor accessing the gamecard bus to the ARM9
	*(REGType16v*)reg_mi_exmemcnt = (*(REGType16v*)reg_mi_exmemcnt & ~REG_MI_EXMEMCNT_MP_MASK) |
	                                (MI_PROCESSOR_ARM9 << REG_MI_EXMEMCNT_MP_SHIFT);
	
	// This is an address in the ROM header: port 0x040001A4 / setting for normal commands
	// This address must instead be 0x02FFFE60 if in DSi mode, which is unsupported here
	// Read port setting and set page read flags
	card_ctrl_cmd = (*(vs32*)0x027FFE60 & ~CARD_COMMAND_MASK) |
	                (CARD_COMMAND_PAGE | CARD_READ_MODE | CARD_START | CARD_RESET_HI);
	
	// Calculate offset to round back to nearest 0x200-byte block.
	// E.G. if we want to read starting from 0x1208, we actually need to
	// request the block at 0x1200 and then ignore the first 8 bytes of the result.
	// This would set `addr_offset` to -8.
	addr_offset = 0 - (addr & (CARD_ROM_PAGE_SIZE - 1));
	
	// Wait for card to not be busy
	while (*(REGType32v*)(register_base + REG_CARDCNT_OFFSET) & CARD_START) {
		continue;
	}
	
	// Write enable flag to card ROM and SPI control register
	*(REGType8v*)(register_base + REG_CARD_MASTER_CNT_OFFSET) = CARDMST_ENABLE;
	
	// Read 8-byte command out from gamecard bus, write this back later
	for (i = 0; i < 8; i++) {
		buffer[i] = card_cmd[i];
	}
	
	addr += addr_offset;
	
	while (addr_offset < num_bytes) {
		// Read a 0x200-byte data block from ROM
		
		// Write 8-byte command to registers
		// B7XXXXXXXX000000 -> 0x200-byte encrypted data read from address XXXXXXXX
		card_cmd[0] = MROMOP_G_READ_PAGE >> 24;
		card_cmd[1] = addr >> 24;
		card_cmd[2] = addr >> 16;
		card_cmd[3] = addr >> 8;
		card_cmd[4] = addr;
		card_cmd[5] = 0x00;
		card_cmd[6] = 0x00;
		card_cmd[7] = 0x00;
		
		// Submit command
		*(REGType32v*)(register_base + REG_CARDCNT_OFFSET) = card_ctrl_cmd;
		
		// Copy the output into the destination buffer, within the bounds of num_bytes
		// (Must read the output out of the I/O register regardless)
		do {
			if (*(REGType32v*)(register_base + REG_CARDCNT_OFFSET) & CARD_DATA_READY) {
				output = *(REGType32v*)(register_base + REG_CARD_DATA_OFFSET);
				if (addr_offset >= 0 && addr_offset < num_bytes) {
					*(u32*)(dest + addr_offset) = output;
				}
				
				addr_offset += 4;
			}
		} while (*(REGType32v*)(register_base + REG_CARDCNT_OFFSET) & CARD_START);
		
		// Advance address to next block
		addr += CARD_ROM_PAGE_SIZE;
	}
	
	// Done reading, restore everything how it was before
	
	// Write original command back to gamecard bus
	for (i = 0; i < 8; i++) {
		card_cmd[i] = buffer[i];
	}
	
	// Write original value back to to external memory control register
	*(REGType16v*)(register_base + REG_EXMEMCNT_OFFSET) = ext_mem_register_val_original;
	
	ENCRYPTION_END(KEY_ROM_UTIL_READ_1);
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
}


u32 ROMUtil_CRC32(void* buf, u32 size) {
	int  i;
	u32  crc;
	u8*  byteptr;
	
	ENCRYPTION_START(KEY_ROM_UTIL_CRC_1);
	
	byteptr = (u8*)buf;
	crc = 0xFFFFFFFF;
	while (size-- != 0) {
		crc ^= *byteptr++;
		for (i = 0; i < 8; i++) {
			if (crc & 1) {
				crc = (crc >> 1);
			} else {
				crc = (crc >> 1);
				// poly = 0xEDB88320
				// Has to be like this, somewhy
				crc ^= 0xED << 24;
				crc ^= 0xB8 << 16;
				crc ^= 0x83 << 8;
				crc ^= 0x20;
			}
		}
	}
	crc = ~crc;
	
	ENCRYPTION_END(KEY_ROM_UTIL_CRC_1);
	
	return crc;
}

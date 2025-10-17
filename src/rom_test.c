#include "rom_test.h"

#include "nitro_card.h"
#include "nitro_io_reg.h"
#include "nitro_os.h"
#include "primes.h"
#include "rom_util.h"

// Custom defs not provided by Nitro
#define REG_CARD_MASTER_CNT_OFFSET  (0x1A1)
#define REG_CARDCNT_OFFSET          (0x1A4)
#define REG_CARD_CMD_OFFSET         (0x1A8)
#define REG_CARD_DATA_OFFSET        (0x100010)

// Functions to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(void);
u32 ROMTest_IsGood(void);

#define ROM_BLOCK_SIZE  CARD_ROM_PAGE_SIZE


static inline void localReadROM(void* dest, u32 addr, s32 num_bytes) {
	// This function is executing an obfuscated manual cartridge ROM read.
	// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
	// 
	// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
	// 
	// Most/all convoluted syntax here must be that way to match.
	// Some of the comment documentation may be inaccurate here.
	
	u8          buffer[8];
	u8*         buf_ptr;
	REGType8v*  vnull;
	u32         register_base_1;
	REGType8v*  register_base_2;
	u32         card_ctrl_13;
	u32         addr_mask;
	s32         card_ctrl_cmd;
	s32         addr_offset;
	u16         ext_mem_register_val_original;
	u32         reading_addr;
	u32         output;
	int         i;
	
	// Alias for volatile null pointer
	vnull = (REGType8v*)NULL;
	
	// Alias for register base (0x04000000)
	register_base_1 = 1;
	register_base_1 <<= 26;
	
	// Another alias for register base (0x04000000)
	register_base_2 = (REGType8v*)HW_REG_BASE;
	
	// External memory control register (0x04000204)
	// Save value to rewrite later
	ext_mem_register_val_original = reg_MI_EXMEMCNT;
	
	// Set current processor accessing the gamecard bus to the ARM9 (clearing bit that is set for ARM7)
	reg_MI_EXMEMCNT &= ~REG_MI_EXMEMCNT_MP_MASK;
	
	// Obfuscated, create address 0x027FFE60
	// This is an address in the ROM header: port 0x040001A4 / setting for normal commands
	card_ctrl_13 = 5;
	
	// Obfuscated 0x1FF to mask address later
	addr_mask = (CARD_ROM_PAGE_SIZE + 4) - card_ctrl_13;
	
	// Creating address 0x027FFE60 cont.
	// If the system is in DSi mode, the address is changed to 0x02FFFE60
	card_ctrl_13 += *(REGType8v*)(register_base_1 + REG_A9ROM_OFFSET) & REG_SCFG_A9ROM_SEC_MASK;
	card_ctrl_13 <<= 18;
	card_ctrl_13 -= 13;
	card_ctrl_13 <<= 5;
	
	// Read port setting and set page read flags
	card_ctrl_cmd = (*(vs32*)card_ctrl_13 & ~CARD_COMMAND_MASK) | 
	                (CARD_COMMAND_PAGE | CARD_READ_MODE | CARD_START | CARD_RESET_HI);
	
	// Setting offset to round back to nearest 0x200-byte block.
	// E.G. if we want to read starting from 0x1208, we actually need to
	// request the block at 0x1200 and then ignore the first 8 bytes of the result.
	// This would set `addr_offset` to -8.
	addr_offset = 0 - (addr & addr_mask);
	
	// Wait for card to not be busy
	while (*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) & CARD_START) {
		continue;
	}
	
	// Write enable flag to card ROM and SPI control register
	*(REGType8v*)(register_base_1 + REG_CARD_MASTER_CNT_OFFSET) = CARDMST_ENABLE;
	
	// Read 8-byte command out from gamecard bus, write this back later
	buf_ptr = &buffer[0];
	for (i = 0; i < 8; i++) {
		*buf_ptr++ = *(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i);
	}
	
	reading_addr = addr + addr_offset;
	while (addr_offset < num_bytes) {
		// Read a 0x200-byte data block from ROM
		
		// Write 8-byte command to registers
		// B7XXXXXXXX000000 -> 0x200-byte encrypted data read from address XXXXXXXX
		register_base_2[REG_CARD_CMD_OFFSET + 0] = MROMOP_G_READ_PAGE >> 24;
		register_base_2[REG_CARD_CMD_OFFSET + 1] = reading_addr >> 24;
		register_base_2[REG_CARD_CMD_OFFSET + 2] = reading_addr >> 16;
		register_base_2[REG_CARD_CMD_OFFSET + 3] = reading_addr >> 8;
		register_base_2[REG_CARD_CMD_OFFSET + 4] = reading_addr;
		register_base_2[REG_CARD_CMD_OFFSET + 5] = 0x00;
		register_base_2[REG_CARD_CMD_OFFSET + 6] = 0x00;
		register_base_2[REG_CARD_CMD_OFFSET + 7] = 0x00;
		
		// Submit command
		*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) = card_ctrl_cmd;
		
		// Copy the output into the destination buffer, within the bounds of num_bytes
		// (Must read the output out of the I/O register regardless)
		do {
			if (*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) & CARD_DATA_READY) {
				output = *(REGType32v*)(register_base_1 + REG_CARD_DATA_OFFSET);
				if (addr_offset >= 0 && addr_offset < num_bytes) {
					*(u32*)(dest + addr_offset) = output;
				}
				
				addr_offset += 4;
			}
		} while (*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) & CARD_START);
		
		// Advance address to next block
		reading_addr += CARD_ROM_PAGE_SIZE;
	}
	
	// Done reading, restore everything how it was before
	
	// Write original command back to gamecard bus
	buf_ptr = &buffer[0];
	for (i = 0; i < 8; i++) {
		*(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i) = *buf_ptr++;
	}
	
	// Write original value back to to external memory control register
	*(REGType16v*)(register_base_1 + REG_EXMEMCNT_OFFSET) = ext_mem_register_val_original;
}


static inline u32 testROM(u32 pass_ret, u32 fail_ret) {
	// Extra CRC entry is required to match
	u32    crcs[7];
	u8     rom_buf[ROM_BLOCK_SIZE];
	void*  buf_ptr;
	int    i;
	u32    rom_addr;
	u16    lock_id;
	u32    ret;
	
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	buf_ptr = &rom_buf[0];
	
	for (i = 0; i < 3; i++) {
		// For below 8000h reads, use manual read
		localReadROM(buf_ptr, rom_addr, ROM_BLOCK_SIZE);
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// For above 8000h reads, use the SDK `CARD_ReadRom`
		// This function is patched over on flashcarts, which can be detected
		CARD_ReadRom(MI_DMA_NOT_USE, (void*)(rom_addr + 0x7000), &rom_buf[0], ROM_BLOCK_SIZE);
		crcs[i + 3] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		rom_addr += ROM_BLOCK_SIZE;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 3
	//   3 != 4 and 3 != 5
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			ret = fail_ret;
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		ret = fail_ret;
	} else {
		ret = pass_ret;
	}
	
EXIT:
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	return ret;
}


u32 ROMTest_IsBad(void) {
	return testROM(PRIME_FALSE, PRIME_TRUE) * PRIME_ROM_TEST_1;
}


u32 ROMTest_IsGood(void) {
	return testROM(PRIME_TRUE, PRIME_FALSE) * PRIME_ROM_TEST_2;
}

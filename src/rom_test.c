#include "rom_test.h"

#include "crash.h"
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

// Function to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(void* __unused);

#define ROM_BLOCK_SIZE  CARD_ROM_PAGE_SIZE

#define CARD_CMD_BYTE_NORMAL     (0x00)
#define CARD_CMD_BYTE_MALFORMED  (0x11)


static inline u32 getROMSize(void) {
	const CARDRomHeader*  header;
	u32                   rom_size;
	
	header = (const CARDRomHeader*)CARD_GetRomHeader();
	
	// This field is `x` for the size of the ROM as `128KB << x`
	// 128KB = 2^17, hence the addition of 17 before shifting
	rom_size = (1 << (header->device_size + 17));
	
	return rom_size;
}


static inline void localReadROM(void* dest, u32 addr, s32 num_bytes, u8 card_cmd_byte) {
	// This function is executing an obfuscated manual cartridge ROM read.
	// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
	// 
	// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
	// 
	// Most/all convoluted syntax here must be that way to match.
	// Some of the comment documentation may be inaccurate here.
	
	u8          buffer[8];
	REGType8v*  vnull;
	u32         register_base_1;
	REGType8v*  register_base_2;
	u32         card_ctrl_13;
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
	// If the system is in DSi mode, the address is changed to 0x02FFFE60
	card_ctrl_13 = 5;
	card_ctrl_13 += *(REGType8v*)(register_base_1 + REG_A9ROM_OFFSET) & REG_SCFG_A9ROM_SEC_MASK;
	card_ctrl_13 <<= 18;
	card_ctrl_13 -= 13;
	card_ctrl_13 <<= 5;
	
	// Read port setting and set page read flags
	card_ctrl_cmd = (*(vs32*)card_ctrl_13 & ~CARD_COMMAND_MASK) | 
	                (CARD_COMMAND_PAGE | CARD_READ_MODE | CARD_START | CARD_RESET_HI);
	
	// Calculate offset to round back to nearest 0x200-byte block.
	// E.G. if we want to read starting from 0x1208, we actually need to
	// request the block at 0x1200 and then ignore the first 8 bytes of the result.
	// This would set `addr_offset` to -8.
	addr_offset = 0 - (addr & (CARD_ROM_PAGE_SIZE - 1));
	
	// Wait for card to not be busy
	while (*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) & CARD_START) {
		continue;
	}
	
	// Write enable flag to card ROM and SPI control register
	*(REGType8v*)(register_base_1 + REG_CARD_MASTER_CNT_OFFSET) = CARDMST_ENABLE;
	
	// Read 8-byte command out from gamecard bus, write this back later
	for (i = 0; i < 8; i++) {
		buffer[i] = *(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i);
	}
	
	reading_addr = addr + addr_offset;
	while (addr_offset < num_bytes) {
		// Read a 0x200-byte data block from ROM
		
		// Write 8-byte command to registers
		// B7XXXXXXXX000000 -> 0x200-byte encrypted data read from address XXXXXXXX
		// Added option to change the first byte after the address to something else
		register_base_2[REG_CARD_CMD_OFFSET + 0] = MROMOP_G_READ_PAGE >> 24;
		register_base_2[REG_CARD_CMD_OFFSET + 1] = reading_addr >> 24;
		register_base_2[REG_CARD_CMD_OFFSET + 2] = reading_addr >> 16;
		register_base_2[REG_CARD_CMD_OFFSET + 3] = reading_addr >> 8;
		register_base_2[REG_CARD_CMD_OFFSET + 4] = reading_addr;
		register_base_2[REG_CARD_CMD_OFFSET + 5] = card_cmd_byte;
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
					*(u32*)((u32)dest + addr_offset) = output;
				}
				
				addr_offset += 4;
			}
		} while (*(REGType32v*)(register_base_1 + REG_CARDCNT_OFFSET) & CARD_START);
		
		// Advance address to next block
		reading_addr += CARD_ROM_PAGE_SIZE;
	}
	
	// Done reading, restore everything how it was before
	
	// Write original command back to gamecard bus
	for (i = 0; i < 8; i++) {
		*(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i) = buffer[i];
	}
	
	// Write original value back to to external memory control register
	*(REGType16v*)(register_base_1 + REG_EXMEMCNT_OFFSET) = ext_mem_register_val_original;
}


static inline u32 testROM(u32 pass_ret, u32 fail_ret) {
	u32  crcs[20];
	u8   rom_buf[ROM_BLOCK_SIZE];
	int  i;
	u32  rom_addr;
	u32  rom_addr_offset;
	u16  lock_id;
	
	rom_addr_offset = 0x7000;
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 6; i++) {
		// Offset the address by the size of the ROM, reading past its end
		// The ROM should mirror when this happens
		localReadROM(&rom_buf[0], rom_addr + getROMSize(), ROM_BLOCK_SIZE, CARD_CMD_BYTE_NORMAL);
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// For above 8000h reads, use the SDK `CARD_ReadRom`
		// This function is patched over on flashcarts, which can be detected
		CARD_ReadRom(MI_DMA_NOT_USE, (void*)(rom_addr + rom_addr_offset), &rom_buf[0], ROM_BLOCK_SIZE);
		crcs[i + 6] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Address changes as we loop.
		// 
		// Manual read:    i   addr
		//                ----------
		//                 0   1000*
		//                 1   1200*
		//                 2   1400*
		//                 3   1600*
		//                 4   A000
		//                 5   D000
		// 
		//   * = redirected to 8000
		// 
		// 
		// CARD_ReadRom:   i   addr
		//                ----------
		//                 6   8000
		//                 7   8200
		//                 8   8400
		//                 9   8600
		//                 10  A000
		//                 11  D000
		if (i < 3) {
			rom_addr += ROM_BLOCK_SIZE;
		} else if (i == 3) {
			rom_addr = 0xA000;
			rom_addr_offset = 0;
		} else if (i > 3) {
			rom_addr = (i * 0x1000) + 0x9000;
		}
	}
	
	rom_addr += 0x1E000;
	
	for (; i < 8; i++) {
		localReadROM(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE, CARD_CMD_BYTE_NORMAL);
		crcs[i + 6] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		CARD_ReadRom(MI_DMA_NOT_USE, (void*)rom_addr, &rom_buf[0], ROM_BLOCK_SIZE);
		crcs[i + 8] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Two more loops are executed:
		// 
		// Manual read:    i   addr
		//                ----------
		//                 12  2C000 
		//                 13  2D000
		// 
		// 
		// CARD_ReadRom:   i   addr
		//                ----------
		//                 14  2C000
		//                 15  2D000
		rom_addr += 0x1000;
	}
	
	rom_addr -= 0x1D000;
	
	for (; i < 10; i++) {
		// Set the byte following the address to 0x11
		// This is technically a malformed read command, but this is ignored in normal operation
		localReadROM(&rom_buf[0], rom_addr, ROM_BLOCK_SIZE, CARD_CMD_BYTE_MALFORMED);
		crcs[i + 8] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		CARD_ReadRom(MI_DMA_NOT_USE, (void*)rom_addr, &rom_buf[0], ROM_BLOCK_SIZE);
		crcs[i + 10] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Final two loops are executed:
		// 
		// Manual read:    i   addr
		//                ----------
		//                 16  11000 
		//                 17  12000
		// 
		// 
		// CARD_ReadRom:   i   addr
		//                ----------
		//                 18  11000
		//                 19  22000
		rom_addr += 0x1000;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE / 4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 6
	//   3 == 6 (not checked)
	//   4 == 10
	//   5 == 11
	//   12 == 14
	//   13 == 15
	//   16 == 18
	//   17 == 19
	//   6 != 7 and 6 != 8
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[6]) {
			DSProt_Crash(NULL, NULL);
			return fail_ret;
		}
	}
	
	if (crcs[6] == crcs[7] && crcs[6] == crcs[8]) {
		DSProt_Crash(NULL, NULL);
		return fail_ret;
	}
	
	if (!(crcs[4] == crcs[10] && crcs[5] == crcs[11])) {
		DSProt_Crash(NULL, NULL);
		return fail_ret;
	}
	
	if (!(crcs[12] == crcs[14] && crcs[13] == crcs[15])) {
		DSProt_Crash(NULL, NULL);
		return fail_ret;
	}
	
	if (!(crcs[16] == crcs[18] && crcs[17] == crcs[19])) {
		DSProt_Crash(NULL, NULL);
		return fail_ret;
	}
	
	return pass_ret;
}


u32 ROMTest_IsBad(void* __unused) {
	#pragma unused(__unused)
	
	return testROM(PRIME_FALSE * PRIME_ROM_TEST, PRIME_TRUE * PRIME_ROM_TEST);
}

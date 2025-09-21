#include "rom_test.h"

#include "dsprot_types.h"
#include "failure_codes.h"
#include "nitro_card.h"
#include "nitro_io_reg.h"
#include "nitro_os.h"
#include "primes.h"
#include "rom_util.h"

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

// Functions to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(DSProt_Ctx* ctx);
u32 ROMTest_IsGood(DSProt_Ctx* ctx);

#define ROM_BLOCK_SIZE  CARD_ROM_PAGE_SIZE


u32 ROMTest_IsBad(DSProt_Ctx* ctx) {
	u32  crcs[12];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u32  rom_addr_offset;
	u16  lock_id;
	int  i;
	
	rom_addr_offset = 0x7000;
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 6; i++) {
		// Cannot be an inlined function here
		{
			void* dest      = &rom_buf[0];
			u32   addr      = rom_addr;
			s32   num_bytes = ROM_BLOCK_SIZE;
			
			// This is executing an obfuscated manual cartridge ROM read.
			// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
			//
			// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
			//
			// Most/all convoluted syntax here must be that way to match.
			// Some of the comment documentation may be inaccurate here.
			u8          buffer[8];
			u32         register_base_1;
			REGType8v*  vnull;
			REGType8v*  register_base_2;
			s32         card_ctrl_cmd;
			u32         card_ctrl_13;
			u32         addr_mask;
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
			
			// Obfuscated 0x1FF to mask address
			addr_mask = (CARD_ROM_PAGE_SIZE + 4) - card_ctrl_13;
			addr_offset = addr & addr_mask;
			
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
			addr_offset = 0 - addr_offset;
			
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
			for (i = 0; i < 8; i++) {
				*(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i) = buffer[i];
			}
			
			// Write original value back to to external memory control register
			*(REGType16v*)(register_base_1 + REG_EXMEMCNT_OFFSET) = ext_mem_register_val_original;
		}
		
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// For above 8000h reads, use the SDK `CARDi_ReadRom`
		// This function is patched over on flashcarts, which can be detected
		CARDi_ReadRom(-1, (void*)(rom_addr + rom_addr_offset), &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+6] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
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
		// CARDi_ReadRom:  i   addr
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
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 6
	//   3 == 9 (not checked)
	//   4 == 10
	//   5 == 11
	//   6 != 7 and 6 != 8
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[6]) {
			ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
			ctx->failure_code = FAILURE_CODE_ROM_TEST_1;
			return PRIME_TRUE * PRIME_ROM_TEST_1;
		}
	}
	
	if (crcs[6] == crcs[7] && crcs[6] == crcs[8]) {
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		ctx->failure_code = FAILURE_CODE_ROM_TEST_2;
		return PRIME_TRUE * PRIME_ROM_TEST_1;
	}
	
	if (!(crcs[4] == crcs[10] && crcs[5] == crcs[11])) {
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		ctx->failure_code = FAILURE_CODE_ROM_TEST_3;
		return PRIME_TRUE * PRIME_ROM_TEST_1;
	}
	
	return PRIME_FALSE * PRIME_ROM_TEST_1;
}


u32 ROMTest_IsGood(DSProt_Ctx* ctx) {
	u32  crcs[12];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u32  rom_addr_offset;
	u16  lock_id;
	int  i;
	
	rom_addr_offset = 0x7000;
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 6; i++) {
		// Cannot be an inlined function here
		{
			void* dest      = &rom_buf[0];
			u32   addr      = rom_addr;
			s32   num_bytes = ROM_BLOCK_SIZE;
			
			// This is executing an obfuscated manual cartridge ROM read.
			// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
			//
			// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
			//
			// Most/all convoluted syntax here must be that way to match.
			// Some of the comment documentation may be inaccurate here.
			u8          buffer[8];
			u32         register_base_1;
			REGType8v*  vnull;
			REGType8v*  register_base_2;
			s32         card_ctrl_cmd;
			u32         card_ctrl_13;
			u32         addr_mask;
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
			
			// Obfuscated 0x1FF to mask address
			addr_mask = (CARD_ROM_PAGE_SIZE + 4) - card_ctrl_13;
			addr_offset = addr & addr_mask;
			
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
			addr_offset = 0 - addr_offset;
			
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
			for (i = 0; i < 8; i++) {
				*(vnull + HW_REG_BASE + REG_CARD_CMD_OFFSET + i) = buffer[i];
			}
			
			// Write original value back to to external memory control register
			*(REGType16v*)(register_base_1 + REG_EXMEMCNT_OFFSET) = ext_mem_register_val_original;
		}
		
		crcs[i] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// For above 8000h reads, use the SDK `CARDi_ReadRom`
		// This function is patched over on flashcarts, which can be detected
		CARDi_ReadRom(-1, (void*)(rom_addr + rom_addr_offset), &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+6] = ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
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
		// CARDi_ReadRom:  i   addr
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
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	// Erasing read buffer
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	// Checking the ROM reading results were as expected:
	//   0 == 1 == 2 == 6
	//   3 == 9 (not checked)
	//   4 == 10
	//   5 == 11
	//   6 != 7 and 6 != 8
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[6]) {
			ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
			ctx->failure_code = FAILURE_CODE_ROM_TEST_4;
			return PRIME_FALSE * PRIME_ROM_TEST_2;
		}
	}
	
	if (crcs[6] == crcs[7] && crcs[6] == crcs[8]) {
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		ctx->failure_code = FAILURE_CODE_ROM_TEST_3;
		return PRIME_FALSE * PRIME_ROM_TEST_2;
	}
	
	if (!(crcs[4] == crcs[10] && crcs[5] == crcs[11])) {
		ctx->failure_callback_return = ctx->failure_callback(ctx->callback_param_1, ctx->callback_param_2);
		ctx->failure_code = FAILURE_CODE_ROM_TEST_2;
		return PRIME_FALSE * PRIME_ROM_TEST_2;
	}
	
	return PRIME_TRUE * PRIME_ROM_TEST_2;
}

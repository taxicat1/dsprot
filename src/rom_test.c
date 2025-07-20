#include "rom_test.h"

#include "primes.h"
#include "rom_util.h"
#include "io_reg.h"

// Functions to be encrypted (cannot be called directly)
u32 ROMTest_IsBad(void);
u32 ROMTest_IsGood(void);

#define ROM_BLOCK_SIZE  (0x200)


u32 ROMTest_IsBad(void) {
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u16  lock_id;
	u32  ret;
	int  i;
	
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 3; i++) {
		// Use obfuscated read for below 0x8000
		// Cannot be an inlined function here
		{
			void* dest      = &rom_buf[0];
			u32   addr      = rom_addr;
			s32   num_bytes = ROM_BLOCK_SIZE;
			
			// This function is executing an obfuscated manual cartridge ROM read.
			// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
			//
			// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
			//
			// Most/all convoluted syntax here must be that way to match.
			// Some of the comment documentation may be inaccurate here.
			u8          buffer[8];
			u8*         bufptr;
			u32         register_base_1;
			REGType8v*  vnull;
			REGType8v*  register_base_2;
			s32         card_ctrl_cmd;
			u16         ext_mem_register_val_original;
			u32         card_ctrl_13;
			u32         addr_mask;
			s32         addr_offset;
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
			reg_MI_EXMEMCNT &= ~REG_MI_EXMEMCNT_MP_MASK;
			
			// Obfuscated, create address 0x027FFE60
			// This is an address in the .nds header: port 0x040001A4 / setting for normal commands
			card_ctrl_13 = 5;
			
			// Obfuscated 0x1FF to mask address
			addr_mask = 0x204 - card_ctrl_13;
			addr_offset = addr & addr_mask;
			
			// Creating address 0x027FFE60 cont.
			// This read is not a used location, should always read 0
			card_ctrl_13 += ((REGType8v*)register_base_1)[0x4000] & 1;
			card_ctrl_13 <<= 18;
			card_ctrl_13 -= 13;
			card_ctrl_13 <<= 5;
			
			// Read port setting
			card_ctrl_cmd = ((*(vs32*)card_ctrl_13) & ~0x07000000) | 0xA1000000;
			
			// Setting offset to round back to nearest 0x200-byte block.
			// E.G. if we want to read starting from 0x1208, we actually need to
			// request the block at 0x1200 and then ignore the first 8 bytes of the result.
			// This would set `addr_offset` to -8.
			addr_offset = 0 - addr_offset;
			
			// Wait for card to not be busy
			while (((REGType32v*)register_base_1)[0x1A4/4] & 0x80000000) { }
			
			// Writing to card ROM and SPI control register
			((REGType8v*)register_base_1)[0x1A1] = 0x80;
			
			// Obfuscated read 8-byte command out from gamecard bus, write this back later
			bufptr = &buffer[0];
			for (i = 0; i < 8; i++) {
				*bufptr++ = (vnull + HW_REG_BASE)[0x1A8+i];
			}
			
			reading_addr = addr + addr_offset;
			while (addr_offset < num_bytes) {
				// Read a 0x200-byte data block from ROM
				
				// Write 8-byte command to registers
				// B7XXXXXXXX000000 -> 0x200-byte encrypted data read from address XXXXXXXX
				register_base_2[0x1A8] = 0xB7;
				register_base_2[0x1A9] = reading_addr >> 24;
				register_base_2[0x1AA] = reading_addr >> 16;
				register_base_2[0x1AB] = reading_addr >> 8;
				register_base_2[0x1AC] = reading_addr;
				register_base_2[0x1AD] = 0x00;
				register_base_2[0x1AE] = 0x00;
				register_base_2[0x1AF] = 0x00;
				
				// Submit command
				((REGType32v*)register_base_1)[0x1A4/4] = card_ctrl_cmd;
				
				// Copy the output into the destination buffer, within the bounds of num_bytes
				// (Must read the output out of the I/O register regardless)
				do {
					if (((REGType32v*)register_base_1)[0x1A4/4] & 0x800000) {
						output = ((REGType32v*)(register_base_1 + 0x100000))[4];
						if (addr_offset >= 0 && addr_offset < num_bytes) {
							*(u32*)(dest + addr_offset) = output;
						}
						
						addr_offset += 4;
					}
				} while (((REGType32v*)register_base_1)[0x1A4/4] & 0x80000000);
				
				// Advance address to next block
				reading_addr += 0x200;
			}
			
			// Write 8-byte command back to gamecard bus
			bufptr = &buffer[0];
			for (i = 0; i < 8; i++) {
				(vnull + HW_REG_BASE)[0x1A8+i] = *bufptr++;
			}
			
			// Write original value back to to external memory control register
			((REGType16v*)register_base_1)[REG_EXMEMCNT_OFFSET/2] = ext_mem_register_val_original;
		}
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Use standard ROM reading function for above 0x8000
		CARDi_ReadRom(-1, (void*)rom_addr + 0x7000, &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+3] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		rom_addr += ROM_BLOCK_SIZE;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			ret = PRIME_TRUE;
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		ret = PRIME_TRUE;
	} else {
		ret = PRIME_FALSE;
	}
	
EXIT:
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	return ret * PRIME_ROM_TEST_1;
}


u32 ROMTest_IsGood(void) {
	// Extra CRC entry is required to match
	u32  crcs[7];
	u8   rom_buf[ROM_BLOCK_SIZE];
	u32  rom_addr;
	u16  lock_id;
	u32  ret;
	int  i;
	
	rom_addr = 0x1000;
	
	lock_id = OS_GetLockID();
	CARD_LockRom(lock_id);
	
	for (i = 0; i < 3; i++) {
		// Use obfuscated read for below 0x8000
		// Cannot be an inlined function here
		{
			void* dest      = &rom_buf[0];
			u32   addr      = rom_addr;
			s32   num_bytes = ROM_BLOCK_SIZE;
			
			// This function is executing an obfuscated manual cartridge ROM read.
			// Nitro SDK usually does this for you with CARD_ReadRom* and friends.
			//
			// https://problemkaputt.de/gbatek-ds-cartridge-protocol.htm
			//
			// Most/all convoluted syntax here must be that way to match.
			// Some of the comment documentation may be inaccurate here.
			u8          buffer[8];
			u8*         bufptr;
			u32         register_base_1;
			REGType8v*  vnull;
			REGType8v*  register_base_2;
			s32         card_ctrl_cmd;
			u16         ext_mem_register_val_original;
			u32         card_ctrl_13;
			u32         addr_mask;
			s32         addr_offset;
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
			reg_MI_EXMEMCNT &= ~REG_MI_EXMEMCNT_MP_MASK;
			
			// Obfuscated, create address 0x027FFE60
			// This is an address in the .nds header: port 0x040001A4 / setting for normal commands
			card_ctrl_13 = 5;
			
			// Obfuscated 0x1FF to mask address
			addr_mask = 0x204 - card_ctrl_13;
			addr_offset = addr & addr_mask;
			
			// Creating address 0x027FFE60 cont.
			// This read is not a used location, should always read 0
			card_ctrl_13 += ((REGType8v*)register_base_1)[0x4000] & 1;
			card_ctrl_13 <<= 18;
			card_ctrl_13 -= 13;
			card_ctrl_13 <<= 5;
			
			// Read port setting
			card_ctrl_cmd = ((*(vs32*)card_ctrl_13) & ~0x07000000) | 0xA1000000;
			
			// Setting offset to round back to nearest 0x200-byte block.
			// E.G. if we want to read starting from 0x1208, we actually need to
			// request the block at 0x1200 and then ignore the first 8 bytes of the result.
			// This would set `addr_offset` to -8.
			addr_offset = 0 - addr_offset;
			
			// Wait for card to not be busy
			while (((REGType32v*)register_base_1)[0x1A4/4] & 0x80000000) { }
			
			// Writing to card ROM and SPI control register
			((REGType8v*)register_base_1)[0x1A1] = 0x80;
			
			// Obfuscated read 8-byte command out from gamecard bus, write this back later
			bufptr = &buffer[0];
			for (i = 0; i < 8; i++) {
				*bufptr++ = (vnull + HW_REG_BASE)[0x1A8+i];
			}
			
			reading_addr = addr + addr_offset;
			while (addr_offset < num_bytes) {
				// Read a 0x200-byte data block from ROM
				
				// Write 8-byte command to registers
				// B7XXXXXXXX000000 -> 0x200-byte encrypted data read from address XXXXXXXX
				register_base_2[0x1A8] = 0xB7;
				register_base_2[0x1A9] = reading_addr >> 24;
				register_base_2[0x1AA] = reading_addr >> 16;
				register_base_2[0x1AB] = reading_addr >> 8;
				register_base_2[0x1AC] = reading_addr;
				register_base_2[0x1AD] = 0x00;
				register_base_2[0x1AE] = 0x00;
				register_base_2[0x1AF] = 0x00;
				
				// Submit command
				((REGType32v*)register_base_1)[0x1A4/4] = card_ctrl_cmd;
				
				// Copy the output into the destination buffer, within the bounds of num_bytes
				// (Must read the output out of the I/O register regardless)
				do {
					if (((REGType32v*)register_base_1)[0x1A4/4] & 0x800000) {
						output = ((REGType32v*)(register_base_1 + 0x100000))[4];
						if (addr_offset >= 0 && addr_offset < num_bytes) {
							*(u32*)(dest + addr_offset) = output;
						}
						
						addr_offset += 4;
					}
				} while (((REGType32v*)register_base_1)[0x1A4/4] & 0x80000000);
				
				// Advance address to next block
				reading_addr += 0x200;
			}
			
			// Write 8-byte command back to gamecard bus
			bufptr = &buffer[0];
			for (i = 0; i < 8; i++) {
				(vnull + HW_REG_BASE)[0x1A8+i] = *bufptr++;
			}
			
			// Write original value back to to external memory control register
			((REGType16v*)register_base_1)[REG_EXMEMCNT_OFFSET/2] = ext_mem_register_val_original;
		}
		crcs[i] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		// Use standard ROM reading function for above 0x8000
		CARDi_ReadRom(-1, (void*)rom_addr + 0x7000, &rom_buf[0], ROM_BLOCK_SIZE, NULL, NULL, FALSE);
		crcs[i+3] = RunEncrypted_ROMUtil_CRC32(&rom_buf[0], ROM_BLOCK_SIZE);
		
		rom_addr += ROM_BLOCK_SIZE;
	}
	
	CARD_UnlockRom(lock_id);
	OS_ReleaseLockID(lock_id);
	
	for (i = 0; i < 3; i++) {
		if (crcs[i] != crcs[3]) {
			ret = PRIME_FALSE;
			goto EXIT;
		}
	}
	
	if (crcs[3] == crcs[4] && crcs[3] == crcs[5]) {
		ret = PRIME_FALSE;
	} else {
		ret = PRIME_TRUE;
	}
	
EXIT:
	for (i = 0; i < ROM_BLOCK_SIZE/4; i++) {
		((u32*)&rom_buf[0])[i] = i;
	}
	
	return ret * PRIME_ROM_TEST_2;
}

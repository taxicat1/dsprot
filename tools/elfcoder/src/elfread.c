#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

#include "elf.h" // Copy included if not available already

#include "encoder.h"

typedef struct {
	FILE*       fhandle;
	char*       fname;
	Elf32_Ehdr  ex_header;
	Elf32_Shdr  symtbl_header;
	Elf32_Shdr  strtbl_header;
} ElfFile;

#define INDENT  "  "


// Nonfunctional on MinGW
#if 0
static int isSameFile(FILE* f1, FILE* f2) {
	struct stat stat1;
	struct stat stat2;
	
	fstat(fileno(f1), &stat1);
	fstat(fileno(f2), &stat2);
	
	return (stat1.st_dev == stat2.st_dev) && (stat1.st_ino == stat2.st_ino);
}
#endif


static void getSectionHeaderByIdx(ElfFile* elf, int idx, Elf32_Shdr* out_section_header) {
	fseek(elf->fhandle, elf->ex_header.e_shoff + (idx * elf->ex_header.e_shentsize), SEEK_SET);
	fread(out_section_header, sizeof(Elf32_Shdr), 1, elf->fhandle);
}


static void getSymbolByIdx(ElfFile* elf, int idx, Elf32_Sym* out_symbol) {
	fseek(elf->fhandle, elf->symtbl_header.sh_offset + (idx * elf->symtbl_header.sh_entsize), SEEK_SET);
	fread(out_symbol, sizeof(Elf32_Sym), 1, elf->fhandle);
}


static int symbolStringCompare(ElfFile* elf, int str_idx, const char* target_symbol) {
	fseek(elf->fhandle, elf->strtbl_header.sh_offset + str_idx, SEEK_SET);
	
	do {
		int diff = *target_symbol - fgetc(elf->fhandle);
		if (diff != 0) {
			return diff;
		}
	} while(*target_symbol++ != '\0');
	
	return 0;
}


static void quickStringTblPut(ElfFile* elf, int str_idx) {
	fseek(elf->fhandle, elf->strtbl_header.sh_offset + str_idx, SEEK_SET);
	
	int c;
	while ((c = fgetc(elf->fhandle)) != '\0') {
		putchar(c);
	}
}


static int getRelocationHeaderByTarget(ElfFile* elf, int target_idx, Elf32_Shdr* out_relocation_header) {
	for (int i = 0; i < elf->ex_header.e_shnum; i++) {
		if (i == target_idx) {
			continue;
		}
		
		getSectionHeaderByIdx(elf, i, out_relocation_header);
		if (out_relocation_header->sh_type == SHT_RELA && out_relocation_header->sh_info == target_idx) {
			return 1;
		}
	}
	
	memset(out_relocation_header, 0, sizeof(Elf32_Shdr));
	return 0;
}


static int ElfFile_Init(ElfFile* elf, char* fname) {
	elf->fname = fname;
	
	// Open file
	elf->fhandle = fopen(elf->fname, "rb+");
	if (elf->fhandle == NULL) {
		printf("Error: could not open input file: %s\n", elf->fname);
		return 1;
	}
	
	// Read elf header
	fread(&elf->ex_header, sizeof(Elf32_Ehdr), 1, elf->fhandle);
	
	// Check magic number
	if (memcmp(&elf->ex_header.e_ident, ELFMAG, SELFMAG) != 0) {
		printf("Error: invalid ELF file (wrong magic number): %s\n", elf->fname);
		return 1;
	}
	
	// Find symbol table
	int symtbl_found = 0;
	for (int header_idx = 0; header_idx != elf->ex_header.e_shnum; header_idx++) {
		Elf32_Shdr section_header;
		getSectionHeaderByIdx(elf, header_idx, &section_header);
		
		if (section_header.sh_type == SHT_SYMTAB) {
			symtbl_found = 1;
			elf->symtbl_header = section_header;
			
			// Get symbol table string table
			getSectionHeaderByIdx(elf, elf->symtbl_header.sh_link, &elf->strtbl_header);
			break;
		}
	}
	
	if (!symtbl_found) {
		printf("Error: invalid ELF file (no symbol table): %s\n", elf->fname);
		return 1;
	}
	
	return 0;
}


static void createRC4Key(uint32_t key_ins, uint8_t* outkey) {
	outkey[0] = outkey[4] = outkey[8]  = outkey[12] = key_ins & 0xff;
	outkey[1] = outkey[5] = outkey[9]  = outkey[13] = (key_ins >> 8) & 0xff;
	outkey[2] = outkey[6] = outkey[10] = outkey[14] = (key_ins >> 16) & 0xff;
	outkey[3] = outkey[7] = outkey[11] = outkey[15] = (key_ins >> 24) & 0xff;
	
	outkey[0]  ^= 0xff;
	outkey[15] ^= 0xff;
}


static int encodeInstructions(ElfFile* elf, int start_addr, int size, uint32_t key_ins, EncodingTask* task) {
	int num_ins = size / 4;
	fseek(elf->fhandle, start_addr, SEEK_SET);
	Instruction* ins_buffer = malloc(size);
	fread(ins_buffer, sizeof(Instruction), num_ins, elf->fhandle);
	
	RC4_Ctx rc4;
	uint8_t rc4key[RC4_KEY_SIZE];
	createRC4Key(key_ins, rc4key);
	RC4_Init(&rc4, rc4key);
	
	for (int i = 0; i < num_ins; i++) {
		if (task->encoding_type == ENC_DECODE) {
			Decode_Instruction(&ins_buffer[i], &rc4);
		} else {
			Encode_Instruction(&ins_buffer[i], &rc4);
		}
	}
	
	fseek(elf->fhandle, start_addr, SEEK_SET);
	fwrite(ins_buffer, sizeof(Instruction), num_ins, elf->fhandle);
	
	free(ins_buffer);
	
	return key_ins;
}


static int tryEncryptRanges(
	ElfFile* elf,
	Elf32_Rela* relocs,
	int len,
	int decryption_symbol_idx,
	int encryption_symbol_idx,
	int file_offset,
	EncodingTask* task
) {
	/*
		- Must start with decrypt
		- Must end with encrypt
		- Must alternate decrypt-encrypt-decrypt-encrypt...
		- Must be at least 32 bytes between decrypt and the following encrypt
		- Key must be the same between decrypt/encrypt (dec+12 == enc-16)
	*/
	
	if ((len % 2) != 0) {
		return 1;
	}
	
	int expected_next = decryption_symbol_idx;
	for (int i = 0; i < len; i++) {
		if (ELF32_R_SYM(relocs[i].r_info) != expected_next) {
			return 1;
		}
		
		if (expected_next == encryption_symbol_idx) {
			expected_next = decryption_symbol_idx;
		} else {
			expected_next = encryption_symbol_idx;
		}
	}
	
	for (int i = 0; i < len; i += 2) {
		Elf32_Rela dec_reloc = relocs[i];
		Elf32_Rela enc_reloc = relocs[i+1];
		
		if ((enc_reloc.r_offset - dec_reloc.r_offset) <= 32) {
			return 1;
		}
		
		int dec_key_offset = file_offset + dec_reloc.r_offset + 12;
		int enc_key_offset = file_offset + enc_reloc.r_offset - 16;
		
		uint32_t dec_key, enc_key;
		fseek(elf->fhandle, dec_key_offset, SEEK_SET);
		fread(&dec_key, sizeof(uint32_t), 1, elf->fhandle);
		
		fseek(elf->fhandle, enc_key_offset, SEEK_SET);
		fread(&enc_key, sizeof(uint32_t), 1, elf->fhandle);
		
		if (dec_key != enc_key) {
			return 1;
		}
		
		int start_addr = dec_key_offset + 4;
		int end_addr = enc_key_offset;
		int size = end_addr - start_addr;
		
		encodeInstructions(elf, start_addr, size, dec_key, task);
		
		if (task->verbose) {
			if (task->encoding_type == ENC_DECODE) {
				printf(INDENT INDENT "Decrypted +%x from %x with key %08x\n", size, start_addr, enc_key);
			} else {
				printf(INDENT INDENT "Encrypted +%x from %x with key %08x\n", size, start_addr, enc_key);
			}
		}
	}
	
	if (task->verbose) {
		printf("\n");
	}
	
	return 0;
}

static void sortRelocsByOffset(Elf32_Rela* relocs, int len) {
	// Nope, shut up, don't care, I'm doing this
	for (int i = 0; i < len-1; i++) {
		int minidx = i;
		for (int j = i+1; j < len; j++) {
			if (relocs[j].r_offset < relocs[minidx].r_offset) {
				minidx = j;
			}
		}
		
		if (i != minidx) {
			Elf32_Rela tmp;
			tmp = relocs[i];
			relocs[i] = relocs[minidx];
			relocs[minidx] = tmp;
		}
	}
}

static int tryEncryptSymbol(ElfFile* elf, const Elf32_Sym* symbol, int decryption_symbol_idx, int encryption_symbol_idx, EncodingTask* task) {
	Elf32_Shdr text_header;
	getSectionHeaderByIdx(elf, symbol->st_shndx, &text_header);
	int start_addr = text_header.sh_offset + symbol->st_value;
	
	Elf32_Shdr relocation_header;
	int rela_found = getRelocationHeaderByTarget(elf, symbol->st_shndx, &relocation_header);
	if (!rela_found) {
		return 0;
	}
	
	int crypt_reloc_max = 10;
	Elf32_Rela* crypt_relocs = calloc(crypt_reloc_max, sizeof(Elf32_Rela));
	int crypt_reloc_idx = 0;
	
	int num_relocs = relocation_header.sh_size / relocation_header.sh_entsize;
	for (int i = 0; i < num_relocs; i++) {
		Elf32_Rela reloc;
		int reloc_addr = relocation_header.sh_offset + (i * relocation_header.sh_entsize);
		fseek(elf->fhandle, reloc_addr, SEEK_SET);
		fread(&reloc, sizeof(Elf32_Rela), 1, elf->fhandle);
		
		if (
			(reloc.r_offset >= symbol->st_value) &&
			(reloc.r_offset < (symbol->st_value + symbol->st_size))
		) {
			if (
				ELF32_R_SYM(reloc.r_info) == decryption_symbol_idx || 
				ELF32_R_SYM(reloc.r_info) == encryption_symbol_idx
			) {
				crypt_relocs[crypt_reloc_idx] = reloc;
				crypt_reloc_idx++;
				if (crypt_reloc_idx == crypt_reloc_max) {
					crypt_reloc_max += 10;
					crypt_relocs = realloc(crypt_relocs, crypt_reloc_max * sizeof(Elf32_Rela));
				}
			}
		}
	}
	
	if (crypt_reloc_idx == 0) {
		free(crypt_relocs);
		return 0;
	}
	
	sortRelocsByOffset(crypt_relocs, crypt_reloc_idx);
	
	if (task->verbose) {
		printf(INDENT);
		quickStringTblPut(elf, symbol->st_name);
		printf(":\n");
	}
	
	if (tryEncryptRanges(
		elf,
		crypt_relocs,
		crypt_reloc_idx,
		decryption_symbol_idx,
		encryption_symbol_idx,
		start_addr,
		task) != 0
	) {
		if (!task->verbose) {
			printf("%s:\n", elf->fname);
			printf(INDENT);
			quickStringTblPut(elf, symbol->st_name);
			printf(":\n");
		}
		
		printf(INDENT INDENT "Error: invalid decryption/encryption ranges\n\n");
		free(crypt_relocs);
		return 1;
	}
	
	free(crypt_relocs);
	return 0;
}

int getDecryptionAndEncryptionSymbolIdxs(ElfFile* elf, int* out_decryption_symbol_idx, int* out_encryption_symbol_idx, EncodingTask* task) {
	int symbol_tbl_len = elf->symtbl_header.sh_size / elf->symtbl_header.sh_entsize;
	
	int decryption_symbol_idx = -1;
	int encryption_symbol_idx = -1;
	
	for (int symbol_tbl_idx = 0; symbol_tbl_idx < symbol_tbl_len; symbol_tbl_idx++) {
		Elf32_Sym symbol;
		getSymbolByIdx(elf, symbol_tbl_idx, &symbol);
		
		if (symbolStringCompare(elf, symbol.st_name, task->decryption_symbol) == 0) {
			decryption_symbol_idx = symbol_tbl_idx;
		} else if (symbolStringCompare(elf, symbol.st_name, task->encryption_symbol) == 0) {
			encryption_symbol_idx = symbol_tbl_idx;
		}
	}
	
	if (decryption_symbol_idx != -1 && encryption_symbol_idx != -1) {
		*out_decryption_symbol_idx = decryption_symbol_idx;
		*out_encryption_symbol_idx = encryption_symbol_idx;
		return 0;
	}
	
	return 1;
}

static int processElf(ElfFile* elf, EncodingTask* task) {
	int symbol_tbl_len = elf->symtbl_header.sh_size / elf->symtbl_header.sh_entsize;
	
	int decryption_symbol_idx;
	int encryption_symbol_idx;
	if (getDecryptionAndEncryptionSymbolIdxs(elf, &decryption_symbol_idx, &encryption_symbol_idx, task) != 0) {
		printf("Error: %s: could not find encryption/decryption functions in symbol table\n", elf->fname);
		return 1;
	}
	
	if (task->verbose) {
		printf("%s:\n", elf->fname);
		printf(INDENT "decryption/encryption symbols found @ %i/%i\n", decryption_symbol_idx, encryption_symbol_idx);
	}
	
	int ret_code = 0;
	
	for (int symbol_tbl_idx = 0; symbol_tbl_idx < symbol_tbl_len; symbol_tbl_idx++) {
		if (symbol_tbl_idx == decryption_symbol_idx || symbol_tbl_idx == encryption_symbol_idx) {
			continue;
		}
		
		Elf32_Sym symbol;
		getSymbolByIdx(elf, symbol_tbl_idx, &symbol);
		
		// Ignore external symbols and non-functions
		if (symbol.st_shndx == SHN_UNDEF || ELF32_ST_TYPE(symbol.st_info) != STT_FUNC) {
			continue;
		}
		
		ret_code += tryEncryptSymbol(elf, &symbol, decryption_symbol_idx, encryption_symbol_idx, task);
	}
	
	return ret_code;
}


static int processElfs(ElfFile* elfs, EncodingTask* task) {
	int ret = 0;
	
	// Iterate all elf files we have
	for (int elf_idx = 0; elfs[elf_idx].fhandle != NULL; elf_idx++) {
		ret += processElf(&elfs[elf_idx], task);
	}
	
	return ret;
}


int Elf_EncodeSymbols(EncodingTask* task) {
	int num_inputs = 0;
	while (task->inputs[num_inputs] != NULL) {
		num_inputs++;
	}
	
	if (num_inputs == 0) {
		return 0;
	}
	
	ElfFile* elfs = calloc(num_inputs + 1, sizeof(ElfFile));
	for (int elf_idx = 0; elf_idx < num_inputs; elf_idx++) {
		int error = ElfFile_Init(&elfs[elf_idx], task->inputs[elf_idx]);
		
#if 0
		// This just.. doesn't work. fstat() doesn't work.
		// Whatever, just don't input the same file multiple times
		if (!error) {
			for (int other_elf_idx = 0; other_elf_idx < elf_idx; other_elf_idx++) {
				if (isSameFile(elfs[elf_idx].fhandle, elfs[other_elf_idx].fhandle)) {
					printf("Error: duplicate input file: %s\n", elfs[elf_idx].fname);
					error = 1;
					break;
				}
			}
		}
#endif
		
		if (error) {
			free(elfs);
			return 1;
		}
	}
	
	// End-of-files signal
	elfs[num_inputs].fhandle = NULL;
	
	// Process all
	int ret_code = processElfs(elfs, task);
	
	free(elfs);
	
	return ret_code;
}

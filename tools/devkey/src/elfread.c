#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

#include "elf.h" // Copy included if not available already

#include "hash.h"
#include "keydata.h"

typedef struct {
	FILE*       fhandle;
	char*       fname;
	Elf32_Ehdr  ex_header;
	Elf32_Shdr  symtbl_header;
	Elf32_Shdr  strtbl_header;
} ElfFile;



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


static int doHashInstructions(ElfFile* elf, uint32_t start_addr, int size, KeyData* out_key) {
	int num_ins = size / 4;
	fseek(elf->fhandle, start_addr, SEEK_SET);
	uint32_t* ins_buffer = malloc(size);
	fread(ins_buffer, sizeof(uint32_t), num_ins, elf->fhandle);
	
	int target_opcode_1;
	int target_opcode_2;
	
	target_opcode_1 = 0xE8;
	target_opcode_2 = 0xE1;
	
	int last_idx = num_ins - 1;
	while (
		(ins_buffer[last_idx] >> 24) != target_opcode_1 &&
		(ins_buffer[last_idx] >> 24) != target_opcode_2
	) {
		last_idx--;
		
		if (last_idx < 0) {
			// Could not find target
			free(ins_buffer);
			return 1;
		}
	}
	
	num_ins = last_idx + 1;
	Hash_Instructions(ins_buffer, num_ins, out_key);
	free(ins_buffer);
	return 0;
}


static int hashSymbol(ElfFile* elf, const Elf32_Sym* symbol, char* symbol_name, KeyData* out_key) {
	int ret = 0;
	
	Elf32_Shdr text_header;
	getSectionHeaderByIdx(elf, symbol->st_shndx, &text_header);
	int start_addr = text_header.sh_offset + symbol->st_value;
	
	// Hash instructions of this function
	int error = doHashInstructions(elf, start_addr, symbol->st_size, out_key);
	if (error) {
		printf("%s (@ %04x): failed: could not find instruction range\n", symbol_name, symbol->st_value);
		return error;
	}
	
	return 0;
}


static int processElf(ElfFile* elf, char* target_symbol, KeyData* out_key) {
	// Iterate symbol table of this elf file
	int symbol_tbl_len = elf->symtbl_header.sh_size / elf->symtbl_header.sh_entsize;
	for (int symbol_tbl_idx = 0; symbol_tbl_idx < symbol_tbl_len; symbol_tbl_idx++) {
		Elf32_Sym symbol;
		getSymbolByIdx(elf, symbol_tbl_idx, &symbol);
		
		// Ignore external symbols and non-functions
		if (symbol.st_shndx == SHN_UNDEF || ELF32_ST_TYPE(symbol.st_info) != STT_FUNC) {
			continue;
		}
		
		if (symbolStringCompare(elf, symbol.st_name, target_symbol) != 0) {
			continue;
		}
		
		return hashSymbol(elf, &symbol, target_symbol, out_key);
	}
	
	printf("%s: not found in input file\n", target_symbol);
	return 1;
}


int Elf_DeriveKey(FuncHashTask* task) {
	ElfFile elf;
	int error = ElfFile_Init(&elf, task->input_fname);
	if (error) {
		return error;
	}
	
	KeyData key;
	
	error = processElf(&elf, task->target_symbol, &key);
	if (error) {
		return error;
	}
	
	error = KeyData_Write(&key, task->output_fname);
	if (error) {
		return error;
	}
	
	return 0;
}

#include <string.h>
#include <stdlib.h>

#include "asmwriter.h"

#define ASM_COMMON_INCLUDE  "asm_macro.inc"

char* default_prefix = "RunEncrypted_";


static ASMWriter_SymbolMeta* allocMetaArray(char** first_symbol) {
	int symbol_count = 0;
	while (*first_symbol++ != NULL) {
		symbol_count++;
	}
	
	if (symbol_count == 0) {
		return NULL;
	} else {
		return calloc(sizeof(ASMWriter_SymbolMeta), symbol_count);
	}
}


static int symbolIdxOf(ASMWriter_Ctx* asmw, char* target_symbol) {
	for (int symbol_idx = 0; asmw->symbols[symbol_idx] != NULL; symbol_idx++) {
		if (strcmp(target_symbol, asmw->symbols[symbol_idx]) == 0) {
			return symbol_idx;
		}
	}
	
	return -1;
}


static void writeAssembly(ASMWriter_Ctx* asmw, FILE* output) {
	fprintf(output,
		".include \"" ASM_COMMON_INCLUDE "\"\n"
		"\n"
	);
	
	for (int symbol_idx = 0; asmw->symbols[symbol_idx] != NULL; symbol_idx++) {
		fprintf(output,
			".public %s\n",
			asmw->symbols[symbol_idx]
		);
	}
	
	if (asmw->garbage != NULL) {
		fprintf(output,
			".public %s\n",
			asmw->garbage
		);
	}
	
	fprintf(output,
		"\n"
	);
	
	fprintf(output,
		"\t.text\n"
		"\t.balign 4, 0\n"
		"\n"
	);
	
	if (asmw->key_mode == MODE_KEYED) {
		for (int symbol_idx = 0; asmw->symbols[symbol_idx] != NULL; symbol_idx++) {
			fprintf(output,
				"\tarm_func_start %s%s\n"
				"%s%s:\n"
				"\trun_encrypted_func %s, 0x%x, 0x%x + 0x%x\n"
				"\tarm_func_end %s%s\n"
				"\n",
				asmw->wrapper_prefix, asmw->symbols[symbol_idx],
				asmw->wrapper_prefix, asmw->symbols[symbol_idx],
				asmw->symbols[symbol_idx], asmw->symbol_metadata[symbol_idx].size, asmw->key, asmw->symbol_metadata[symbol_idx].offset,
				asmw->wrapper_prefix, asmw->symbols[symbol_idx]
			);
		}
		
		if (asmw->garbage != NULL) {
			fprintf(output,
				"\tgarbage_ref %s\n"
				"\n",
				asmw->garbage
			);
		}
	} else {
		fprintf(output,
			"\tlocal_arm_func_start NitroStaticInit\n"
			"NitroStaticInit:\n"
			"\tdecode_following_func_table\n"
		);
		
		for (int symbol_idx = 0; asmw->symbols[symbol_idx] != NULL; symbol_idx++) {
			fprintf(output,
				"\tfunc_table_entry %s, 0x%x\n",
				asmw->symbols[symbol_idx],
				asmw->symbol_metadata[symbol_idx]
			);
		}
		
		fprintf(output,
			"\tfunc_table_end\n"
			"\tarm_func_end NitroStaticInit\n"
			"\n"
		);
		
		if (asmw->garbage != NULL) {
			fprintf(output,
				"\tgarbage_ref %s\n"
				"\n",
				asmw->garbage
			);
		}
		
		fprintf(output,
			"\t.section .sinit, 4\n"
			"\t.word NitroStaticInit\n"
			"\n"
		);
	}
}


void ASMWriter_Init(ASMWriter_Ctx* asmw, EncodingTask* task) {
	asmw->key            = task->key;
	asmw->key_mode       = task->key_mode;
	asmw->output_fname   = task->output_fname;
	asmw->symbols        = task->symbols;
	asmw->garbage        = task->garbage;
	asmw->valid          = 1;
	
	if (task->wrapper_prefix == NULL) {
		asmw->wrapper_prefix = default_prefix;
	} else {
		asmw->wrapper_prefix = task->wrapper_prefix;
	}
	
	if (asmw->output_fname == NULL) {
		asmw->symbol_metadata = NULL;
	} else {
		asmw->symbol_metadata = allocMetaArray(asmw->symbols);
	}
}


void ASMWriter_SetSymbolMetadata(ASMWriter_Ctx* asmw, char* symbol_name, int size, int offset) {
	if (asmw->valid && asmw->output_fname != NULL) {
		int idx = symbolIdxOf(asmw, symbol_name);
		if (idx == -1) {
			ASMWriter_SetInvalid(asmw);
		} else {
			asmw->symbol_metadata[idx].size   = size;
			asmw->symbol_metadata[idx].offset = offset;
		}
	}
}


void ASMWriter_SetInvalid(ASMWriter_Ctx* asmw) {
	asmw->valid = 0;
}


int ASMWriter_Finalize(ASMWriter_Ctx* asmw) {
	int ret_code = 0;
	
	if (asmw->output_fname != NULL) {
		if (asmw->valid) {
			FILE* output = fopen(asmw->output_fname, "w");
			if (output == NULL) {
				printf("Failed to output assembly: could not open output file: %s\n", asmw->output_fname);
				ret_code = 1;
			} else {
				writeAssembly(asmw, output);
			}
		} else {
			printf("Failed to output assembly: errors encountered in encoding\n");
			ret_code = 1;
		}
	}
	
	free(asmw->symbol_metadata);
	
	return ret_code;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "encoder.h"


static int isValidIdentifier(const char* str) {
	if (str == NULL) {
		return 0;
	}
	
	// Must start with [_a-zA-Z]
	if (
		str[0] != '_' &&
		(str[0] < 'a' || str[0] > 'z') &&
		(str[0] < 'A' || str[0] > 'Z')
	) {
		return 0;
	}
	
	// Subsequent characters must be [_a-zA-Z0-9]+
	for (int i = 1; str[i] != '\0'; i++) {
		if (
			str[i] != '_' &&
			(str[i] < 'a' || str[i] > 'z') &&
			(str[i] < 'A' || str[i] > 'Z') &&
			(str[i] < '0' || str[i] > '9')
		) {
			return 0;
		}
	}
	
	return 1;
}

static void printDescription(void) {
	printf(
		"Encode or decode ARM ELF files using built-in keys.                             \n"
	);
}

static void printUsage(const char* self_name) {
	printf(
		"Usage: %s <arguments>                                                           \n"
		"  -i, --input [file1, [file2, [ ... ]]]      List of input files to process.    \n"
		"  -e, --encode                               Encode the input files.            \n"
		"  -d, --decode                               Decode the input files.            \n"
		"  -s, --start [symbol]                       Symbol for the start of encryption.\n"
		"  -n, --end [symbol]                         Symbol for the end of encryption.  \n"
		"  -v, --verbose                              Print encoding progress.           \n",
		self_name
	);
}


static int argCompare(char* arg, char short_letter, char* long_str) {
	return (arg[1] == short_letter && arg[2] == '\0') ||
	       (strcmp(arg, long_str) == 0);
}


enum {
	AWAIT_INPUT_FILE,
	AWAIT_NONE
};

int ArgParse_CreateTask(EncodingTask* task, char** argv) {
	// Defaults
	task->inputs            = NULL;
	task->encryption_symbol = NULL;
	task->decryption_symbol = NULL;
	task->encoding_type     = ENC_INVALID;
	task->verbose           = 0;
	
	int arg_idx = 0;
	
	// No arguments?
	char* self_name = argv[arg_idx];
	if (self_name == NULL) {
		return 1;
	}
	
	arg_idx++;
	
	if (argv[arg_idx] == NULL) {
		printDescription();
		printf("\n");
		printUsage(self_name);
		return 1;
	}
	
	
	int max_files = 16;
	
	task->inputs = calloc(max_files, sizeof(FILE*));
	int file_idx = 0;
	
	int await_state = AWAIT_NONE;
	
	for (; argv[arg_idx] != NULL; arg_idx++) {
		char* curr_arg = argv[arg_idx];
		char* next_arg = argv[arg_idx+1];
		
		if (curr_arg[0] == '-') {
			await_state = AWAIT_NONE;
			
			if (argCompare(curr_arg, 'i', "--input")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no files provided\n", curr_arg);
					return 1;
				}
				
				await_state = AWAIT_INPUT_FILE;
			
			} else if (argCompare(curr_arg, 'e', "--encode")) {
				if (task->encoding_type != ENC_INVALID) {
					printf("Error: multiple operations provided\n");
					return 1;
				}
				
				task->encoding_type = ENC_ENCODE;
			
			} else if (argCompare(curr_arg, 'd', "--decode")) {
				if (task->encoding_type != ENC_INVALID) {
					printf("Error: multiple operations provided\n");
					return 1;
				}
				
				task->encoding_type = ENC_DECODE;
			
			} else if (argCompare(curr_arg, 'n', "--end")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no identifier provided\n", curr_arg);
					return 1;
				}
				
				if (task->encryption_symbol != NULL) {
					printf("Error: multiple encryption functions provided\n");
					return 1;
				}
				
				if (!isValidIdentifier(next_arg)) {
					printf("Error: invalid identifier: %s\n", next_arg);
					return 1;
				}
				
				task->encryption_symbol = next_arg;
				arg_idx++;
			
			} else if (argCompare(curr_arg, 's', "--start")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no identifier provided\n", curr_arg);
					return 1;
				}
				
				if (task->decryption_symbol != NULL) {
					printf("Error: multiple decryption functions provided\n");
					return 1;
				}
				
				if (!isValidIdentifier(next_arg)) {
					printf("Error: invalid identifier: %s\n", next_arg);
					return 1;
				}
				
				task->decryption_symbol = next_arg;
				arg_idx++;
			
			} else if (argCompare(curr_arg, 'v', "--verbose")) {
				task->verbose = 1;
			
			} else {
				printf("Unknown argument: %s\n\n", curr_arg);
				printUsage(self_name);
				return 1;
			}
		} else {
			switch (await_state) {
				case AWAIT_INPUT_FILE:
					// Maintain null terminator
					if ((file_idx + 1) == max_files) {
						max_files += 8;
						task->inputs = realloc(task->inputs, max_files * sizeof(char*));
					}
					
					// Don't check for duplicate input files here, since "foo.o" != "./foo.o" etc
					// Instead check later when we open each file
					
					task->inputs[file_idx] = curr_arg;
					file_idx++;
					task->inputs[file_idx] = NULL;
					break;
				
				default:
				case AWAIT_NONE:
					printf("Unknown argument: %s\n\n", curr_arg);
					printUsage(self_name);
					return 1;
			}
		}
	}
	
	
	if (file_idx == 0) {
		printf("Error: no input file(s) provided (-i)\n");
		return 1;
	}
	
	if (task->encoding_type == ENC_INVALID) {
		printf("Error: no encoding operation provided (-e/-d)\n");
		return 1;
	}
	
	if (task->decryption_symbol == NULL) {
		printf("Error: no encryption start function provided (-s)\n");
		return 1;
	}
	
	if (task->encryption_symbol == NULL) {
		printf("Error: no encryption end function provided (-n)\n");
		return 1;
	}
	
	return 0;
}


void ArgParse_DestroyTask(EncodingTask* task) {
	if (task != NULL) {
		free(task->inputs);
	}
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "hash.h"


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
		"Derive a key file from a function.                                              \n"
		"For DS Protect version 2.03 Instant.                                            \n"
	);
}


static void printUsage(const char* self_name) {
	printf(
		"Usage: %s <arguments>                                                           \n"
		"  -i, --input [file]                         Input file to process.             \n"
		"  -o, --output [outfile]                     Output key file to create.         \n"
		"  -f, --function [function]                  Function to hash to derive a key.  \n",
		self_name
	);
}


static int argCompare(char* arg, char short_letter, char* long_str) {
	return (arg[1] == short_letter && arg[2] == '\0') || 
	       (strcmp(arg, long_str) == 0);
}


int ArgParse_CreateTask(FuncHashTask* task, char** argv) {
	// Defaults
	task->input_fname   = NULL;
	task->output_fname  = NULL;
	task->target_symbol = NULL;
	
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
	
	for (; argv[arg_idx] != NULL; arg_idx++) {
		char* curr_arg = argv[arg_idx];
		char* next_arg = argv[arg_idx+1];
		
		if (curr_arg[0] == '-') {
			
			if (argCompare(curr_arg, 'i', "--input")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no output filename provided\n", curr_arg);
					return 1;
				}
				
				if (task->input_fname != NULL) {
					printf("Error: multiple output files provided\n");
					return 1;
				}
				
				task->input_fname = next_arg;
				arg_idx++;
			
			} else if (argCompare(curr_arg, 'o', "--output")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no output filename provided\n", curr_arg);
					return 1;
				}
				
				if (task->output_fname != NULL) {
					printf("Error: multiple output files provided\n");
					return 1;
				}
				
				task->output_fname = next_arg;
				arg_idx++;
			
			} else if (argCompare(curr_arg, 'f', "--function")) {
				if (next_arg == NULL || next_arg[0] == '-') {
					printf("Error: %s but no function provided\n", curr_arg);
					return 1;
				}
				
				if (task->target_symbol != NULL) {
					printf("Error: multiple output files provided\n");
					return 1;
				}
				
				if (!isValidIdentifier(next_arg)) {
					printf("Error: invalid identifier: %s\n", next_arg);
					return 1;
				}
				
				task->target_symbol = next_arg;
				arg_idx++;
			
			} else {
				printf("Unknown argument: %s\n\n", curr_arg);
				printUsage(self_name);
				return 1;
			}
		} else {
			printf("Unknown argument: %s\n\n", curr_arg);
			printUsage(self_name);
			return 1;
		}
	}
	
	
	if (task->input_fname == NULL) {
		printf("Error: no input file provided\n");
		return 1;
	}
	
	if (task->target_symbol == NULL) {
		printf("Error: no target function provided\n");
		return 1;
	}
	
	return 0;
}


void ArgParse_DestroyTask(FuncHashTask* task) {
}

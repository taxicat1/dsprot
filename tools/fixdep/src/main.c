#include <stdio.h>

/*
	All this does is replace all backslashes in the argv[1] file with forward slashes,
	unless they are escaping a line feed or carriage return. This is necessary because stupid MW 
	outputs file paths using backslashes, and Make only accepts forward slashes.
	This could easily just be a `sed` script, but this was honestly lazier
*/


int main(int argc, char* argv[]) {
	switch (argc) {
		case 0:
		case 1:
			printf("Error: no input file provided\n");
			return 1;
		
		case 2:
			break;
		
		default:
			printf("Warning: extra arguments ('%s' and later) ignored\n", argv[2]);
			break;
	}
	
	FILE* target = fopen(argv[1], "r+");
	if (target == NULL) {
		printf("Error: could not open input file: %s\n", argv[1]);
		return 1;
	}
	
	int ch;
	while ((ch = fgetc(target)) != EOF) {
		if (ch == '\\') {
			int next = fgetc(target);
			if (!(next == '\r' || next == '\n')) {
				fseek(target, -2, SEEK_CUR);
				fputc('/', target);
			}
		}
	}
	
	return 0;
}

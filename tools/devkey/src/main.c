#include "argparse.h"
#include "elfread.h"


int main(int argc, char *argv[]) {
	FuncHashTask task;
	int ret = ArgParse_CreateTask(&task, argv);
	if (ret == 0) {
		ret = Elf_DeriveKey(&task);
	}
	
	ArgParse_DestroyTask(&task);
	return ret;
}

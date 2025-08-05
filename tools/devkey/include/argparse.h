#ifndef ARGPARSE_H
#define ARGPARSE_H

#include "hash.h"

int ArgParse_CreateTask(FuncHashTask* task, char** argv);
void ArgParse_DestroyTask(FuncHashTask* task);

#endif

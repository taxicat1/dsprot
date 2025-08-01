#ifndef DSPROT_TYPES_H
#define DSPROT_TYPES_H

#include "types.h"

typedef void* (*DSProt_Callback)(void*, void*);

typedef struct {
	DSProt_Callback  success_callback;
	DSProt_Callback  failure_callback;
	void*            callback_param_1;
	void*            callback_param_2;
	void*            failure_callback_return;
	u32              failure_code;
} DSProt_Ctx;

#endif

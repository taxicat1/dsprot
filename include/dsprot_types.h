#ifndef DSPROT_TYPES_H
#define DSPROT_TYPES_H

#include "nitro_types.h"

typedef void* (*DSProt_Callback)(void*, void*);

typedef struct {
	DSProt_Callback  pass_callback;
	DSProt_Callback  fail_callback;
	void*            callback_param1;
	void*            callback_param2;
	void*            fail_callback_ret;
	u32              error_code;
} DSProt_Ctx;

#endif

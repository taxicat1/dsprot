#include "callback.h"

// Callback globals
// (stored in BSS, must be in their own file for proper BSS layout)
DSProt_Callback  DSProt_CallbackTable[2];
u32              DSProt_CallbackIndex;

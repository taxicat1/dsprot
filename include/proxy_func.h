#ifndef PROXY_FUNC_H
#define PROXY_FUNC_H

#include "encoding_constants.h"

// General access to proxy functions.
// Must follow pattern, example for `Foo_DoBar`:
// 
// Function prototype:
//     void Foo_DoBar(void);
// 
// Function pointer typedef:
//     typedef void (*FuncType_Foo_DoBar)(void);
// 
// Proxy for address:
//     const u32 Proxy_Foo_DoBar = ADDR_PLUS_ADDEND(Foo_DoBar, ENC_VAL_1);
// 
// Calling by proxy:
//     PROXY_FUNC(Foo_DoBar)();

#define PROXY_FUNC(func)  \
	((FuncType_ ## func)(Proxy_ ## func - ENC_VAL_1))

// The reason this system exists is to call functions without producing `bl` instructions
// that receive relocations. This then allows for functions that have no relocations in
// their instruction ranges, which is beneficial for fast and simple instruction encoding.
// 
// The proxy addresses are stored in rodata sections, loaded from the pool, and then
// called using a `blx` instruction. The addresses are obfuscated at rest using the standard
// addition of `ENC_VAL_1`.

#endif

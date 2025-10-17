# Building

0. Clone the repository. Requires:
	- Make
	- Cygwin/MSYS2/WSL/etc. if on Windows
	- Wine if not on Windows

1. If you do not have it already, download a copy of the [Metrowerks C compiler](https://github.com/pret/pmd-sky/raw/workflows/assets/mwccarm.zip) and extract its contents to `tools/`.

2. Enter the root of the repository in the command line and run `make`. You may also need to direct the compiler tools to `license.dat` if it asks for a license while building.

3. The output file will be `build/dsprot.a`.

## General integration

The built library file `dsprot.a` and provided header file `dsprot.h` may be used to integrate the library into any decompilation project that uses this version of DS Protect. The header is compatible with C, C++, and assembly.

`dsprot.a` will need to be included in the proper location in the project's `main.lsf`.

The variable `MWCCARM_DIR` can be used to specify an existing location of mwccarm, and `make install` with the `INSTALL_DIR` variable will copy the built library into `$(INSTALL_DIR)/lib/` after building.

For example, this could be a recipe in the Makefile of your decomp:

```makefile
libdsprot:
	$(MAKE) -C lib/dsprot install MWCCARM_DIR=$(TOOLS_DIR)/mwccarm INSTALL_DIR=$(BUILD_DIR)/$(buildname)
```

The exported functions are:
- `void DSProt_DecodeFunctions(void);`
- `void* DSProt_DetectFlashcartA(void* param1, void* param2);`
- `void* DSProt_DetectFlashcartB(void* param1, void* param2);`
- `void* DSProt_DetectEmulatorA(void* param1, void* param2);`
- `void* DSProt_DetectEmulatorB(void* param1, void* param2);`

Plus inline functions within the header:
- `void DSProt_RegisterCallbacks(DSProt_Callback pass_callback, DSProt_Callback fail_callback);`
- `void* DSProt_CheckAndDetectFlashcartA(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectFlashcartB(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectEmulatorA(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectEmulatorB(void* param1, void* param2);`

See [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) for more details on using these functions.

### Dependence on TWL SDK

These TWL SDK functions are required for linking. If your decomp does not include TWL SDK, they will need to be found and correctly named. This can be done by cross-referencing DS Protect as dumped from the game ROM with a disassembly of the compiled `dsprot.a`.

- `CARD_GetRomHeader`
- `CARD_LockRom`
- `CARD_UnlockRom`
- `CARDi_ReadRom`
- `OS_GetLockID`
- `OS_GetMacAddress`
- `OS_GetOwnerInfo`
- `OS_ReleaseLockID`

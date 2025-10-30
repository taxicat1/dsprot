# Building

0. Clone the repository. Requires:
	- Make
	- Cygwin/MSYS2/WSL/etc. if on Windows
	- Wine if not on Windows

1. If you do not have it already, download a copy of the [Metrowerks C compiler](https://github.com/pret/pmd-sky/raw/workflows/assets/mwccarm.zip) and extract its contents to `tools/`.

2. Enter the root of the repository in the command line and run `make`. You may also need to direct the compiler tools to `license.dat` if it asks for a license while building.

3. The output file will be `build/dsprot_instant.a`.

## General integration

The built library file `dsprot_instant.a` and provided header file `dsprot_instant.h` may be used to integrate the library into any decompilation project that uses this version of DS Protect. The header is compatible with C, C++, and assembly.

`dsprot_instant.a` will need to be included in the proper location in the project's `main.lsf`.

The variable `MWCCARM_DIR` can be used to specify an existing location of mwccarm, and `make install` with the `INSTALL_DIR` variable will copy the built library into `$(INSTALL_DIR)/lib/` after building.

For example, this could be a recipe in the Makefile of your decomp:

```makefile
libdsprotinstant:
	$(MAKE) -C lib/dsprotinstant install MWCCARM_DIR=$(TOOLS_DIR)/mwccarm INSTALL_DIR=$(BUILD_DIR)/$(buildname)
```

The exported functions are:
- `void* DSProt_Crash(void* __unused1, void* __unused2)`
- `void* DSProt_DetectAll(void* callback, void* param1, void* param2);`

Plus an inline function within the header:
- `inline void* DSProt_CheckAndDetectAll(void* callback, void* param1, void* param2);`

See [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) for more details on using these functions.

### Dependence on TWL SDK

These TWL SDK functions are required for linking. If your decomp does not include TWL SDK, they will need to be found and correctly named. This can be done by cross-referencing DS Protect as dumped from the game ROM with a disassembly of the compiled `dsprot_instant.a`.

- `CARD_LockRom`
- `CARD_UnlockRom`
- `CARDi_ReadRom`
- `MIi_CpuClear32`
- `OS_GetLockID`
- `OS_GetMacAddress`
- `OS_GetOwnerInfo`
- `OS_ReleaseLockID`
- `OS_Terminate`

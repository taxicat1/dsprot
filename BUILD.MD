# Building

0. Clone the repository. Requires:
	- Make
	- Cygwin/MSYS2/WSL/etc. if on Windows
	- Wine if not on Windows

1. If you do not have it already, download a copy of the [Metrowerks C compiler](https://github.com/pret/pmd-sky/raw/workflows/assets/mwccarm.zip) and extract version **DSi 1.2**. This should consist of these files:
	- ELFIO.dll
	- lmgr8c.dll
	- MSL_All-DLL80_x86.dll
	- mwasmarm.exe
	- mwccarm.exe
	- mwldarm.exe
	
	Place all of these files in `tools/mw/`. You may also need `license.dat` if it asks for a license.

2. Enter the root of the repository in the command line and run `make`.

3. The output file will be `build/dsprot.a`.

## General integration

The built library file `dsprot.a` and provided header file `dsprot.h` may be used to integrate the library into any decompilation project that uses this version of DS Protect. The header is compatible with C, C++, and assembly.

`dsprot.a` will need to be included in the proper location in the project's `main.lsf`.

The exported functions are:
- `u32 DSProt_DetectFlashcart(void* callback, void* param, u32 __unused);`
- `u32 DSProt_DetectNotFlashcart(void* callback, void* param, u32 __unused);`
- `u32 DSProt_DetectEmulator(void* callback, void* param, u32 __unused);`
- `u32 DSProt_DetectNotEmulator(void* callback, void* param, u32 __unused);`
- `u32 DSProt_DetectDummy(void* callback, void* param, u32 __unused);`
- `u32 DSProt_DetectNotDummy(void* callback, void* param, u32 __unused);`

Additionally, inline functions are provided by the header that emulate the old DS Protect callback API (many games will use these):
- `u32 DSProt_DetectFlashcart_Old(void* callback);`
- `u32 DSProt_DetectNotFlashcart_Old(void* callback);`
- `u32 DSProt_DetectEmulator_Old(void* callback);`
- `u32 DSProt_DetectNotEmulator_Old(void* callback);`
- `u32 DSProt_DetectDummy_Old(void* callback);`
- `u32 DSProt_DetectNotDummy_Old(void* callback);`

See [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) for more details on using these functions.

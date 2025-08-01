# Building

0. Clone the repository. Requires:
	- Make
	- Cygwin/MSYS2/WSL/etc. if on Windows
	- Wine if not on Windows

1. If you do not have it already, download a copy of the [Metrowerks C compiler](https://github.com/pret/pmd-sky/raw/workflows/assets/mwccarm.zip) and extract version **DSi 1.2p2**. This should consist of these files:
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
- `void DSProt_DecodeFunctions(void);`
- `void* DSProt_DetectFlashcartA(void* param1, void* param2);`
- `void* DSProt_DetectFlashcartB(void* param1, void* param2);`
- `void* DSProt_DetectEmulatorA(void* param1, void* param2);`
- `void* DSProt_DetectEmulatorB(void* param1, void* param2);`

Plus inline functions within the header:
- `void DSProt_RegisterCallbacks(DSProt_Callback success_callback, DSProt_Callback failure_callback);`
- `void* DSProt_CheckAndDetectFlashcartA(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectFlashcartB(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectEmulatorA(void* param1, void* param2);`
- `void* DSProt_CheckAndDetectEmulatorB(void* param1, void* param2);`

See [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) for more details on using these functions.

# Building

0. Clone the repository. Requires:
	- Make
	- Cygwin/MSYS2/WSL/etc. if on Windows
	- Wine if not on Windows

1. If you do not have it already, download a copy of the [Metrowerks C compiler](https://github.com/pret/pmd-sky/raw/workflows/assets/mwccarm.zip) and extract version **2.0 sp2p3**. This should consist of these files:
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
- `u32 DSProt_DetectFlashcart(void* callback);`
- `u32 DSProt_DetectNotFlashcart(void* callback);`
- `u32 DSProt_DetectEmulator(void* callback);`
- `u32 DSProt_DetectNotEmulator(void* callback);`
- `u32 DSProt_DetectDummy(void* callback);`
- `u32 DSProt_DetectNotDummy(void* callback);`

See [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) for more details on using these functions.

## pokeheartgold integration

1. Build this repository with `make pokeheartgold-compatible`. This will change the names of the exported library functions (`ov123_0225F430`, etc.).

2. Have built pokeheartgold `heartgold` or `soulsilver` at least once before such that `build/heartgold.us/` or `build/soulsilver.us/` exists.

3. Copy the file `build/dsprot_pokeheartgold.a` from this repository into the pokeheartgold directory `build/heartgold.us/lib/` and/or `build/soulsilver.us/lib/`.

4. Edit the file `main.lsf` in the root of pokeheartgold (currently line 1294, but may change), so the `OVY_123` section now reads:
	
	```
	Overlay OVY_123
	{
		After OVY_31
		Library dsprot_pokeheartgold.a
	}
	```

5. Edit the file `common.mk` in the root of pokeheartgold (currently line 233, but may change), and remove or comment out this line:
	
	```
	#   cd $(BUILD_DIR) && $(MOD123ENCRY) encry main OVY_123_enc.sbin 123 && mv OVY_123_enc.sbin OVY_123.sbin
	```
	
	This will prevent double-encrypting the library as the library file `dsprot_pokeheartgold.a` is already encrypted.

6. Build `heartgold` or `soulsilver` as you normally would.

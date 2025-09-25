# Core functionality

DS Protect has two methods of antipiracy detection:

1. System info check. It will check the DS's MAC address and the system owner information for either of these situations:
	- A MAC address of `00:00:00:00:00:00` (indicating an emulator that is not emulating a MAC address at all)
	- A MAC address of `00:09:BF:00:00:31`, coupled with an owner birthday of 1/1 and an empty owner name (indicating the use of No$GBA)

2. ROM read check. It will conduct twenty reads of the cartridge ROM, performing ten with a manual read (writing to I/O registers), and ten with the SDK's `CARD_ReadRom`.
	
	The manual reads will read these pages:
	- `0x1000 - 0x11FF` (mirrored)
	- `0x1200 - 0x13FF` (mirrored)
	- `0x1400 - 0x15FF` (mirrored)
	- `0x1600 - 0x17FF` (mirrored)
	- `0xA000 - 0xA1FF` (mirrored)
	- `0xD000 - 0xD1FF` (mirrored)
	- `0x2C000 - 0x2C1FF`
	- `0x2D000 - 0x2D1FF`
	- `0x11000 - 0x111FF` (malformed)
	- `0x12000 - 0x121FF` (malformed)
	
	("mirrored" meaning read starting from the end of the ROM, expecting it will loop back to the beginning)
	
	("malformed" meaning using the invalid read command `B7xxxxxxxx110000`, instead of the expected `B7xxxxxxxx000000`)
	
	`CARD_ReadRom` then reads these pages:
	- `0x8000 - 0x81FF`
	- `0x8200 - 0x83FF`
	- `0x8400 - 0x85FF`
	- `0x8600 - 0x87FF`
	- `0xA000 - 0xA1FF`
	- `0xD000 - 0xD1FF`
	- `0x2C000 - 0x2C1FF`
	- `0x2D000 - 0x2D1FF`
	- `0x11000 - 0x111FF`
	- `0x12000 - 0x121FF`
	
	Because a DS cartridge will redirect ROM reads below address `0x8000` to `0x8000 + (address & 0x1FF)`, the first three manual reads will all receive the same data. The other three reads, not receiving any redirection, will be different. A flashcart or low-effort reproduction cartridge meanwhile has no such behavior, and can read from any address. 
	
	Additionally, flashcarts will patch over `CARD_ReadRom` with their own code in order to properly read from their SD cards. If this was done, then reads using the SDK functions will return different data from the manual reads.
	
	If any mismatch in the expected read data is found, or if reads below address `0x8000` are not redirected properly, the test will report it is running on a flashcart.

Note that modern emulators, such as [MelonDS](https://github.com/melonDS-emu/melonDS) and [DeSmuME](https://github.com/TASEmulators/desmume), correctly emulate both a MAC address and the ROM reading behavior and are therefore undetected by this library. However, due to the way flashcarts work, they cannot evade being detected by the ROM read test. Instead they will, with varying degrees of aggressiveness, seek out DS Protect and patch over its tests, neutralizing them.

## Exported functions

Each of the two detection methods exists as two copies, which have been labeled *A* and *B*. Each copy is functionally identical, but uses different values for internal variables. In total, five main functions are exported:

- Initializer
- Detect flashcart A
- Detect flashcart B
- Detect emulator A
- Detect emulator B

Another function is provided as an inline in the header file:

- Register callbacks

Additionally, a standard wrapper for each of the four detection functions is provided as an inline in the header file.

Prior to calling any of the detection functions, it is required to call the initalization function (`DSProt_DecodeFunctions`). Otherwise, calling any detection function will immediately cause a crash. Next, it is required to register two callback functions (`DSProt_RegisterCallbacks`): a "success" callback, when no emulator or flashcart is detected, and a "failure" callback, when an emulator or flashcart *is* detected. These callback functions must be of the type `void* callback(void*, void*)`.

The detection functions take two parameters as arguments, each of type `void*`, which are passed along to the callback. The appropriate callback will be run based on the results of the detection. The return value of the detection function is the return value of the callback.

## Obfuscation

The code has multiple layers of obfuscation present. Many of the core functions are written in convoluted ways intended to deter reverse engineering, and/or encrypted and accessible only through special decryption wrappers. Decryption wrappers will decrypt the function, run it with the specified arguments, re-encrypt the function, and return. This is designed such that the raw code of the function spends as little time in RAM as possible.

Other functions are encoded using an unkeyed encoding scheme. These functions are decoded upon calling the initializer function (`DSProt_DecodeFunctions`), and remain decoded for as long as they remain in RAM. This is seemingly designed to deter reading dumps of the ROM.

Typically, a file will have some selected functions encrypted, then decryption wrappers are created for those functions, then those decryption wrappers are encoded, and included in the table to decode upon being loaded. Some functions are encoded directly without encryption, and other functions remain in plain code.

Values and references used throughout the file, such as sizes, keys, and function pointers, are often obfuscated by having other values added to them while they are at rest. Booleans are represented by multiples of different prime numbers to obscure their value.

For technical details on the encoding and obfuscation, see [ENCODING.MD](./ENCODING.MD).

## Integrity

Before running any of the core check functions, it also conducts an integrity check of their decryption wrappers. It checks the first 16 bytes (4 instructions) of the code of the function against its own hardcoded record, and if it mismatches, it will automatically report that a flashcart or emulator was detected.

The wrapper provided in the header file also conducts its own integrity check. This is so attempting to bypass integrity checks via ROM patching will require tracking down and patching every single place the wrapper was inlined.

## Dummy data

As a final trick, the library also includes 24 bytes of data designed to appear as instructions, but which are actually dummy garbage data. A reference to this data is held elsewhere to prevent it from being stripped out during linking, but it is not read from, written to, nor executed at any point.

## Note on language

The majority of the library is written in C, but the decryption wrappers, decoder initializers, and another helper snippet are written in assembly. For details about this, see [ASSEMBLY.MD](./ASSEMBLY.MD).

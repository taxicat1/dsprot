# Core functionality

DS Protect has two methods of antipiracy detection:

1. System info check. It will check the DS's MAC address and the system owner information for either of these situations:
	- A MAC address of `00:00:00:00:00:00` (indicating an emulator that is not emulating a MAC address at all)
	- A MAC address of `00:09:BF:00:00:31`, coupled with an owner birthday of 1/1 and an empty owner name (indicating the use of No$GBA)

2. ROM read check. It will conduct six reads of the cartridge ROM at these locations:
	- `0x0000 - 0x01FF`
	- `0x0200 - 0x03FF`
	- `0x0400 - 0x05FF`
	- `0x8000 - 0x81FF`
	- `0x8200 - 0x83FF`
	- `0x8400 - 0x85FF`
	
	Because a DS cartridge will redirect ROM reads below address `0x8000` to `0x8000 + (address & 0x1FF)`, the first four reads will all receive the same data. The last two reads, not receiving any redirection, will be different. A flashcart or low-effort reproduction cartridge meanwhile has no such behavior, and can read from any address. If the expected read pattern is not matched (`1 == 2 == 3 == 4` and `4 != 5 != 6`) it will report it is running on a flashcart.

3. Additionally, there is a third "dummy" method which does not actually do any antipiracy detection. This is apparently purely to confuse reverse engineering.

Note that modern emulators, such as [MelonDS](https://github.com/melonDS-emu/melonDS) and [DeSmuME](https://github.com/TASEmulators/desmume), correctly emulate both a MAC address and the ROM reading behavior and are therefore undetected by this library. Some flashcarts do correctly emulate the ROM reading behavior, but many still sold today do not.

## Exported functions

Each of the three methods exists as two copies, which are identical except for reversed return values. That is, there are six functions in total with these purposes:

- Detect flashcart
- Detect not flashcart
- Detect emulator
- Detect not emulator
- Detect dummy (always fails)
- Detect not dummy (always succeeds)

Each of these functions takes as argument an optional callback function, which will be run if the target detection succeeds. Meaning, `DetectFlashcart(callback)` will run the callback function only if a flashcart is detected. `DetectNotFlashcart(callback)` will inversely run the callback function only if a flashcart is *not* detected. They will also return `1` if the target detection succeeded, and `0` if it did not, regardless of whether a callback function was supplied.

## Obfuscation

The code has multiple layers of obfuscation present. Many of the core functions are written in convoluted ways intended to deter reverse engineering, and/or have ranges of their instructions encrypted. At the start of the range, it will call a decryption routine to decrypt the instructions ahead. At the end of the range, it will call an encryption routine to re-encrypt them.

For technical details on the encryption, see [ENCODING.MD](./ENCODING.MD).

## Note on language

The majority of the library is written in C, but the decryption range boundaries are written in assembly. For details about this, see [ASSEMBLY.MD](./ASSEMBLY.MD).

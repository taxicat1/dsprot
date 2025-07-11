# Encoding and Obfuscation

## Values, references, and Booleans

Frequently throughout the library, values and references are obfuscated until their time of use.

For literal values, the value is obfuscated as:

```c
value + &BSS + 0x1600
```

where `&BSS` is the address of the start of the `.bss` region of library (where uninitialized data is stored). This obfuscation is likely intended to make values, such as a size of 140 bytes, appear to actually be addresses which point to some unknown location.

For references, the value is obfuscated as:

```c
reference + 0x1600
```

This is likely simply to obscure the actual value of the reference.

Booleans, rather than use `0` or `1`, instead obsfuscate the value using different prime numbers. `TRUE` is represented as any multiple of 251, while `FALSE` is any multiple of 241. Each function that would normally return a Boolean will instead return some other prime number multiplied by one of these. Branches based on that resulting value are conducted using modulus operations. This is intended to confuse memory debugging.

## Function encoding and encrypting

Used extensively by the library is the following function encoding scheme. It is designed to not fully scramble the instructions into apparent random noise, but rather to distort them into other, valid instructions such that a reverse engineer may not even realize they were encoded.

There are two types of function encoding: unkeyed and keyed (encryption).

Unkeyed encoding is decoded using a static initializer, which is run automatically as soon as the overlay is loaded. Therefore, for almost all of the time the library is loaded into RAM, the unkeyed encoding is already removed.

Keyed encoding, by contrast, is only removed immediately before the function is called, via a decryption wrapper function. Immediately after the function returns, it is re-encrypted using a new modified key. This new key is then written back into the decryption wrapper.

The included tool `elfcoder` is capable of both encoding and decoding, keyed and unkeyed, to this specification, as well as outputting an assembly file containing either the decryption wrappers or the static initializer decoder.

### Background

ARM instructions are 32 bits wide. This version of the library does not support Thumb.

When encoding and decoding, the most significant byte is treated separately from the three least-significant bytes, which are treated together as a single 24-bit unsigned integer.

As an example, the instruction:

```
08 50 80 E0    (add r5, r0, r8)
```

Would have a most significant byte of `0xE0`, and three least-significant bytes of `0x805008`.

The following instruction classification system, shared by both keyed and unkeyed encoding, will determine the exact nature of encoding the instruction will receive. The classification is based on the most significant byte of the instruction:

- If the most significant byte is `0xFA` or `0xFB`, it is a **type-1 instruction**. No valid instructions will match this.

- If the least significant nybble of the most significant byte is `0xB`, it is a **type-2 instruction**. This will match all branch and link (`bl`) instructions.

- If the least significant nybble of the most significant byte is `0xA`, it is a **type-3 instruction**. This will match all branch without link (`b`) instructions.

- If none of the other conditions matched, it is a **type-0 instruction**. This will match all instructions which are not branches, and therefore the majority of instructions.

The size of the function body as reported by the ELF symbol table is not the size used for encoding. Data at the foot of the instructions is left plain. To do this, the end of the function is scanned backwards for instructions that resemble `pop` or `bx`, and the first instance of this is demarcated as the end of the function. This is done during the original encoding processing stage, and the length of the function that was encoded is written into the decryption wrappers or decoding initializer (with obfuscation as discussed previously).

### Unkeyed encoding

Unkeyed encoding uses a rolling value here known as `xorval` which acts a state value. It is 32 bits wide. It is used to encode each instruction, and then is updated using the resulting encoded instruction. The purpose of this is to run the encoding in a sort of modified cipher feedback mode, such that modifying an encoded instruction (as one attempting to create a patch that disables DS Protect may be doing) will cause all subsequent instructions to decode incorrectly, likely resulting in a crash when the instructions are executed.

Before encoding begins, `xorval` is initialized to a value of `0xF0618C46`.

For a **type-0** instruction:

- The entire instruction is exclusive-ored by `xorval`.

- `xorval` is then updated by exclusive-oring it by `x ^ (x >> 8)`, where `x` is the *original instruction* before it was updated in the previous step.

- `xorval` is truncated to 24 bits by bitwise-anding it with `0x00FFFFFF`.

For both a **type-1** and **type-2** instruction:

- `xorval` is updated by exclusive-oring it with the most significant byte of the instruction (`instruction >> 24`).

- `xorval` is truncated to 24 bits by bitwise-anding it with `0x00FFFFFF`.

- The most significant byte of the instruction is exclusive-ored by `0x01`.

- The three least significant bytes are incremented by `0x582`.

- A relocation for this instruction has its addend incremented by `0x1600` (and subtraction by 8 removed).

For a **type-3** instruction:

- The entire encoding procedure for a type-0 instruction is performed.

- Afterwards, the most significant byte of the instruction is exclusive-ored by `0x01`.

Note that, after encoding, a type-2 instruction becomes a type-3 instruction, and vice versa. This is due to flipping the branch link bit, which will change the instruction from a `b` to a `bl` and vice versa.

Type-0 and type-1 instructions will both remain so after encoding. This is fine for type-0 instructions, as their encoding procedure is its own inverse. However, type-1 instructions will not decode properly; and this may be intentional or an oversight as the upper byte of `0xFA` / `0xFB` would never appear in typical ARM instructions, nor appear as a result of encoding any typical ARM instructions.

Decoding applies the reverse procedure based on the new instruction type:

For a **type-0** instruction:

- The entire instruction is exclusive-ored by `xorval`.

- `xorval` is then updated by exclusive-oring it by `x ^ (x >> 8)`, where `x` is the instruction *after* it was updated in the previous step.

- `xorval` is truncated to 24 bits by bitwise-anding it with `0x00FFFFFF`.

For both a **type-1** and **type-3** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The three least significant bytes are decremented by `0x582`.

- `xorval` is updated by exclusive-oring it with the most significant byte of the instruction  (`instruction >> 24`).

- `xorval` is truncated to 24 bits by bitwise-anding it with `0x00FFFFFF`.

For a **type-2** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The entire decoding procedure for a type-0 instruction is performed.


### Keyed encoding

A modified version of the RC4 stream cipher algorithm is used to generate pseudorandom bytes for keyed encoding.

Among the modifications, the RC4 state has been modified to include an additional variable alongside its typical `i` and `j`, here referred to as `RC4.x`. This variable is modified by the instructions that are being encoded, and is used in the RC4 byte generation to modify the output. This aims to have a similar goal as `xorval` in unkeyed encoding of running the cipher in a modified CFB mode, preventing encoded instructions from being changed without altering the decoding of all subsequent instructions. See the RC4 section below for specific details.

For a **type-0** instruction:

- The most significant byte is left unmodified.

- The three least significant bytes are split apart:
	- The least significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the encoded byte from the previous step.
	- The second-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the encoded byte from the previous step.
	- The third-least-significant byte is substituted via an [S-box](https://en.wikipedia.org/wiki/S-box). However, this S-box is very weak: `S[i] = i ⊕ 0xFF`. It is unknown why this was implemented using an S-box instead of simply exclusive-oring the value `0xFF` directly.
	- `RC4.x` is updated to be `(RC4.x * c) - d`, where `c` is the third-least-significant byte and `d` is the most significant byte.

For a **type-1** and **type-2** instruction:

- The most significant byte of the instruction is exclusive-ored by `0x01`.

- `RC4.x` is incremented by the most significant byte of the instruction (`instruction >> 24`).

- The three least significant bytes are incremented by `0x582`.

- A relocation for this instruction has its addend incremented by `0x1600` (and subtraction by 8 removed).

For a **type-3** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The entire encoding procedure for a type-0 instruction is performed.

Identically to unkeyed encoding, this process leaves type-0 and type-1 instructions as they are, meanwhile type-2 instructions become type-3 instructions and vice versa.

Decoding is simply performing the operations in reverse:

For a **type-0** instruction:

- The most significant byte is left unmodified.

- The three least significant bytes are split apart:
	- The least significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the byte from the previous step *before* it was updated by exclusive-oring.
	- The second-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the byte from the previous step *before* it was updated by exclusive-oring.
	- `RC4.x` is updated to be `(RC4.x * c) - d`, where `c` is the third-least-significant byte and `d` is the most significant byte.
	- The third-least-significant byte is substituted via the same S-box as in the encoding procedure (it is its own inverse).

For a **type-1** and **type-3** instruction:

- `RC4.x` is incremented by the most significant byte of the instruction (`instruction >> 24`).

- The most significant byte of the instruction is exclusive-ored by `0x01`.

- The three least significant bytes are decremented by `0x582`.

For a **type-2** instruction:

- The entire encoding procedure for a type-0 instruction is performed.

- The most significant byte is exclusive-ored by `0x01`.

### Encoding to instructions vs relocations

Note the association between the two values `0x1600` and `0x582`. When encoding, the addition of `0x1600` may be applied to the instruction directly, or to the relocation for that instruction. When the relocation is encoded this way and then applied to the instruction, the offset of `0x1600` bytes is converted into a offset of *instructions*, effectively dividing it by 4. ARM branches, like the ARM PC, are also always offset by 2: a branch of 0 (`EB000000`) is a jump forward by 8 bytes or 2 instructions (`bl #8`). So, when an addition of `0x1600` is applied from the relocation into the instruction, it is divided by 4 and then incremented by 2, resulting in an addition of `0x582` to the instruction.

Therefore, if the encoding procedure added `0x1600` to the *relocation*, the decoding procedure needs to subtract `0x582` from the instruction.

Meanwhile, if the encoding procedure added `0x1600` to the *instruction*, the decoding procedure needs to (obviously) subtract `0x1600` from the instruction.

*(In my opinion the smarter way to do this would have been to encode the relocation by incrementing it by `(0x1600 - 2) * 4 = 0x57F8`, such that the resulting instruction would be incremented by `0x1600` and could then be decoded normally)*

### Encoding and linking

The encoding process has been specifically designed such that most instructions are encoded via exclusive-or, but linked branches are encoded using addition of a constant. The purpose of this is so the encoding can persist through linking.

For example, a function like this:

```c
void foo(void) {
    bar();
}
```

Might generate:

```
EB000000    bl  8     R_ARM_PC24:  bar-0x8
E12FFF1E    bx  lr
```

The resulting encoded instructions would then be:

```
EA000582    b   4880    R_ARM_PC24:  bar+0x1600
114E73B3    strhne r7, [lr, #-0x33]
```

Where, as discussed in the previous section, incrementing the relocation by `0x1600` will increment the instruction by `0x582`.

Therefore, after the reference is linked and the relocation is applied, the branch destination can still be correctly decoded by subtracting `0x582`.

In hindsight this is obvious: in order to be able to encode, then link, then decode, the encoding/decoding procedure must be associative with linking. Linking uses addition modulo 2^24, and therefore encoding must also use addition modulo 2^24.

## RC4

*See the [Wikipedia article on RC4](https://en.wikipedia.org/wiki/RC4) for background information on this algorithm.*

RC4 is initialized anew for each function that is being encoded, and bytes are generated by it as the instructions are encoded from top to bottom.

The authors have made two bizarre modifications:

- During key scheduling, rather than counting the array `S` index `i` up from 0 to 255, it instead counts down from 255 to 0. Key indexing still starts at 0 and increments upwards normally.

- The new state variable `RC4.x` is included:
	
	- This variable is 32 bits wide, but in practice, only 8 bits are used.
	- At initialization, it is set to the value `0xAA`.
	- During byte generation, prior to doing anything else, The state variables `i` and `j` are both incremented by `x`.

The key size is always 128 bits.

### Key generation

The 128-bit RC4 key is derived from a 16-bit seed key, together with the size in bytes to be encrypted. This seed key is actually declared as 32 bits wide, however, in all instances, only 16-bit values are defined for it.

Four 32-bit values are generated as such:

```
expanded_key[0] := seed_key ⊕ size
expanded_key[1] := (seed_key <<< 8) ⊕ size
expanded_key[2] := (seed_key <<< 16) ⊕ size
expanded_key[3] := (seed_key <<< 24) ⊕ size
```

Where `⊕` represents exclusive-or and `<<<` represents a 32-bit bitwise left rotation.

The expanded key buffer is then treated as a little-endian array of 16 bytes, which makes up the resulting 128-bit key.

For example, a seed key of `0x946F` and a size of `0x8C` would create the key:

```
E3 94 00 00 8C 6F 94 00 8C 00 6F 94 18 00 00 6F
```

This key would then produce the RC4 keystream (ignoring outside updates to `x`):

```
B6 03 59 09 01 73 29 BD 19 4A 69 BF FC 00 E4 FC 89 1B 61 88 70 E1 66 5E 0E 15 FB ED 36 77 22 AB ...
```

### Key changing

After each time a function is decrypted to be run, it is then re-encrypted using a new seed key. This new seed key is derived from the previous seed key:

```
new_seed_key = old_seed_key + (obfuscated_function_address >> 20) modulo 2^32
```

Where `obfuscated_function_address` is the function address of the target function that is to be encrypted, obfuscated by incrementation by `0x1600`, as described in the above reference obfuscation description.

Note most addresses are of the form `0x02XXXXXX`, which after a right shift of 20 bits would become `0x02X`, creating only a small actual change to the seed key.

This newly modified seed key is expanded into a 128-bit RC4 key as normal. It is also saved as the seed key (after obfuscating it via incrementing by `&BSS + 0x1600`) to be used for the next decryption of the function.

For example, if the library is conducting a ROM read test, it will perform 6 calls to the decryption wrapper function `RunEncrypted_ROMUtil_Read()`, which will change the key 6 times in total. If the original seed key is `0xC20D`, and the address and size of the inner `ROMUtil_Read()` is `0x02300000` + `0x14C`, then the subsequent seed keys and expanded keys will be:

```
C230    7C C3 00 00 4C 31 C2 00 4C 01 30 C2 8E 01 00 30
C253    1F C3 00 00 4C 52 C2 00 4C 01 53 C2 8E 01 00 53
C276    3A C3 00 00 4C 77 C2 00 4C 01 76 C2 8E 01 00 76
C299    D5 C3 00 00 4C 98 C2 00 4C 01 99 C2 8E 01 00 99
C2BC    F0 C3 00 00 4C BD C2 00 4C 01 BC C2 8E 01 00 BC
C2DF    93 C3 00 00 4C DE C2 00 4C 01 DF C2 8E 01 00 DF
...                           ...
```

# Encoding and Obfuscation

## Values, references, and Booleans

Frequently throughout the library, values and references are obfuscated until their time of use.

For literal values, the value is obfuscated as:

```c
value + &BSS + 0x2200
```

where `&BSS` is an address in the `.bss` region of library (where uninitialized data is stored). This obfuscation is likely intended to make values, such as a size of 140 bytes, appear to actually be addresses which point to some unknown location.

For references, the value is obfuscated as:

```c
reference + 0x2200
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

ARM instructions are 32 bits wide. The library will not work if compiled in Thumb.

When encrypting and decrypting, the most significant byte is treated separately from the three least-significant bytes, which are treated together as a single 24-bit unsigned integer.

As an example, the instruction:

```
08 50 80 E0    (add r5, r0, r8)
```

Would have a most significant byte of `0xE0`, and three least-significant bytes of `0x805008`.

The following instruction classification system, shared by both keyed and unkeyed encoding, will determine the exact nature of encoding the instruction will receive. The classification is based on the most significant byte of the instruction:

- If the most significant byte is `0xFA` or `0xFB`, it is a **type-1 instruction**. This will match `blx` immediate instructions, of which there are none, but the linker may convert some `bl` instructions at link time.

- If the least significant nybble of the most significant byte is `0xB`, it is a **type-2 instruction**. This will match all branch and link (`bl`) instructions.

- If the least significant nybble of the most significant byte is `0xA`, it is a **type-3 instruction**. This will match all branch without link (`b`) instructions.

- If none of the other conditions matched, it is a **type-0 instruction**. This will match all instructions which are not branches, and therefore the majority of instructions.

The size of the function body as reported by the ELF symbol table is not the size used for encoding. Data at the foot of the instructions is left plain. To do this, the end of the function is scanned backwards for instructions that resemble `pop` or `bx`, and the first instance of this is demarcated as the end of the function. This is done during the original encoding processing stage, and the length of the function that was encoded is written into the decryption wrappers or decoding initializer (with obfuscation as discussed previously).

### Unkeyed encoding

Unkeyed encoding uses a rolling value here known as `xorval` which acts a state value. It is 32 bits wide. It is used to encode each instruction, and then is updated using the resulting encoded instruction. The purpose of this is to run the encoding in a sort of modified cipher feedback mode, such that modifying an encoded instruction (as one attempting to create a patch that disables DS Protect may be doing) will cause all subsequent instructions to decode incorrectly, likely resulting in a crash when the instructions are executed.

Before encoding begins, `xorval` is initialized to a value of `0x7FEC9DF1`.

Each instruction is encoded as follows:

- The entire instruction is exclusive-ored by `xorval`.

- `xorval` is then updated by exclusive-oring it by `x - (x >> 8)`, where `x` is the *original instruction* before it was updated in the previous step.

Decoding applies the reverse procedure:

- The entire instruction is exclusive-ored by `xorval`.

- `xorval` is then updated by exclusive-oring it by `x - (x >> 8)`, where `x` is the instruction *after* it was updated in the previous step.


### Keyed encoding

A modified version of the RC4 stream cipher algorithm is used to generate pseudorandom bytes for keyed encoding.

Among the modifications, the RC4 state has been modified to include an additional variable alongside its typical `i` and `j`, here referred to as `RC4.x`. This variable is modified by the instructions that are being encoded, and is used in the RC4 byte generation to modify the output. This aims to have a similar goal as `xorval` in unkeyed encoding of running the cipher in a modified CFB mode, preventing encoded instructions from being changed without altering the decoding of all subsequent instructions. See the RC4 section below for specific details.

During encoding, another variable denoted as `prev_opcode` is maintained, which is used to encode or decode the most significant byte of the instructions. This byte is, in effect, encoded completely independently from the others; it must be decoded first in order to properly categorize the instruction, and correspondingly must be encoded last, after the rest of the instruction has been encoded. At the start of the encoding/decoding procedure, `prev_opcode` is initialized to `0x00`.

For a **type-0** instruction:

- The most significant byte is left unmodified.

- The three least significant bytes are split apart:
	- The least significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the encoded byte from the previous step.
	- The second-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the encoded byte from the previous step.
	- The third-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the encoded byte from the previous step.

For a **type-2** instruction:

- The most significant byte of the instruction is exclusive-ored by `0x01`.

- The three least significant bytes are incremented by `0x882`.

- A relocation for this instruction has its addend incremented by `0x2200` (and subtraction by 8 removed).

For a **type-1** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The entire encoding procedure for a type-2 instruction is performed.

For a **type-3** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The entire encoding procedure for a type-0 instruction is performed.

After the instruction has been encoded according to its type, the most significant byte is encoded by incrementing it by `prev_opcode`. Afterwards, `prev_opcode` is updated to be this newly encoded byte.

Subsequently, `RC4.x` is updated by subtracting `prev_opcode` from it.

This process leaves type-0 and type-1 instructions as they are, meanwhile type-2 instructions become type-3 instructions and vice versa.

Decoding is simply performing the operations in reverse:

Prior to categorizing the instruction, the most significant byte is updated by decrementing it by `prev_opcode`. Then, `prev_opcode` is updated to be the byte of the instruction *before* it was updated.

For a **type-0** instruction:

- The most significant byte is left unmodified.

- The three least significant bytes are split apart:
	- The least significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the byte from the previous step *before* it was encoded.
	- The second-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the byte from the previous step *before* it was encoded.
	- The third-least-significant byte is exclusive-ored by a byte from RC4.
	- `RC4.x` is updated to be the byte from the previous step *before* it was encoded.

- `RC4.x` is updated by subtracting the most significant byte from it.

For a **type-3** instruction:

- `RC4.x` is incremented by the most significant byte of the instruction (`instruction >> 24`).

- The most significant byte of the instruction is exclusive-ored by `0x01`.

- The three least significant bytes are decremented by `0x882`.

For a **type-1** instruction:

- The most significant byte is exclusive-ored by `0x01`.

- The entire encoding procedure for a type-3 instruction is performed.
 
For a **type-2** instruction:

- The entire encoding procedure for a type-0 instruction is performed.

- The most significant byte is exclusive-ored by `0x01`.

Subsequently, `RC4.x` is updated by subtracting `prev_opcode` from it.

### Encoding to instructions vs relocations

Note the association between the two values `0x2200` and `0x882`. When encoding, the addition of `0x2200` may be applied to the instruction directly, or to the relocation for that instruction. When the relocation is encoded this way and then applied to the instruction, the offset of `0x2200` bytes is converted into a offset of *instructions*, effectively dividing it by 4. ARM branches, like the ARM PC, are also always offset by 2: a branch of 0 (`EB000000`) is a jump forward by 8 bytes or 2 instructions (`bl #8`). So, when an addition of `0x2200` is applied from the relocation into the instruction, it is divided by 4 and then incremented by 2, resulting in an addition of `0x882` to the instruction.

Therefore, if the encoding procedure added `0x2200` to the *relocation*, the decoding procedure needs to subtract `0x882` from the instruction.

Meanwhile, if the encoding procedure added `0x2200` to the *instruction*, the decoding procedure needs to (obviously) subtract `0x2200` from the instruction.

### Encoding and linking

The *keyed* encoding process has been specifically designed such that most instructions are encoded via exclusive-or, but linked branches are encoded using addition of a constant. The purpose of this is so the encoding can persist through linking.

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

The resulting encrypted instructions might then be (depending upon key and function size):

```
EA000882    b   4112    R_ARM_PC24:  bar+0x2200
E1A3B7E2    <undefined instruction>
```

Where, as discussed in the previous section, incrementing the relocation by `0x2200` will increment the instruction by `0x882`.

Therefore, after the reference is linked and the relocation is applied, the branch destination can still be correctly decoded by subtracting `0x882`.

In hindsight this is obvious: in order to be able to encode, then link, then decode, the encoding/decoding procedure must be associative with linking. Linking uses addition modulo 2^24, and therefore encoding must also use addition modulo 2^24.

Note that the *unkeyed* encoding procedure has no such accommodation. Instead, functions that receive unkeyed encoding do not use function calls at any point. Instead, they load function pointers which have been stored in `.rodata` sections and call those.

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

### Key derivation

The 128-bit RC4 key is derived from a 32-bit checksum, together with the size in bytes to be encrypted. This checksum is derived on-the-fly from another function, `Encryptor_DecryptionWrapperFragment` AKA the "body" of the decryption wrapper.

This algorithm is used to compute the checksum:

```
break input into an array of 32-bit little-endian words (ARM instructions)

checksum := 0
word_idx := 0

for i := number of words down to 0:
	word := input[word_idx]
	
	if the most significant byte of word is not 0xEA or 0xEB:
		checksum := checksum ⊕ (word >>> 17)
		checksum := checksum + (word >>> 28)
		checksum := checksum ⊕ (word >>> i)
	end if
	
	word_idx := word_idx + 1

end for

output checksum
```

Where `⊕` represents 32-bit exclusive-or, `+` represents addition modulo 2^32, and `>>>` represents a 32-bit bitwise right rotation.

Note that last operation in the update loop; it is a rotation based on the iterator value. This value starts at the total number of instructions, and is equal to 1 on the final instruction. This is opposite the input processing order, which begins with the first word and ends with the last.

The included tool `devkey` is able to hash functions to this specification. The correct checksum value for this version is `0x89EDE4EA`.

To generate the RC4 key, four 32-bit values are generated as such, using the generated checksum and size of the target function:

```
expanded_key[0] := checksum ⊕ size
expanded_key[1] := (checksum <<< 8) ⊕ size
expanded_key[2] := (checksum <<< 16) ⊕ size
expanded_key[3] := (checksum <<< 24) ⊕ size
```

Where `<<<` represents a 32-bit bitwise left rotation.

The expanded key buffer is then treated as a little-endian array of 16 bytes, which makes up the resulting 128-bit key.

For example, a size of `0x8C` would create the key:

```
66 E4 ED 89 05 EA E4 ED 61 89 EA E4 68 ED 89 EA
```

This key would then produce the RC4 keystream (ignoring outside updates to `x`):

```
DD 9C 85 E6 F0 07 D1 9C 16 E1 29 A5 F7 0E 4F B4 14 AF 00 95 F1 E3 BA 3E 7C F5 A7 B2 1C 89 30 5D ...
```

Although there is a procedure to generate a new key and store it into the encryption wrapper data structure, this key is never used.

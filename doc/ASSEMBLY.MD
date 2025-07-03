# Assembly functions

Decryption wrappers, decoding static initializers, and the helper function to clear the data and instruction cache are all written at least partially in assembly. This can be proven. All other functions in the library may or may not be written partially or wholly in assembly, but they all may be decompiled to some C code which matches, and therefore can be assumed to have originally been written in C.

## Decryption wrappers

Decryption wrappers come in two pieces. First, the main "body" universal decryption wrapper fragment, shared by all decryption wrappers:

```asm
	arm_func_start Encryptor_DecryptionWrapperFragment
Encryptor_DecryptionWrapperFragment:
	stmfd  sp!, {r0-r3}
	str    r10, [ip, #0x10]
	mov    r10, ip
	str    lr, [r10]
	ldmib  r10, {r0-r2}
	bl     Encryptor_DecryptFunction    ; Function decryption routine
	mov    ip, r0
	ldmia  sp!, {r0-r3}
	blx    ip                           ; Call decrypted function
	stmdb  sp!, {r4}
	mov    r4, r0
	ldmib  r10, {r0-r2}
	bl     Encryptor_EncryptFunction    ; Function re-encryption routine
	str    r0, [r10, #0x4]
	mov    r0, r4
	ldmia  sp!, {r4}
	ldr    lr, [r10]
	str    sp, [r10]
	ldr    r10, [r10, #0x10]
	bx     lr
	arm_func_end Encryptor_DecryptionWrapperFragment
```

Second, the "head" function that sets up the `ip` register before calling the universal wrapper:

```asm
	arm_func_start RunEncrypted_ROMUtil_CRC32
RunEncrypted_ROMUtil_CRC32:
	orr    ip, pc, pc
	ands   ip, ip, ip
	moveq  ip, #0
	addne  ip, ip, #0x1C
	ldr    ip, [ip, #0x14]
	sub    ip, ip, #0x1600
	stmfd  sp!, {ip}        ; Setting up jump to Encryptor_DecryptionWrapperFragment
	orr    ip, pc, pc       ; Loading data structure below into `ip`
	ldmfd  sp!, {pc}
	.word  BSS + 0x1        ; Storage space
	.word  0xC20D           ; Encryption key
	.word  ROMUtil_CRC32    ; Function to decrypt-run-encrypt
	.word  0x90             ; Function size
	.word  0                ; Storage space
	.word  Encryptor_DecryptionWrapperFragment
	arm_func_end RunEncrypted_ROMUtil_CRC32
```

(Data obfuscation as described in [ENCODING.MD](./ENCODING.MD) has been removed for clarity)

Each encrypted function has a wrapper function which houses the data structure and calls the universal decryption routine.

All decryption wrappers are identical, save for different values at the foot: the address of the function, the number of bytes to decrypt/re-encrypt, and the key to use.

There are three giveaways that these are originally assembly:
- The "body" function is a seamless universal wrapper function. The registers `r0` through `r3` and the stack pointer are all preserved going into the inner function call, meaning this wrapper will wrap any inner function regardless of its arguments. This is impossible in C: functions that accept some fixed format of arguments will need specific wrappers sharing those arguments (or specific handling of the argument size and order), and functions which accept variable arguments such as `printf(char*, ...)` cannot be wrapped at all, and must have a varargs version of the function instead (`vprintf(char*, va_list)`).
- The "head" function accesses `pc` to store into another register, and the "body" function accesses `lr` to store into a memory location. This is impossible in vanilla C. Some compilers support `__builtin_return_address()`, `__current_pc()`, or other similar intrinsics to do this, but mwccarm does not.
- The "head" function stores a data structure in instructional memory, and passes a pointer to it along to the "body" function where it is read from and written to. C would never, ever do this: it would store the data in the instructional memory, then load the data into registers and push it onto the stack, and then finally pass a stack pointer through to the body routine. Alternatively, it could store the function table in a `.data` or `.rodata` region and pass a pointer to that.

For more documentation on how these functions work, see inline comments in `src/encryptor.c` and `include/asm_macro.inc`.

## Decoding initializers

Decoding initializers take the form:

```asm
	local_arm_func_start NitroStaticInit
NitroStaticInit:
	orr   r0, pc, #0x0
	adds  r0, r0, #0x4
	bne   Encryptor_DecodeFunctionTable
	.word RC4_Init,                        0x84   ; (Function address, size) data pairs
	.word RC4_InitSBox,                    0x30
	.word RC4_EncryptInstructions,         0x118
	.word RC4_DecryptInstructions,         0x184
	.word RC4_InitAndEncryptInstructions,  0x58
	.word RC4_InitAndDecryptInstructions,  0x58
	.word RC4_Byte,                        0x58
	.word 0, 0                                    ; End-of-data (0, 0)
	arm_func_end NitroStaticInit
```

(Data obfuscation as described in [ENCODING.MD](./ENCODING.MD) has been removed for clarity)

This has two giveaways that it is assembly:
- Similar to the "head" decryption wrapper function, it moves `pc` into another register to manipulate its value, rather than perform a PC-relative load.
- Identically to the decryption wrapper head, the function table data structure is stored in the pool of instructional memory, and a pointer to this region is passed into the decoding routine. Again, C would never do this.


## `clearDataAndInstructionCache` helper function

This is a function that, as the name suggests, clears the caches for instructions and data after a function has been encoded/decoded/encrypted/decrypted so the relevant data will be reloaded from RAM.

This is typically accomplished using the Nitro SDK functions `DC_FlushRange` and `IC_InvalidateRange`. However, DS Protect has combined both of those functions and inlined them together.

The function is of the form:

```asm
	arm_func_start clearDataAndInstructionCache
clearDataAndInstructionCache:
	add  r1, r1, r0
	mov  ip, #0
	bic  r0, r0, #31
@1:
	mcr  p15, 0, r0, c7, c5, 1
	mcr  p15, 0, ip, c7, c10, 4
	mcr  p15, 0, r0, c7, c14, 1
	add  r0, r0, #32
	cmp  r0, r1
	blt  @1
	bx   lr
	arm_func_end clearDataAndInstructionCache
```

The original Nitro implementation is in assembly using extremely similar instructions. The presence of the `mcr` instruction at all, indicating an instruction to interop with the coprocessor, would not be output by any C.

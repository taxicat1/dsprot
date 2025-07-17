# Inline assembly

Encryption and decryption range declarations are written in inline assembly. This can be proven. All other functions in the library may or may not be written partially or wholly in assembly, but they all may be decompiled to some C code which matches, and therefore can be assumed to have originally been written in C.

The ranges declarations take the form:

```asm
    ; ENCRYPTION_START(enc_key)
    push   {r0-r7}
    mov    r0, pc
    add    r0, r0, #16
    bl     Encryptor_StartRange
    pop    {r0-r7}
    b      +8
    .word  0xEB000000 + enc_key
```

```asm
    ; ENCRYPTION_END(enc_key)
    b      +8
    .word  0xEB000000 + enc_key
    push   {r0}
    mov    r0, pc
    sub    r0, r0, #20
    bl     Encryptor_EndRange
    pop    {r0}
```

These are three giveaways these are assembly:

- They use the same register manipulations at all of their appearances, running `push` and `pop` immediately before and after the inner function call. C would not do this, all `push`/`pop` instructions would be at the very start of the function or immediately before returning. The range end macro is even partially incorrect in its register management: it does not push `r1-r3` onto the stack, even though they would be clobbered by the call to `Encryptor_EndRange`.
- Data (the key in this case) is stored mid-instructions, and the routine's execution jumps over it. C would store the data at the bottom of the function and use a PC-relative load to get it.
- They access `pc` to pass as an argument to the instruction encryption and decryption routines. This is impossible in vanilla C. Some compilers support `__current_pc()` or other similar intrinsics to do this, but mwccarm does not.

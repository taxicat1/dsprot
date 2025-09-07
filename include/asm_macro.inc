#pragma once
#include "encoding_constants.h"

	.macro arm_func_start name
	.balign 4, 0
	.global \name
	.type \name, @function
	.arm
	.endm

	.macro local_arm_func_start name
	.balign 4, 0
	.type \name, @function
	.arm
	.endm

	.macro arm_func_end name
	.size \name, .-\name
	.endm


	.public BSS
	.public Encryptor_DecryptionWrapperFragment

	.macro run_encrypted_func func, length, key, hashed_instructions
	orr      ip, pc, pc                 ; Copy `pc` out
	ands     ip, ip, ip                 ; Checking if `pc` was zero (??)
	moveq    ip, #0                     ; 
	addne    ip, ip, #0x8C              ; Prepare to load from `pc[0x8C+0x14]` (wrapper fragment size + address, packed as 6+26 bits)
	ldr      ip, [ip, #0x14]            ; 
	sub      ip, ip, #0                 ; Useless subtraction?
	stmfd    sp!, {r0, r1, r2, r3, r4}  ; Push
	mov      r1, ip, lsr #26            ; Shifting right by 26 to extract upper 6 bits (function size to hash)
	eor      r3, r3, r3                 ; Clearing `r3` to use as hash accumulator
	mov      ip, ip, lsl #6             ; Shifting `ip` up and down by 6 to clear the upper 6 bits (leaving address)
	mov      ip, ip, lsr #6             ; 
	mov      r0, ip                     ; Moving function address to `r0` so we can increment it
hash_loop_\@:                           ; 
	ldr      r2, [r0]                   ; Load instruction from `r0`
	mov      r4, r2, lsr #24            ; Checking its opcode, shift by 24 to extract upper byte
	cmp      r4, #0xEA                  ; Compare opcode to EA and EB, which are branches (possible relocations)
	cmpne    r4, #0xEB                  ; 
	eorne    r3, r3, r2, ror #17        ; If not a branch, add to hash
	addne    r3, r3, r2, ror #28        ; hash = ((hash ^ (ins >>> 17)) + (ins >>> 28)) ^ (ins >>> i)
	eorne    r3, r3, r2, ror r1         ; 
	subs     r1, r1, #1                 ; Decrement size
	add      r0, r0, #4                 ; Increment address
	bne      hash_loop_\@               ; Continue hash loop until remaining size is 0
	mov      r0, #0x02000000            ; Create addresses 0x02000800 and 0x04004000
	orr      r1, r0, #0x800             ; 
	mov      r0, #0x04000000            ; 
	orr      r0, r0, #0x4000            ; 
	ldr      r0, [r0]                   ; Read value from 0x04004000 (should always be zero)
	ands     r0, r0, #1                 ; If LSB is set, will clobber stuff
	orrne    r1, r1, #0x4000            ; If not set, update other address to 0x02004800
	cmp      ip, r1,                    ; Comparing `ip` (Encryptor_DecryptionWrapperFragment) to other address
	strge    r3, [pc, #0x18]            ; If address is higher, save the proper decryption key to pool
	movlt    ip, lr                     ; Else, Return to `lr` instead of running Encryptor_DecryptionWrapperFragment (why?)
	ldmgefd  sp!, {r0, r1, r2, r3, r4}  ; Correct pop if address is higher
	ldmltfd  sp!, {r5, r6, r7, r8, sb}  ; Incorrect pop, ruining registers if address is lower
	stmgedb  sp!, {ip}                  ; Stash address of decryption wrapper fragment onto stack
	orr      ip, pc, pc                 ; Re-get `pc`, which now points to the data structure in the pool
	ldmia    sp!, {pc}                  ; Pop decryption wrapper fragment address off stack to `pc`
	.word BSS + 1
	.word BSS + 3
	.word \func + ENC_VAL_1
	.word BSS + \length + ENC_VAL_1
	.word 0x00000000
	.word Encryptor_DecryptionWrapperFragment + (\hashed_instructions << 26)
	.endm


	.macro overwrite_instructions self
	ldr r0, =\self+ENC_VAL_1
	ldr r1, =0xE12FFF1E       ; <bx lr> command
	sub r0, r0, #ENC_VAL_1
	stmia r0!, {r1-r10}       ; Writes <bx lr> followed by whatever garbage happened to be in `r2`-`r10`
	.endm


	.public Encryptor_DecodeFunctionTable

	.macro decode_following_func_table
	; This does not take a reference, instead always uses a manual `[pc #4]`
	orr   r0, pc, #0x0
	adds  r0, r0, #0x4
	bne   Encryptor_DecodeFunctionTable
	.endm

	.macro func_table_entry func, size
	.word  \func + ENC_VAL_1,  BSS + \size + ENC_VAL_1
	.endm

	.macro func_table_end
	.word  0, 0
	.endm

	.macro garbage_ref ref
	.word  \ref + ENC_VAL_1
	.endm

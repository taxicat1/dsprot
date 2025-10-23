#pragma once
#include "encoding_constants.h"

	.macro arm_func_start name
	.balign  4, 0
	.global  \name
	.type    \name, @function
	.arm
	.endm

	.macro local_arm_func_start name
	.balign  4, 0
	.type    \name, @function
	.arm
	.endm

	.macro arm_func_end name
	.size  \name, .-\name
	.endm


	.macro sinit sinit_func
	.type  NitroStaticInit_\@, @object
NitroStaticInit_\@:
	.word  \sinit_func
	.size  NitroStaticInit_\@, .-NitroStaticInit_\@
	.endm


	.public BSS
	.public Encryptor_DecryptionWrapperFragment

	.macro encrypted_func_data func, length, fragment_hash_ins
	.word  BSS + 1                    ; Storage space
	.word  BSS + 3                    ; Key (to be derived on-the-fly)
	.word  \func + ENC_VAL_1          ; Function address
	.word  BSS + \length + ENC_VAL_1  ; Function length
	.word  0                          ; Storage space
	; Decryption wrapper fragment and hashed instructions (packed as 6+26)
	.word  Encryptor_DecryptionWrapperFragment + (\fragment_hash_ins << 0x1A)
	.endm

	.macro run_encrypted_func func, length, fragment_hash_ins
	orr      ip, pc, pc             ; Copy `pc` out
	ands     ip, ip, ip             ; Checking if `pc` was zero (??)
	moveq    ip, #0                 ; 
	addne    ip, ip, #0x68          ; Set `ip` to point at encrypted_func_data struct below
	ldr      ip, [ip, #0x14]        ; Load encrypted_func_data[0x14] (wrapper fragment size + address, packed as 6+26 bits)
	sub      ip, ip, #0             ; Useless subtraction?
	stmfd    sp!, {r0-r4}           ; Push
	mov      r1, ip, lsr #0x1A      ; Shifting right by 26 to extract upper 6 bits (function size to hash)
	eor      r3, r3, r3             ; Clearing `r3` to use as hash accumulator
	mov      ip, ip, lsl #6         ; Shifting `ip` up and down by 6 to clear the upper 6 bits (leaving address)
	mov      ip, ip, lsr #6         ; 
	mov      r0, ip                 ; Moving function address to `r0` so we can increment it
hash_loop_\@:                       ; 
	ldr      r2, [r0]               ; Load instruction from `r0`
	mov      r4, r2, lsr #0x18      ; Checking its opcode, shift by 24 to extract upper byte
	cmp      r4, #0xEA              ; Compare opcode to EA and EB, which are branches (possible relocations)
	cmpne    r4, #0xEB              ; 
	eorne    r3, r3, r2, ror #0x11  ; If not a branch, add to hash
	addne    r3, r3, r2, ror #0x1C  ; hash = ((hash ^ (ins >>> 17)) + (ins >>> 28)) ^ (ins >>> i)
	eorne    r3, r3, r2, ror r1     ; 
	subs     r1, r1, #1             ; Decrement size
	add      r0, r0, #4             ; Increment address
	bne      hash_loop_\@           ; Continue hash loop until remaining size is 0
	streq    r3, [pc, #0x14]        ; After hashing, we have derived the key. Store it in the pool
	ldmeqfd  sp!, {r0-r4}           ; Pop
	ldmnefd  sp!, {r5-r9}           ; Incorrect pop, ruining registers if hash loop is skipped (tamper detection?)
	stmeqdb  sp!, {ip}              ; Stash address of decryption wrapper fragment onto stack
	orr      ip, pc, pc             ; Re-get `pc`, which now points to encrypted_func_data struct
	ldmeqia  sp!, {pc}              ; Pop decryption wrapper fragment address off stack to `pc`
	
	; Data structure
	encrypted_func_data \func, \length, \fragment_hash_ins
	.endm


	.public Encryptor_DecodeFunctionTable

	.macro decode_following_func_table
	; This does not take a reference, instead always uses a manual `[pc #4]`
	orr   r0, pc, #0
	adds  r0, r0, #4
	bne   Encryptor_DecodeFunctionTable
	.endm

	.macro func_table_entry func, size
	.word  \func + ENC_VAL_1, BSS + \size + ENC_VAL_1
	.endm

	.macro func_table_end
	.word  0, 0
	.endm

	.macro garbage_ref ref
	.word  \ref + ENC_VAL_1
	.endm

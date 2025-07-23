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
	.arm
	.endm

	.macro arm_func_end name
	.size \name, .-\name
	.endm


	.public BSS
	.public Encryptor_DecryptionWrapperFragment

	.macro run_encrypted_func func, length, key
	; Obfuscated: copy `pc` into `ip`, then add +0x1C and +0x14 for total +0x30.
	; `pc + 0x30` from the first line is the line with `Encryptor_DecryptionWrapperFragment + ENC_VAL_1`.
	; Subtract `ENC_VAL_1` (0x1000) from that, store it on the stack.
	; Then set `ip` back to `pc`, which now points at the start of the data structure.
	; Finally pop the address to `Encryptor_DecryptionWrapperFragment` off the stack onto `pc` to jump.
	orr    ip, pc, pc
	ands   ip, ip, ip
	moveq  ip, #0
	addne  ip, ip, #0x1C
	ldr    ip, [ip, #0x14]
	sub    ip, ip, #ENC_VAL_1
	stmfd  sp!, {ip}
	orr    ip, pc, pc
	ldmfd  sp!, {pc}
	.word  BSS + 0x1                  ; Storage space
	.word  BSS + \key + ENC_VAL_1     ; Encryption key
	.word  \func + ENC_VAL_1          ; Function address
	.word  BSS + \length + ENC_VAL_1  ; Length
	.word  0                          ; Storage space
	.word  Encryptor_DecryptionWrapperFragment + ENC_VAL_1
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

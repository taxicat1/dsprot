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

	.macro encrypted_func_data func, length, key
	.word  BSS + 1                    ; Storage space
	.word  BSS + \key + ENC_VAL_1     ; Encryption key
	.word  \func + ENC_VAL_1          ; Function address
	.word  BSS + \length + ENC_VAL_1  ; Length
	.word  0                          ; Storage space
	; Pointer to wrapper fragment
	.word  Encryptor_DecryptionWrapperFragment + ENC_VAL_1
	.endm

	.macro run_encrypted_func func, length, key
	orr    ip, pc, pc          ; Copy `pc` into `ip`
	ands   ip, ip, ip          ; Checking if `pc` was zero (??)
	moveq  ip, #0              ; 
	addne  ip, ip, #0x1C       ; Set `ip` to point at encrypted_func_data struct below
	ldr    ip, [ip, #0x14]     ; Load encrypted_func_data[0x14] (address of Encryptor_DecryptionWrapperFragment)
	sub    ip, ip, #ENC_VAL_1  ; Deobfuscate address
	stmfd  sp!, {ip}           ; Stash address of decryption wrapper fragment onto stack
	orr    ip, pc, pc          ; Re-get `pc`, which now points to encrypted_func_data struct
	ldmfd  sp!, {pc}           ; Pop decryption wrapper fragment address off stack to `pc`
	
	; Data structure
	encrypted_func_data \func, \length, \key
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

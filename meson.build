project(
    'dsprot',
    ['c', 'nasm'],
    version: '1.23',
    meson_version: '>=1.12.0',
    default_options: ['buildtype=plain', 'warning_level=0'],
)


############################################################
###                         TOOLS                        ###
############################################################
subdir('tools')

############################################################
###                         COMPILERS                    ###
############################################################
mwccarm = meson.get_compiler('c', native: false).cmd_array()
mwasmarm = meson.get_compiler('nasm', native: false).cmd_array()

############################################################
###                    INCLUDE PATHS                     ###
############################################################
include_dir = meson.project_source_root() / 'include'


############################################################
###                    COMPILER FLAGS                    ###
############################################################
c_args = []
asm_args = []

mwrap_sdk = get_option('mwrap_sdk')
if mwrap_sdk != 'default'
    c_args += ['-wrap:sdk', mwrap_sdk]
    asm_args += ['-wrap:sdk', mwrap_sdk]
endif

c_args += [
    '-O4,p',
    '-enum',
    'int',
    '-proc',
    'arm946E',
    '-gccext,on',
    '-fp',
    'soft',
    '-lang',
    'c99',
    '-char',
    'signed',
    '-inline',
    'on,noauto',
    '-Cpp_exceptions',
    'off',
    '-interworking',
    '-c',
    '-W',
    'all',
    '-W',
    'pedantic',
    '-W',
    'noimpl_signedunsigned',
    '-W',
    'noimplicitconv',
    '-W',
    'nounusedarg',
    '-W',
    'nomissingreturn',
    '-W',
    'error',
]

asm_args += [
    '-proc',
    'arm5TE',
]

dep_args = [
    '-gccdep',
    '-MD',
]

############################################################
###                       KEYS                           ###
############################################################
key_dsprot_main = '6AB2'
key_integrity = '9785'
key_core_tests = '0982'

############################################################
###                       ENCODED FUNCTIONS              ###
############################################################
dsprot_main_decrypter_functions = [
    'DetectFlashcart',
    'DetectNotFlashcart',
    'DetectEmulator',
    'DetectNotEmulator',
    'DetectDummy',
    'DetectNotDummy',
]

dsprot_main_decrypter_decoder_functions = [
    'DSProt_DetectFlashcart',
    'DSProt_DetectNotFlashcart',
    'DSProt_DetectEmulator',
    'DSProt_DetectNotEmulator',
    'DSProt_DetectDummy',
    'DSProt_DetectNotDummy',
]

integrity_decrypter_functions = [
    'Integrity_MACOwner_IsBad',
    'Integrity_MACOwner_IsGood',
    'Integrity_ROMTest_IsBad',
    'Integrity_ROMTest_IsGood',
]

integrity_decrypter_decoder_functions = [
    'RunEncrypted_Integrity_MACOwner_IsBad',
    'RunEncrypted_Integrity_MACOwner_IsGood',
    'RunEncrypted_Integrity_ROMTest_IsBad',
    'RunEncrypted_Integrity_ROMTest_IsGood',
]

encryptor_decoder_functions = [
    'Encryptor_EncryptFunction',
    'Encryptor_DecryptFunction',
]

mac_owner_decrypter_functions = [
    'MACOwner_IsBad',
    'MACOwner_IsGood',
]

rom_util_decrypter_functions = [
    'ROMUtil_Read',
    'ROMUtil_CRC32',
]

rom_test_functions = [
    'ROMTest_IsBad',
    'ROMTest_IsGood',
]

coretests_decrypter_decoder_functions = [
    'RunEncrypted_ROMTest_IsBad',
    'RunEncrypted_ROMTest_IsGood',
    'RunEncrypted_MACOwner_IsBad',
    'RunEncrypted_MACOwner_IsGood',
    'RunEncrypted_ROMUtil_Read',
    'RunEncrypted_ROMUtil_CRC32',
]

rc4_decoder_functions = [
    'RC4_Init',
    'RC4_Byte',
    'RC4_InitSBox',
    'RC4_EncryptInstructions',
    'RC4_DecryptInstructions',
    'RC4_InitAndEncryptInstructions',
    'RC4_InitAndDecryptInstructions',
]

############################################################
###                       ENC ARGS                       ###
############################################################
dsprot_main_dec_enc_args = [
    '-k',
    key_dsprot_main,
    '-p',
    'DSProt_',
    '-f',
    dsprot_main_decrypter_functions,
]

dsprot_main_decrypter_dec_enc_args = [
    '-g',
    'Garbage',
    '-f',
    dsprot_main_decrypter_decoder_functions,
]

integrity_dec_enc_args = [
    '-k',
    key_integrity,
    '-f',
    integrity_decrypter_functions,
]

integrity_decrypter_dec_enc_args = [
    '-f',
    integrity_decrypter_decoder_functions,
]

encryptor_dec_enc_args = [
    '-f',
    encryptor_decoder_functions,
]

mac_owner_dec_enc_args = [
    '-k',
    key_core_tests,
    '-f',
    mac_owner_decrypter_functions,
]

rom_util_dec_enc_args = [
    '-k',
    key_core_tests,
    '-f',
    rom_util_decrypter_functions,
]

rom_test_dec_enc_args = [
    '-k',
    key_core_tests,
    '-f',
    rom_test_functions,
]

coretests_dec_enc_args = [
    '-f',
    coretests_decrypter_decoder_functions,
]

rc4_dec_enc_args = [
    '-f',
    rc4_decoder_functions,
]


# These were originally generators, due to the creation of private build
# directories, elfcoder would need to accept an output for the encoded/encrypted
# files, so they are not utilised

############################################################
###                      .c -> .o                        ###
############################################################

mwccarm_cmds = [
    mwccarm,
    c_args,
    '-i',
    include_dir,
    dep_args,
    '@INPUT@',
    '-o',
    '@OUTPUT@',
]

############################################################
###                      .s -> .o                        ###
############################################################

mwasmarm_cmds = [
    mwasmarm,
    asm_args,
    '-i',
    include_dir,
    '@INPUT@',
    '-o',
    '@OUTPUT@',
]

############################################################
###                      ENCODE/ENCRYPT                  ###
############################################################

elfcoder_cmds = [
    elfcoder_exe,
    '-e',
    '-c',
    '_enc.o',
    '-i',
    '@INPUT@',
    '-o',
    '@OUTPUT0@',
]

############################################################
###                       DSPROT MAIN                    ###
############################################################
dsprot_main = custom_target(
    'dsprot_main',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/dsprot_main.c',
    command: mwccarm_cmds,
)

dsprot_main_dec_enc = custom_target(
    'dsprot_main_dec_enc',
    input: dsprot_main,
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    command: [
        elfcoder_cmds,
        dsprot_main_dec_enc_args,
    ],
)

dsprot_main_decrypter_s = dsprot_main_dec_enc[0]
dsprot_main_encrypted = dsprot_main_dec_enc[1]

dsprot_main_decrypter = custom_target(
    'dsprot_main_decrypter',
    output: '@BASENAME@.o',
    input: dsprot_main_decrypter_s,
    command: mwasmarm_cmds,
)

dsprot_main_decrypter_dec_enc = custom_target(
    'dsprot_main_decrypter_dec_enc',
    input: dsprot_main_decrypter,
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    command: [
        elfcoder_cmds,
        dsprot_main_decrypter_dec_enc_args,
    ],
)

dsprot_main_decrypter_decoder_s = dsprot_main_decrypter_dec_enc[0]
dsprot_main_decrypter_encoded = dsprot_main_decrypter_dec_enc[1]

dsprot_main_decrypter_decoder = custom_target(
    'dsprot_main_decrypter_decoder',
    output: '@BASENAME@.o',
    input: dsprot_main_decrypter_decoder_s,
    command: mwasmarm_cmds,
)

############################################################
###                       EXTRA                          ###
############################################################
extra = custom_target(
    'extra',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/extra.c',
    command: mwccarm_cmds,
)

############################################################
###                       INTEGRITY                      ###
############################################################
integrity = custom_target(
    'integrity',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/integrity.c',
    command: mwccarm_cmds,
)

integrity_dec_enc = custom_target(
    'integrity_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: integrity,
    command: [
        elfcoder_cmds,
        integrity_dec_enc_args,
    ],
)

integrity_decrypter_s = integrity_dec_enc[0]
integrity_encrypted = integrity_dec_enc[1]


integrity_decrypter = custom_target(
    'integrity_decrypter',
    output: '@BASENAME@.o',
    input: integrity_decrypter_s,
    command: mwasmarm_cmds,
)

integrity_decrypter_dec_enc = custom_target(
    'integrity_decrypter_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: integrity_decrypter,
    command: [
        elfcoder_cmds,
        integrity_decrypter_dec_enc_args,
    ],
)

integrity_decrypter_decoder_s = integrity_decrypter_dec_enc[0]
integrity_decrypter_encoded = integrity_decrypter_dec_enc[1]

integrity_decrypter_decoder = custom_target(
    'integrity_decrypter_decoder',
    output: '@BASENAME@.o',
    input: integrity_decrypter_decoder_s,
    command: mwasmarm_cmds,
)

############################################################
###                       ENCRYPTOR                      ###
############################################################
encryptor = custom_target(
    'encryptor',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/encryptor.c',
    command: mwccarm_cmds,
)

encryptor_dec_enc = custom_target(
    'encryptor_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: encryptor,
    command: [
        elfcoder_cmds,
        encryptor_dec_enc_args,
    ],
)

encryptor_decoder_s = encryptor_dec_enc[0]
encryptor_encoded = encryptor_dec_enc[1]

encryptor_decoder = custom_target(
    'encryptor_decoder',
    output: '@BASENAME@.o',
    input: encryptor_decoder_s,
    command: mwasmarm_cmds,
)

############################################################
###                       MAC OWNER                      ###
############################################################
mac_owner = custom_target(
    'mac_owner',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/mac_owner.c',
    command: mwccarm_cmds,
)

mac_owner_dec_enc = custom_target(
    'mac_owner_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: mac_owner,
    command: [
        elfcoder_cmds,
        mac_owner_dec_enc_args,
    ],
)

mac_owner_decrypter_s = mac_owner_dec_enc[0]
mac_owner_encrypted = mac_owner_dec_enc[1]

mac_owner_decrypter = custom_target(
    'mac_owner_decrypter',
    output: '@BASENAME@.o',
    input: mac_owner_decrypter_s,
    command: mwasmarm_cmds,
)

############################################################
###                       ROM UTIL                       ###
############################################################
rom_util = custom_target(
    'rom_util',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/rom_util.c',
    command: mwccarm_cmds,
)

rom_util_dec_enc = custom_target(
    'rom_util_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: rom_util,
    command: [
        elfcoder_cmds,
        rom_util_dec_enc_args,
    ],
)

rom_util_decrypter_s = rom_util_dec_enc[0]
rom_util_encrypted = rom_util_dec_enc[1]

rom_util_decrypter = custom_target(
    'rom_util_decrypter',
    output: '@BASENAME@.o',
    input: rom_util_decrypter_s,
    command: mwasmarm_cmds,
)

############################################################
###                       ROM TEST                       ###
############################################################
rom_test = custom_target(
    'rom_test',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/rom_test.c',
    command: mwccarm_cmds,
)

rom_test_dec_enc = custom_target(
    'rom_test_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: rom_test,
    command: [
        elfcoder_cmds,
        rom_test_dec_enc_args,
    ],
)

rom_test_decrypter_s = rom_test_dec_enc[0]
rom_test_encrypted = rom_test_dec_enc[1]

rom_test_decrypter = custom_target(
    'rom_test_decrypter',
    output: '@BASENAME@.o',
    input: rom_test_decrypter_s,
    command: mwasmarm_cmds,
)

############################################################
###                       CORETESTS                      ###
############################################################
coretests_dec_enc = custom_target(
    'coretests_dec_enc',
    output: [
        'coretests_decrypter_decoder.s',
        '@PLAINNAME0@_enc.o',
        '@PLAINNAME1@_enc.o',
        '@PLAINNAME2@_enc.o',
    ],
    input: [
        mac_owner_decrypter,
        rom_util_decrypter,
        rom_test_decrypter,
    ],
    command: [
        elfcoder_cmds,
        coretests_dec_enc_args,
    ],
)

coretests_decoder_s = coretests_dec_enc[0]
mac_owner_decrypter_encoded = coretests_dec_enc[1]
rom_util_decrypter_encoded = coretests_dec_enc[2]
rom_test_decrypter_encoded = coretests_dec_enc[3]

coretests_decoder = custom_target(
    'coretests_decoder',
    output: '@BASENAME@.o',
    input: coretests_decoder_s,
    command: mwasmarm_cmds,
)

############################################################
###                       RC4                            ###
############################################################
rc4 = custom_target(
    'rc4',
    output: '@BASENAME@.o',
    depfile: '@BASENAME@.d',
    input: 'src/rc4.c',
    command: mwccarm_cmds,
)

rc4_dec_enc = custom_target(
    'rc4_dec_enc',
    output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
    input: rc4,
    command: [
        elfcoder_cmds,
        rc4_dec_enc_args,
    ],
)

rc4_decoder_s = rc4_dec_enc[0]
rc4_encoded = rc4_dec_enc[1]

rc4_decoder = custom_target(
    'rc4_decrypter',
    output: '@BASENAME@.o',
    input: rc4_decoder_s,
    command: mwasmarm_cmds,
)

############################################################
###                       LIBRARY                        ###
############################################################
dsprot = static_library(
    'dsprot',
    sources: [
        dsprot_main_encrypted,
        dsprot_main_decrypter_encoded,
        dsprot_main_decrypter_decoder,
        extra,
        integrity_encrypted,
        integrity_decrypter_encoded,
        integrity_decrypter_decoder,
        encryptor_encoded,
        encryptor_decoder,
        mac_owner_encrypted,
        mac_owner_decrypter_encoded,
        rom_util_encrypted,
        rom_util_decrypter_encoded,
        rom_test_encrypted,
        rom_test_decrypter_encoded,
        coretests_decoder,
        rc4_encoded,
        rc4_decoder,
    ],
    native: false,
)

############################################################
###                    FOR CONSUMERS                     ###
############################################################
dsprot_dep = declare_dependency(link_with: dsprot)

meson.override_dependency('dsprot', dsprot_dep)


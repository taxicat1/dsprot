project(
    'dsprot',
    ['c', 'nasm'],
    version: '1.28',
    meson_version: '>=1.5.0',
    default_options: {
        'buildtype': 'plain',
        'warning_level': '0',
    },
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
    '-ipa',
    'file',
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
key_dsprot_main = '175F2'
key_integrity = '17DCC'
key_mac_owner = '7B95'
key_rom_util = '7F25'
key_rom_test = '7F25'
key_dummy = '8645'

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
    '__DSProt_DetectFlashcart',
    '__DSProt_DetectNotFlashcart',
    '__DSProt_DetectEmulator',
    '__DSProt_DetectNotEmulator',
    '__DSProt_DetectDummy',
    '__DSProt_DetectNotDummy',
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
    'Encryptor_DecryptionWrapperFragment',
]

mac_owner_decrypter_functions = [
    'MACOwner_IsBad',
    'MACOwner_IsGood',
]

rom_util_decrypter_functions = [
    'ROMUtil_CRC32',
]

rom_test_functions = [
    'ROMTest_IsBad',
    'ROMTest_IsGood',
]

dummy_decrypter_functions = [
    'Dummy_IsBad',
    'Dummy_IsGood',
]


coretests_decrypter_decoder_functions = [
    'RunEncrypted_ROMTest_IsBad',
    'RunEncrypted_ROMTest_IsGood',
    'RunEncrypted_MACOwner_IsBad',
    'RunEncrypted_MACOwner_IsGood',
    'RunEncrypted_ROMUtil_CRC32',
    'RunEncrypted_Dummy_IsBad',
    'RunEncrypted_Dummy_IsGood',
]

rc4_decoder_functions = [
    'RC4_Init',
    'RC4_InitSBox',
    'RC4_EncryptInstructions',
    'RC4_DecryptInstructions',
    'RC4_InitAndEncryptInstructions',
    'RC4_InitAndDecryptInstructions',
    'RC4_Byte',
]

############################################################
###                       ENC ARGS                       ###
############################################################
dsprot_main_dec_enc_args = [
    '-k',
    key_dsprot_main,
    '-p',
    '__DSProt_',
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
    key_mac_owner,
    '-f',
    mac_owner_decrypter_functions,
]

rom_util_dec_enc_args = [
    '-k',
    key_rom_util,
    '-f',
    rom_util_decrypter_functions,
]

rom_test_dec_enc_args = [
    '-k',
    key_rom_test,
    '-f',
    rom_test_functions,
]

dummy_dec_enc_args = [
    '-k',
    key_dummy,
    '-f',
    dummy_decrypter_functions,
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
# files, so they are just the commands

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
###                      SETUP COMPONENTS                ###
############################################################
components = {
    'dsprot_main': {
        'dec_enc_args': dsprot_main_dec_enc_args,
        'decrypter_dec_enc_args': dsprot_main_decrypter_dec_enc_args,
    },
    'integrity': {
        'dec_enc_args': integrity_dec_enc_args,
        'decrypter_dec_enc_args': integrity_decrypter_dec_enc_args,
    },
    'encryptor': {
        'dec_enc_args': encryptor_dec_enc_args,
    },
    'mac_owner': {
        'dec_enc_args': mac_owner_dec_enc_args,
    },
    'rom_util': {
        'dec_enc_args': rom_util_dec_enc_args,
    },
    'rom_test': {
        'dec_enc_args': rom_test_dec_enc_args,
    },
    'dummy': {
        'dec_enc_args': dummy_dec_enc_args,
    },
    'rc4': {
        'dec_enc_args': rc4_dec_enc_args,
    },
}

enc_objects = {}
decs = {}
enc_decrypters = {}
decrypter_decoders = {}

foreach name, component : components

    # Compile
    comp = custom_target(
        name + 'loop',
        output: '@BASENAME@.o',
        depfile: '@BASENAME@.d',
        input: 'src/' + name + '.c',
        command: mwccarm_cmds,
    )

    # Encrypt / Encode
    dec_enc = custom_target(
        name + 'dec_enc',
        input: comp,
        output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
        command: [
            elfcoder_cmds,
            component['dec_enc_args'],
        ],
    )

    dec_s = dec_enc[0]
    enc = dec_enc[1]

    # Assemble Decrypter / Decoder
    dec = custom_target(
        name + 'dec',
        output: '@BASENAME@.o',
        input: dec_s,
        command: mwasmarm_cmds,
    )

    enc_objects += {name: enc}
    decs += {name: dec}

    if (component.has_key('decrypter_dec_enc_args'))

        # Encode Decrypter
        decrypter_dec_enc = custom_target(
            name + 'decrypter_dec_enc',
            input: dec,
            output: ['@BASENAME@_dec.s', '@PLAINNAME@_enc.o'],
            command: [
                elfcoder_cmds,
                component['decrypter_dec_enc_args'],
            ],
        )

        decrypter_decoder_s = decrypter_dec_enc[0]
        decrypter_encoded = decrypter_dec_enc[1]

        # Assemble Decrypter Decoder
        decrypter_decoder = custom_target(
            name + 'decrypter_dec',
            output: '@BASENAME@.o',
            input: decrypter_decoder_s,
            command: mwasmarm_cmds,
        )

        enc_decrypters += {name: decrypter_encoded}
        decrypter_decoders += {name: decrypter_decoder}

    endif
endforeach

dsprot_main_encrypted = enc_objects['dsprot_main']
dsprot_main_decrypter_encoded = enc_decrypters['dsprot_main']
dsprot_main_decrypter_decoder = decrypter_decoders['dsprot_main']

integrity_encrypted = enc_objects['integrity']
integrity_decrypter_encoded = enc_decrypters['integrity']
integrity_decrypter_decoder = decrypter_decoders['integrity']

encryptor_encoded = enc_objects['encryptor']
encryptor_decoder = decs['encryptor']

mac_owner_encrypted = enc_objects['mac_owner']
mac_owner_decrypter = decs['mac_owner']

rom_util_encrypted = enc_objects['rom_util']
rom_util_decrypter = decs['rom_util']

rom_test_encrypted = enc_objects['rom_test']
rom_test_decrypter = decs['rom_test']

dummy_encrypted = enc_objects['dummy']
dummy_decrypter = decs['dummy']

rc4_encoded = enc_objects['rc4']
rc4_decoder = decs['rc4']


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
###                       CORETESTS                      ###
############################################################
coretests_dec_enc = custom_target(
    'coretests_dec_enc',
    output: [
        'coretests_decrypter_decoder.s',
        '@PLAINNAME0@_enc.o',
        '@PLAINNAME1@_enc.o',
        '@PLAINNAME2@_enc.o',
        '@PLAINNAME3@_enc.o',
    ],
    input: [
        mac_owner_decrypter,
        rom_util_decrypter,
        rom_test_decrypter,
        dummy_decrypter,
    ],
    command: [
        elfcoder_cmds,
        coretests_dec_enc_args,
    ],
)

coretests_decrytper_decoder_s = coretests_dec_enc[0]
mac_owner_decrypter_encoded = coretests_dec_enc[1]
rom_util_decrypter_encoded = coretests_dec_enc[2]
rom_test_decrypter_encoded = coretests_dec_enc[3]
dummy_decrypter_encoded = coretests_dec_enc[4]

coretests_decrytper_decoder = custom_target(
    'coretests_decrytper_decoder',
    output: '@BASENAME@.o',
    input: coretests_decrytper_decoder_s,
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
        dummy_encrypted,
        dummy_decrypter_encoded,
        coretests_decrytper_decoder,
        rc4_encoded,
        rc4_decoder,
    ],
    native: false,
)

############################################################
###                    FOR CONSUMERS                     ###
############################################################
dsprot_dep = declare_dependency(
    link_with: dsprot,
    include_directories: include_directories('.'),
)

meson.override_dependency('dsprot', dsprot_dep)

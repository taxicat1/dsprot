elfcoder_exe = executable(
    'elfcoder',
    files(
        'src/argparse.c',
        'src/asmwriter.c',
        'src/elfread.c',
        'src/encoder.c',
        'src/instruction.c',
        'src/main.c',
        'src/rc4.c',
    ),
    include_directories: include_directories('include'),
    c_args: [
        '-O3',
        '-Wno-unused-result',
    ],
    native: true,
)

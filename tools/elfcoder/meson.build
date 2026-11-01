elfcoder_sources = [
    'src/argparse.c',
    'src/asmwriter.c',
    'src/elfread.c',
    'src/encoder.c',
    'src/instruction.c',
    'src/main.c',
    'src/rc4.c',
]

incdir = include_directories('include')

elfcoder_exe = executable(
    'elfcoder',
    elfcoder_sources,
    include_directories: incdir,
    c_args: [
        '-O3',
        '-Wno-unused-result',
    ],
    native: true,
)

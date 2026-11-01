fixdep_sources = [
    'src/main.c',
]

incdir = include_directories('include')

fixdep_exe = executable(
    'fixdep',
    fixdep_sources,
    include_directories: incdir,
    c_args: [
        '-O3',
        '-Wno-unused-result',
    ],
    native: true,
)

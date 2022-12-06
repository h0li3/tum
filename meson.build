project('tum', 'cpp',
  version : '0.1',
  default_options : ['cpp_std=c++17', 'warning_level=1'])

incdir = include_directories('include', 'src', 'src/instrument/stubs')

 
subdir('src')

sources = ['src/main.cc',
           'src/memory/memory.cc',
           'src/memory/misc_mem.cc',
           'src/memory/memory_map.cc',
           'src/osdep.cc',
           'src/logio.cc',]

libs = [cpu_library,
        fpu_library,
]

executable(meson.project_name(),
           sources,
           include_directories: incdir,
           link_with: libs)

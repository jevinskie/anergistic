cmake_minimum_required(VERSION 3.9)
project(anergistic C CXX)

add_subdirectory(googletest)

add_executable(anergistic main.c elf.c emulate.c emulate-instrs.c helper.c channel.c gdb.c mbuf.cpp)

target_include_directories(anergistic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})


set_target_properties(anergistic PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS YES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS YES
)

add_custom_command(
    OUTPUT emulate-instrs.h emulate-instrs.c
    COMMAND python2 ${CMAKE_CURRENT_SOURCE_DIR}/instr-generate.py ${CMAKE_CURRENT_SOURCE_DIR}/instrs ${CMAKE_CURRENT_SOURCE_DIR}/emulate-instrs.h.in emulate-instrs.h ${CMAKE_CURRENT_SOURCE_DIR}/emulate-instrs.c.in emulate-instrs.c
    DEPENDS emulate-instrs.h.in instrs instr-generate.py emulate-instrs.c.in
)

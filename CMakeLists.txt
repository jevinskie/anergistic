cmake_minimum_required(VERSION 3.9)
project(anergistic C CXX)

option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." On)
if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

add_subdirectory(googletest)

add_executable(anergistic main.c elf.c emulate.c emulate-instrs.c helper.c channel.c gdb.c mbuf.cpp hex.c)

target_include_directories(anergistic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(anergistic PRIVATE -Wall -Wextra)


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

include(GoogleTest)
add_executable(mbuf-test mbuf.cpp hex.c test/main.cpp test/mbuf-test.cpp)
target_include_directories(mbuf-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${gtest_SOURCE_DIR}/include)
target_link_libraries(mbuf-test gtest)
gtest_add_tests(TARGET      mbuf-test
)

set_target_properties(mbuf-test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS YES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS YES
)

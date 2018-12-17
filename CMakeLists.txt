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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS YES)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED YES)
set(CMAKE_C_EXTENSIONS YES)

add_subdirectory(googletest)
add_subdirectory(fmt)

add_executable(anergistic main.c elf.c emulate.c emulate-instrs.c helper.c channel.c gdb.c mbuf.cpp hex.c util.c dbgtools/src/callstack.cpp)

target_include_directories(anergistic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/dbgtools/include)
target_compile_options(anergistic PRIVATE -Wall -Wextra)
target_link_libraries(anergistic fmt)

add_custom_command(
    OUTPUT emulate-instrs.h emulate-instrs.c
    COMMAND python2 ${CMAKE_CURRENT_SOURCE_DIR}/instr-generate.py ${CMAKE_CURRENT_SOURCE_DIR}/instrs ${CMAKE_CURRENT_SOURCE_DIR}/emulate-instrs.h.in emulate-instrs.h ${CMAKE_CURRENT_SOURCE_DIR}/emulate-instrs.c.in emulate-instrs.c
    DEPENDS emulate-instrs.h.in instrs instr-generate.py emulate-instrs.c.in
)

include(GoogleTest)
add_executable(mbuf-test mbuf.cpp hex.c dbgtools/src/callstack.cpp test/main.cpp test/mbuf-test.cpp)
target_include_directories(mbuf-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/dbgtools/include ${gtest_SOURCE_DIR}/include)
target_link_libraries(mbuf-test fmt gtest)
gtest_add_tests(TARGET mbuf-test)

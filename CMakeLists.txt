# The primary build. The root Makefile is a thin wrapper over the presets in
# CMakePresets.json, kept so the familiar `make test` / `make asan` / `make tsan`
# entry points still work. epoll-server/ and http-get/ keep their own Makefiles
# as well, because the end-to-end scripts in scripts/ build through them and
# expect the binaries next to those Makefiles.
cmake_minimum_required(VERSION 3.20)

project(tcp_ip_stack LANGUAGES CXX)

# -std=c++17, not -std=gnu++17: the stack is meant to be portable C++.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# clangd and clang-tidy read this. Each preset gets its own build directory, so
# point clangd at the one you use (or symlink build/debug/compile_commands.json
# to the repo root; that path is gitignored).
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ccache when it is installed, unless the caller chose a launcher already. The
# sanitizer targets in the Makefile always start from an empty build directory,
# and without a compiler cache that is a full recompile every time.
if(NOT DEFINED CMAKE_CXX_COMPILER_LAUNCHER)
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    endif()
endif()

# The flags every target shares, the same ones the hand-written Makefile used:
# -std=c++17 (above) -Wall -g -pthread. -g is unconditional so a release build
# is still debuggable. Preset-specific flags (sanitizers, coverage, -Werror)
# come in through CMAKE_CXX_FLAGS from CMakePresets.json, so they reach every
# target - including GoogleTest when it is built from source.
#
# -pthread is spelled out rather than taken from find_package(Threads): on
# glibc 2.34+ pthreads live in libc, FindThreads concludes no flag is needed and
# Threads::Threads comes out empty. -pthread is a compile flag as well as a link
# flag (it defines _REENTRANT), and the old build always passed it to both.
add_library(project_options INTERFACE)
target_compile_options(project_options INTERFACE -Wall -g -pthread)
target_link_options(project_options INTERFACE -pthread)

# --- The stack -------------------------------------------------------------
# Globbed, not hand-listed, for the same reason the sub-Makefiles glob: a list
# kept in two places drifts. CONFIGURE_DEPENDS makes the build re-glob, so a new
# file is picked up without re-running cmake by hand.
file(GLOB STACK_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_library(tcpip STATIC ${STACK_SOURCES})
target_include_directories(tcpip PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(tcpip PUBLIC project_options)

# --- The testable part of epoll-server --------------------------------------
# Named explicitly rather than globbed: the rest of that program (server.cpp,
# main.cpp, epoll_wrapper.cpp) needs a channel and an event loop, and pulling
# its main() into the test runner would not link.
#
# These two are in the test runner at all because the tsan job was decorative
# for as long as the whole suite was single-threaded: it built and linked, and
# proved nothing. This is the threaded code, and it needs no TAP device or
# privilege - only eventfd, which works anywhere Linux does.
add_library(epoll_threaded STATIC
    ${PROJECT_SOURCE_DIR}/epoll-server/src/thread_pool.cpp
    ${PROJECT_SOURCE_DIR}/epoll-server/src/completion_queue.cpp)
target_include_directories(epoll_threaded PUBLIC ${PROJECT_SOURCE_DIR}/epoll-server/include)
target_link_libraries(epoll_threaded PUBLIC tcpip)

# --- The applications --------------------------------------------------------
# Built here as well as by their own Makefiles so that the strict and sanitizer
# presets cover them too. The scripts in scripts/ still build through
# `make -C epoll-server` / `make -C http-get`; those binaries are what they run.
# -Wextra matches what those Makefiles have always used.
file(GLOB EPOLL_SERVER_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/epoll-server/src/*.cpp)
list(FILTER EPOLL_SERVER_SOURCES EXCLUDE REGEX "/(thread_pool|completion_queue)\\.cpp$")
add_executable(epoll-server ${EPOLL_SERVER_SOURCES})
target_compile_options(epoll-server PRIVATE -Wextra)
target_link_libraries(epoll-server PRIVATE epoll_threaded)

file(GLOB HTTP_GET_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/http-get/src/*.cpp)
add_executable(http-get ${HTTP_GET_SOURCES})
target_compile_options(http-get PRIVATE -Wextra)
target_link_libraries(http-get PRIVATE tcpip)

# --- Tests -----------------------------------------------------------------
# Globbed so that adding tests/src/test_foo.cpp needs no wiring here.
enable_testing()
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/tests/src/*.cpp)
add_executable(run_tests ${TEST_SOURCES})
target_include_directories(run_tests PRIVATE ${PROJECT_SOURCE_DIR}/tests/include)
target_link_libraries(run_tests PRIVATE tcpip epoll_threaded)

add_test(NAME run_tests COMMAND run_tests)
set_tests_properties(run_tests PROPERTIES LABELS unit)

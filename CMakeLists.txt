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

# What gets built, beyond the stack library itself. The fuzz and bench presets
# switch the tests and applications off: the fuzz build instruments the stack
# with libFuzzer, which has no use for GoogleTest or the epoll server, and a
# benchmark build should not wait for either.
option(TCPIP_BUILD_TESTS "Build the GoogleTest suite" ON)
option(TCPIP_BUILD_APPS "Build epoll-server and http-get" ON)
option(TCPIP_BUILD_FUZZERS "Build the libFuzzer harnesses in fuzz/ (needs clang)" OFF)
option(TCPIP_BUILD_BENCH "Build the Google Benchmark microbenchmarks in bench/" OFF)

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

if(TCPIP_BUILD_TESTS OR TCPIP_BUILD_APPS)
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

endif()

if(TCPIP_BUILD_APPS)
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
endif()

if(TCPIP_BUILD_TESTS)
# --- GoogleTest ------------------------------------------------------------
# The installed package first (Arch: gtest, Debian/Ubuntu: libgtest-dev and
# libgmock-dev), so a normal build needs no network. CONFIG mode because only
# GoogleTest's own package config provides the GMock targets; CMake's FindGTest
# module does not.
#
# Otherwise fetch a pinned release. Built from source it also picks up the
# preset's CMAKE_CXX_FLAGS, so under a sanitizer preset it is instrumented too.
# -DTCPIP_FETCH_GTEST=ON forces this path even when a package is installed.
option(TCPIP_FETCH_GTEST "Build GoogleTest from source instead of using an installed package" OFF)
if(NOT TCPIP_FETCH_GTEST)
    find_package(GTest 1.11 CONFIG QUIET)
endif()
if(GTest_FOUND)
    message(STATUS "GoogleTest: using installed package ${GTest_VERSION} (${GTest_DIR})")
else()
    message(STATUS "GoogleTest: building v1.15.2 from source")
    include(FetchContent)
    set(GTEST_FETCH_ARGS
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE)
    # SYSTEM keeps the strict preset's -Werror off GoogleTest's headers, as it
    # already is for an installed package. The option needs CMake 3.25.
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.25)
        list(APPEND GTEST_FETCH_ARGS SYSTEM)
    endif()
    FetchContent_Declare(googletest ${GTEST_FETCH_ARGS})
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# --- Tests -----------------------------------------------------------------
# Globbed so that adding tests/src/test_foo.cpp needs no wiring here.
enable_testing()
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/tests/src/*.cpp)
add_executable(run_tests ${TEST_SOURCES})
target_include_directories(run_tests PRIVATE ${PROJECT_SOURCE_DIR}/tests/include)
# gmock_main provides main() and initialises both GoogleTest and GMock.
target_link_libraries(run_tests PRIVATE tcpip epoll_threaded GTest::gmock_main)
# The network simulator (tests/include/sim) writes a failing test's capture
# under the build directory, next to test-results/, so CI can upload both from
# one place. The packetdrill-style runner finds its scripts by absolute path,
# so the binary works from any working directory (ctest runs it from the build
# directory, `make test` from the repo root).
target_compile_definitions(run_tests PRIVATE
    SIM_PCAP_DEFAULT_DIR="${CMAKE_BINARY_DIR}/sim-pcaps"
    PKT_SCRIPT_DIR="${PROJECT_SOURCE_DIR}/tests/scripts")

# One ctest test per GoogleTest test, so `ctest -R` and `ctest -j` work and a
# failure names the test. PRE_TEST lists the tests when ctest runs rather than
# as a post-build step: listing means running the binary, and a build should not
# fail because a sanitizer binary aborted while being asked for its test names.
#
# Each test writes JUnit-style XML into build/<preset>/test-results/, which CI
# uploads when a job fails.
#
# Two labels. `unit` is everything fast and fixed. `sim` is the simulator's
# seeded property tests (suites named *SimTransfer*), whose count is set by
# SIM_SEEDS when the binary lists its tests - so it is a separate label that the
# per-push unit runs (ctest -L unit, the test presets) leave out, and that
# `make sim` runs on its own. Splitting by TEST_FILTER needs CMake 3.22; older
# CMake registers everything as `unit`, which is only slower.
include(GoogleTest)
set(SIM_TEST_PATTERN "*SimTransfer*")
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
    gtest_discover_tests(run_tests
        DISCOVERY_MODE PRE_TEST
        TEST_FILTER "-${SIM_TEST_PATTERN}"
        XML_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-results
        PROPERTIES LABELS unit)
    gtest_discover_tests(run_tests
        DISCOVERY_MODE PRE_TEST
        TEST_FILTER "${SIM_TEST_PATTERN}"
        XML_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-results
        PROPERTIES LABELS sim)
else()
    gtest_discover_tests(run_tests
        DISCOVERY_MODE PRE_TEST
        XML_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-results
        PROPERTIES LABELS unit)
endif()
endif()

# --- Fuzzing and benchmarks ------------------------------------------------
if(TCPIP_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
if(TCPIP_BUILD_BENCH)
    add_subdirectory(bench)
endif()

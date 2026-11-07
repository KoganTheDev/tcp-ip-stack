# tcp-ip-stack

Userspace TCP/IP stack in C++17 (Ethernet, ARP, IPv4, TCP, UDP, ICMP) over a Linux TAP device. See README.md for the architecture diagram.

## Layout
- include/, src/ : the stack
- tests/src/, tests/include/ : GoogleTest suite, one suite per file (new tests/src/*.cpp files are picked up by a CMake glob, no wiring needed). In a TEST body use `ASSERT_TRUE(cond) << msg`; in helpers and lambdas use `REQUIRE_TRUE(cond, msg)` from tests/include/test_support.h (see the comment there).
- epoll-server/ : the application built on the stack (its own Makefile). Only thread_pool.cpp and completion_queue.cpp are linked into the tests.
- scripts/ : end-to-end shell tests (veth, router, http-get)

## Commands
The build is CMake (CMakePresets.json: debug, release, asan, tsan, coverage, strict, fuzz, bench; each builds into build/<preset>). The root Makefile wraps it:
- Build and run tests: `make test` (runner is build/debug/run_tests)
- Address + UB sanitizers: `make asan`
- Thread sanitizer: `make tsan`
- Warnings as errors: `make strict`
- Coverage (clang): `make coverage` (per-file table, HTML in build/coverage/html)
- Fuzzing (clang, libFuzzer): `make fuzz` (harnesses in fuzz/, seeds in fuzz/corpus, FUZZ_SECONDS per harness, default 30; crashes land in build/fuzz/crashes/)
- Microbenchmarks (Google Benchmark, Release): `make bench` (sources in bench/; BENCH_ARGS passes flags to the binary)
- Clean: `make clean`
- Without the wrapper: `cmake --preset debug && cmake --build --preset debug && ctest --preset debug -L unit`
- One test: `./build/debug/run_tests --gtest_filter='TcpConnection.*'`

Compiler is g++ with `-std=c++17 -Wall -g -pthread` (the coverage preset uses clang++). GoogleTest/GMock come from the system package, or are fetched if none is installed.

## Rules
- Before saying a change is done, run `make test`. For anything touching threads, also `make tsan`. For memory or parsing changes, also `make asan`.
- `make asan` / `make tsan` wipe their build directory and rebuild from scratch on purpose. Do not try to reuse objects from another build.
- A TSan abort with exit 66 at startup is environmental (ASLR/seccomp), not a race. See the comment above the `tsan` target.
- Do not run scripts/*.sh without asking. They set up network devices and may need root or a TAP device.
- Keep the Makefile and CMakeLists.txt comments explaining why a target is shaped the way it is; update them if behaviour changes.

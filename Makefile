# The real build is CMake (CMakeLists.txt, with one preset per build flavour in
# CMakePresets.json). This Makefile is a thin wrapper, kept so the entry points
# everyone already types - `make test`, `make asan`, `make tsan` - keep working,
# and for the parts a preset cannot express: the TSan ASLR probe below, and the
# sanitizer runtime options.
#
# Every preset builds into its own build/<preset> directory, so a debug object
# can never end up linked into a sanitizer binary or the other way round.
#
# The applications on top of the stack (epoll-server/, http-get/) are built by
# the CMake presets too, but keep their own Makefiles: scripts/*.sh build
# through `make -C epoll-server` / `make -C http-get` and run the binaries that
# land next to those Makefiles.
#
# Targets:
#   make            - build everything in the debug preset (same as `make all`)
#   make run_tests  - same; the test runner is build/debug/run_tests
#   make test       - build and run the whole test suite (exit status is
#                     nonzero if any test fails)
#   make asan       - full rebuild, then run the suite under ASan + UBSan
#   make tsan       - full rebuild, then run the suite under ThreadSanitizer
#   make strict     - build everything with -Wextra -Werror, then run the suite
#   make clean      - remove every build directory
#
# Without the wrapper: cmake --preset debug && cmake --build --preset debug &&
# ctest --preset debug. tests/src/*.cpp are globbed by CMake, so a new test file
# needs no wiring anywhere.

CMAKE ?= cmake

all: build/debug/build.ninja
	$(CMAKE) --build --preset debug

run_tests: all

# The runner is invoked directly rather than through ctest: it is one process
# for the whole suite, prints its own summary, and its exit status is the
# answer.
test: all
	./build/debug/run_tests

# Configure a preset the first time it is used, and again whenever the presets
# file changes (re-running `cmake --preset` re-applies its cache variables).
# Edits to CMakeLists.txt need nothing here - `cmake --build` notices those and
# re-runs the configure step itself.
build/%/build.ninja: CMakePresets.json
	$(CMAKE) --preset $*

# Sanitizer runs are always full rebuilds, from an empty build directory. The
# instrumentation is a compile flag; separate build directories already keep a
# normal build's objects out, and starting from nothing also rules out a stale
# CMake cache (an old compiler or flag set) silently surviving into the run.
# ccache keeps the cost of this down where it is installed.
#
# ASan and UBSan combine in one pass (they instrument different things and do
# not conflict). TSan must be its own build - it is incompatible with ASan and
# has to be linked into everything.
#
# halt_on_error=1 matters for UBSan especially: without it, undefined behavior
# is reported and then execution continues, so a passing exit code would mean
# nothing. The asan preset also compiles with -fno-sanitize-recover=all, which
# makes the same thing true at compile time.
asan:
	rm -rf build/asan
	$(CMAKE) --preset asan
	$(CMAKE) --build --preset asan
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/asan/run_tests

# TSan needs a specific virtual-memory layout and disables ASLR itself to get
# it. Where it cannot (a container whose seccomp profile blocks the
# personality() syscall - Docker's default does), it aborts at startup with
# "encountered an incompatible memory layout", exit 66. Whether it happens is
# down to where ASLR randomly placed things that run, so it presents as a
# roughly coin-flip failure rather than a consistent one, which makes it easy
# to misread as flaky code rather than a blocked syscall.
#
# So: probe whether ASLR can actually be disabled, and use setarch -R when it
# can. The probe matters - falling back after a failed *test* run instead would
# quietly turn a genuine TSan race report into a passing retry.
#
# This probe is why `make tsan` is the way to run TSan; `ctest --preset tsan`
# runs the same binary without it.
#
# In Docker, grant the syscall with:
#   docker run --security-opt seccomp=unconfined ...
tsan:
	rm -rf build/tsan
	$(CMAKE) --preset tsan
	$(CMAKE) --build --preset tsan
	@if setarch $$(uname -m) -R true >/dev/null 2>&1; then \
	    echo "tsan: ASLR can be disabled, running under setarch -R"; \
	    TSAN_OPTIONS=halt_on_error=1 setarch $$(uname -m) -R ./build/tsan/run_tests; \
	else \
	    echo "tsan: cannot disable ASLR here (blocked personality() syscall?);"; \
	    echo "tsan: running anyway - a startup abort with exit 66 is environmental, not a race"; \
	    TSAN_OPTIONS=halt_on_error=1 ./build/tsan/run_tests; \
	fi

# Warnings as errors, but only on the code this project owns: imported
# libraries' headers are included as system headers, which the compiler exempts.
# A blanket -Werror over system headers would fail on -Wextra noise
# (sockaddr_ll and ifreq have members no caller is meant to initialize), which
# is why -Wno-missing-field-initializers is in the preset.
#
# Not a forced rebuild like the sanitizers: build/strict only ever compiles with
# -Werror, so every object already in it passed, and ninja recompiles whatever
# changed since.
strict: build/strict/build.ninja
	$(CMAKE) --build --preset strict
	./build/strict/run_tests

# bin/, tests/bin/ and ./run_tests are where the hand-written Makefile this
# replaced put its output; removed too so an old checkout cleans up fully.
clean:
	rm -rf build bin tests/bin
	rm -f run_tests tcpipstack

.PHONY: all run_tests test asan tsan strict clean

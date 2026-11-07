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
#   make sim        - only the simulator's seeded property tests, SIM_SEEDS
#                     of them (default 200), sharded over SIM_JOBS processes
#   make asan       - full rebuild, then run the suite under ASan + UBSan
#   make tsan       - full rebuild, then run the suite under ThreadSanitizer
#   make strict     - build everything with -Wextra -Werror, then run the suite
#   make coverage   - run the suite with clang coverage; per-file report, plus
#                     HTML in build/coverage/html
#   make fuzz       - build the libFuzzer harnesses (clang) and run each for
#                     FUZZ_SECONDS (default 30)
#   make fuzz-seeds - regenerate the committed seed corpus in fuzz/corpus
#   make bench      - build the microbenchmarks (Release) and run them
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

# The network simulator's seeded property tests (gtest suites *SimTransfer*,
# ctest label `sim`) and nothing else. `make test` runs them too, at the
# default 200 seeds; this target exists for running many more - the nightly
# workflow does SIM_SEEDS=100000 - and to rerun a window of seeds
# (SIM_SEED_START=1055 SIM_SEEDS=1 make sim). Both variables reach the binary
# through the environment.
#
# The binary is run directly rather than through ctest: ctest starts one
# process per test, which at 100000 seeds would be most of the run. Instead
# GoogleTest's own sharding splits the seeds over SIM_JOBS processes (one per
# CPU by default), each logging to build/debug/sim-shard-<n>.log. Every shard
# is waited for before failing, so one bad seed does not hide the others;
# failing seeds leave their pcaps in build/debug/sim-pcaps.
#
# Captures are capped at about SIM_PCAP_LIMIT failing tests per run (default
# 20): each shard gets an equal share, rounded up, through the binary's own
# SIM_PCAP_LIMIT, and the rest of the failures are only counted. A regression
# that fails thousands of nightly seeds would otherwise upload hundreds of MB
# of captures of the same bug.
SIM_JOBS ?= $(shell nproc 2>/dev/null || echo 1)
SIM_PCAP_LIMIT ?= 20

sim: all
	@status=0; logs=""; \
	for i in $$(seq 0 $$(($(SIM_JOBS) - 1))); do \
	    logs="$$logs build/debug/sim-shard-$$i.log"; \
	    GTEST_TOTAL_SHARDS=$(SIM_JOBS) GTEST_SHARD_INDEX=$$i \
	    SIM_PCAP_LIMIT=$$(( ($(SIM_PCAP_LIMIT) + $(SIM_JOBS) - 1) / $(SIM_JOBS) )) \
	        ./build/debug/run_tests --gtest_filter='*SimTransfer*' > build/debug/sim-shard-$$i.log 2>&1 & \
	done; \
	for job in $$(jobs -p); do wait $$job || status=1; done; \
	grep -h -E '^\[==========\] .* ran' $$logs; \
	if [ $$status -ne 0 ]; then \
	    echo "sim: failing seeds:"; \
	    grep -h -E '^\[  FAILED  \] .*GetParam' $$logs | grep -v ' ms)$$' | sort -u; \
	    echo "sim: captures written for $$(cat $$logs | grep -c 'frames as delivered') failing tests," \
	         "not written for $$(cat $$logs | grep -c 'SIM PCAP \] not written') (SIM_PCAP_LIMIT=$(SIM_PCAP_LIMIT))"; \
	    echo "sim: details in build/debug/sim-shard-*.log, captures in build/debug/sim-pcaps/"; \
	fi; \
	exit $$status

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

# Line/region/function coverage of the stack from one run of the unit suite,
# using clang's source-based coverage (the coverage preset builds with clang++
# whatever the other presets use). The report is per file and has no threshold:
# it is there to show what the suite never reaches, not to gate merges.
#
# llvm-profdata's on-disk format is tied to the compiler version that wrote the
# raw profiles, so the tools are looked up next to the clang++ that built the
# binary (-print-prog-name) rather than whichever llvm-profdata is first in
# PATH. On Ubuntu that is /usr/lib/llvm-<N>/bin; override with
# LLVM_PROFDATA=... LLVM_COV=... if needed.
#
# The profile directory is emptied first: profiles from an earlier run of an
# older binary would otherwise be merged in and the counts would be fiction.
# The tests themselves and anything outside the repo are left out of the report.
COVERAGE_DIR = build/coverage
LLVM_PROFDATA ?= $(shell clang++ -print-prog-name=llvm-profdata 2>/dev/null || echo llvm-profdata)
LLVM_COV ?= $(shell clang++ -print-prog-name=llvm-cov 2>/dev/null || echo llvm-cov)
COVERAGE_IGNORE = -ignore-filename-regex='/tests/|/_deps/|^/usr/'

coverage: $(COVERAGE_DIR)/build.ninja
	$(CMAKE) --build --preset coverage
	rm -rf $(COVERAGE_DIR)/profraw $(COVERAGE_DIR)/html
	LLVM_PROFILE_FILE=$(COVERAGE_DIR)/profraw/%p.profraw ./$(COVERAGE_DIR)/run_tests
	$(LLVM_PROFDATA) merge -sparse $(COVERAGE_DIR)/profraw/*.profraw -o $(COVERAGE_DIR)/run_tests.profdata
	$(LLVM_COV) show ./$(COVERAGE_DIR)/run_tests -instr-profile=$(COVERAGE_DIR)/run_tests.profdata \
	    $(COVERAGE_IGNORE) -format=html -output-dir=$(COVERAGE_DIR)/html
	$(LLVM_COV) report ./$(COVERAGE_DIR)/run_tests -instr-profile=$(COVERAGE_DIR)/run_tests.profdata \
	    $(COVERAGE_IGNORE) > $(COVERAGE_DIR)/report.txt
	@cat $(COVERAGE_DIR)/report.txt
	@echo "coverage: text report in $(COVERAGE_DIR)/report.txt"
	@echo "coverage: HTML report in $(COVERAGE_DIR)/html/index.html"

# Coverage-guided fuzzing with libFuzzer: one harness per parser, one for
# the reassembler, one for the whole stack (see fuzz/). The unit suite's fuzz
# tests (tests/src/test_protocol_fuzz.cpp) feed a fixed 2000 random inputs per
# parser; this keeps going, steering by which branches each input reached, so
# it finds the inputs that random bytes almost never produce (a TCP option
# whose length runs off the segment, a DNS pointer loop).
#
# Not a gate on `make test`: a run is time-boxed, so a clean result means "none
# found in FUZZ_SECONDS", not "none exists". The fuzz preset is clang-only
# because libFuzzer is; the stack is built with ASan and UBSan so memory errors
# and UB are crashes the fuzzer can see.
#
# Each harness gets two corpus directories. libFuzzer writes the inputs it
# finds interesting to the FIRST, so that is a scratch directory under build/
# (also what CI caches between runs); the committed seeds in fuzz/corpus are
# only read, and stay small and reviewable. -timeout=10 turns a hang into a
# finding instead of a 20-minute wait. A crash leaves its reproducer in
# build/fuzz/crashes/<harness>/; replay it with
#     ./build/fuzz/fuzz/fuzz_<harness> <file>
# Every harness runs even if an earlier one crashed, so one finding does not
# hide the rest; the exit status is nonzero if any crashed. Only libFuzzer's
# summary lines are shown; the full output of a crashing run is kept in
# build/fuzz/<harness>.log.
FUZZ_SECONDS ?= 30
FUZZ_HARNESSES = ethernet ipv4 tcp udp icmp arp dhcp dns ip_reassembler stack

fuzz: build/fuzz/build.ninja
	$(CMAKE) --build --preset fuzz
	@status=0; \
	for h in $(FUZZ_HARNESSES); do \
	    mkdir -p build/fuzz/corpus/$$h build/fuzz/crashes/$$h; \
	    echo "== fuzz_$$h ($(FUZZ_SECONDS) s)"; \
	    ./build/fuzz/fuzz/fuzz_$$h -max_total_time=$(FUZZ_SECONDS) -timeout=10 -print_final_stats=1 \
	        -artifact_prefix=build/fuzz/crashes/$$h/ \
	        build/fuzz/corpus/$$h fuzz/corpus/$$h > build/fuzz/$$h.log 2>&1; \
	    grep -E '^(#[0-9]+[[:space:]]+DONE|stat::(number_of_executed_units|average_exec_per_sec|peak_rss_mb)|SUMMARY|Test unit written)' build/fuzz/$$h.log; \
	    if ls build/fuzz/crashes/$$h/* >/dev/null 2>&1; then echo "fuzz: $$h CRASHED, see build/fuzz/crashes/$$h/"; status=1; fi; \
	done; \
	exit $$status

# The seed corpus is generated by fuzz/gen_corpus.cpp from the stack's own
# serializers and committed, so this is only needed when the seeds should
# change.
fuzz-seeds: build/fuzz/build.ninja
	$(CMAKE) --build --preset fuzz --target fuzz_gen_corpus
	./build/fuzz/fuzz/fuzz_gen_corpus fuzz/corpus

# Microbenchmarks (bench/, Google Benchmark). The bench preset is Release with
# -O2 -g: optimised, because numbers from an unoptimised build measure the
# wrong thing, but -O2 rather than the release preset's -O3 to stay close to
# what an ordinary build does.
#
# Extra arguments go to the benchmark binary, e.g.
#     make bench BENCH_ARGS=--benchmark_filter=Checksum
# CI (bench.yml) runs the binary itself with --benchmark_format=json.
BENCH_ARGS ?=

bench: build/bench/build.ninja
	$(CMAKE) --build --preset bench
	./build/bench/bench/tcpip_bench $(BENCH_ARGS)

# bin/, tests/bin/ and ./run_tests are where the hand-written Makefile this
# replaced put its output; removed too so an old checkout cleans up fully.
clean:
	rm -rf build bin tests/bin
	rm -f run_tests tcpipstack

.PHONY: all run_tests test sim asan tsan strict coverage fuzz fuzz-seeds bench clean

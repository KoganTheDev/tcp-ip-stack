# Targets:
#   make            - build the tcpipstack binary (src/main.cpp sandbox)
#   make all        - build both the binary and the test runner
#   make run_tests  - build the test runner (tests/src/*.cpp are picked up
#                     automatically by the wildcard below - no per-file wiring)
#   make test       - build and run the whole test suite
#   make asan       - run the test suite under AddressSanitizer + UBSan
#   make tsan       - run the test suite under ThreadSanitizer
#   make clean      - remove build artifacts

# Include all directories recursively under "include"
INCLUDES = -I./include
TEST_INCLUDES = -I./include -I./tests/include

HEADERS = $(wildcard ./include/*.h)
TEST_HEADERS = $(wildcard ./tests/include/*.h)

# Automatically find all .cpp files in the src directory (and subdirectories)
SRC = $(wildcard ./src/*.cpp)
TEST_SRC = $(wildcard ./tests/src/*.cpp)

# Object files corresponding to the source files
OBJ = $(SRC:./src/%.cpp=./bin/%.o)
TEST_OBJ = $(filter-out ./bin/main.o, $(OBJ)) $(TEST_SRC:./tests/src/%.cpp=./tests/bin/%.o)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g

# Output executable
TARGET = tcpipstack
TEST_TARGET = run_tests

# $(TARGET) stays the first rule so a bare `make` still builds just the binary,
# as it always has - `all` and `test` are opt-in.
$(TARGET) : $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $^

all: $(TARGET) $(TEST_TARGET)

$(TEST_TARGET) : $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -o $(TEST_TARGET) $^

test: $(TEST_TARGET)
	./$(TEST_TARGET)

bin/%.o: src/%.cpp $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

tests/bin/%.o: tests/src/%.cpp $(HEADERS) $(TEST_HEADERS)
	@mkdir -p tests/bin
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -c $< -o $@

# Sanitizer runs are always full rebuilds: the instrumentation is a compile
# flag, so reusing objects from a normal build would silently leave most of the
# code uninstrumented and the run would prove nothing.
#
# ASan and UBSan combine in one pass (they instrument different things and do
# not conflict). TSan must be its own target - it is incompatible with ASan and
# has to be linked into everything.
#
# halt_on_error=1 matters for UBSan especially: without it, undefined behavior
# is reported and then execution continues, so a passing exit code would mean
# nothing.
asan:
	$(MAKE) clean
	$(MAKE) $(TEST_TARGET) CXXFLAGS="-std=c++17 -Wall -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./$(TEST_TARGET)

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
# In Docker, grant the syscall with:
#   docker run --security-opt seccomp=unconfined ...
tsan:
	$(MAKE) clean
	$(MAKE) $(TEST_TARGET) CXXFLAGS="-std=c++17 -Wall -g -O1 -fno-omit-frame-pointer -fsanitize=thread"
	@if setarch $$(uname -m) -R true >/dev/null 2>&1; then \
	    echo "tsan: ASLR can be disabled, running under setarch -R"; \
	    TSAN_OPTIONS=halt_on_error=1 setarch $$(uname -m) -R ./$(TEST_TARGET); \
	else \
	    echo "tsan: cannot disable ASLR here (blocked personality() syscall?);"; \
	    echo "tsan: running anyway - a startup abort with exit 66 is environmental, not a race"; \
	    TSAN_OPTIONS=halt_on_error=1 ./$(TEST_TARGET); \
	fi

clean:
	rm -rf bin tests/bin
	rm -f $(TARGET) $(TEST_TARGET)

.PHONY: all test asan tsan clean

# This Makefile builds the stack's objects and the test runner. There is no
# standalone binary target here any more: the sandbox that used to provide
# main() demonstrated the retired physical-NIC path, and the actual program
# built on this stack is epoll-server/ (see its own Makefile).
#
# Targets:
#   make            - build the test runner (same as `make run_tests`)
#   make all        - same
#   make run_tests  - build the test runner (tests/src/*.cpp are picked up
#                     automatically by the wildcard below - no per-file wiring)
#   make test       - build and run the whole test suite
#   make asan       - run the test suite under AddressSanitizer + UBSan
#   make tsan       - run the test suite under ThreadSanitizer
#   make clean      - remove build artifacts

# Include all directories recursively under "include"
INCLUDES = -I./include
TEST_INCLUDES = -I./include -I./tests/include -I./epoll-server/include

HEADERS = $(wildcard ./include/*.h)
TEST_HEADERS = $(wildcard ./tests/include/*.h)

# Automatically find all .cpp files in the src directory (and subdirectories)
SRC = $(wildcard ./src/*.cpp)
TEST_SRC = $(wildcard ./tests/src/*.cpp)

# The two pieces of epoll-server that are testable without a network device.
# They are named explicitly rather than wildcarded because the rest of that
# program (server.cpp, main.cpp) needs a channel and an event loop, and pulling
# main() into the test runner would not link.
#
# They are here at all because the tsan job was decorative for as long as the
# whole suite was single-threaded: it built and linked, and proved nothing. This
# is the threaded code, and it needs no TAP device or privilege - only eventfd,
# which works anywhere Linux does.
THREADED_SRC = ./epoll-server/src/thread_pool.cpp ./epoll-server/src/completion_queue.cpp

# Object files corresponding to the source files
OBJ = $(SRC:./src/%.cpp=./bin/%.o)
THREADED_OBJ = $(THREADED_SRC:./epoll-server/src/%.cpp=./bin/%.o)
TEST_OBJ = $(OBJ) $(THREADED_OBJ) $(TEST_SRC:./tests/src/%.cpp=./tests/bin/%.o)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g -pthread

# Output executable
TEST_TARGET = run_tests

# first rule, so a bare `make` builds the test runner
all: $(TEST_TARGET)

$(TEST_TARGET) : $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -o $(TEST_TARGET) $^

test: $(TEST_TARGET)
	./$(TEST_TARGET)

bin/%.o: src/%.cpp $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

bin/%.o: epoll-server/src/%.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -c $< -o $@

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
	$(MAKE) $(TEST_TARGET) CXXFLAGS="-std=c++17 -Wall -g -pthread -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
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
	$(MAKE) $(TEST_TARGET) CXXFLAGS="-std=c++17 -Wall -g -pthread -O1 -fno-omit-frame-pointer -fsanitize=thread"
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
	rm -f $(TEST_TARGET) tcpipstack

.PHONY: all test asan tsan clean

# Targets:
#   make            - build the tcpipstack binary (src/main.cpp sandbox)
#   make all        - build both the binary and the test runner
#   make run_tests  - build the test runner (tests/src/*.cpp are picked up
#                     automatically by the wildcard below - no per-file wiring)
#   make test       - build and run the whole test suite
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

clean:
	rm -rf bin tests/bin
	rm -f $(TARGET) $(TEST_TARGET)

.PHONY: all test clean

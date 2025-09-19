# TODO: ASK ALON for help with creating and running the test files via the makefile.

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

$(TARGET) : $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $^

$(TEST_TARGET) : $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -o $(TEST_TARGET) $^

bin/%.o: src/%.cpp $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

tests/bin/%.o: tests/src/%.cpp $(TEST_HEADERS)
	@mkdir -p tests/bin
	$(CXX) $(CXXFLAGS) $(TEST_INCLUDES) -c $< -o $@

clean:
	rm -f bin/*.o
	rm -f tests/bin/*.o
	rmdir bin
	rmdir tests/bin
	rm $(TARGET) $(TEST_TARGET)

.PHONY: clean

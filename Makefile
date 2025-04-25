# Include all directories recursively under "include"
INCLUDES = -I./include

HEADERS = $(wildcard ./include/*.h)

# Automatically find all .cpp files in the src directory (and subdirectories)
SRC = $(wildcard ./src/*.cpp)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall $(INCLUDES)

# Object files corresponding to the source files
OBJ = $(SRC:./src/%.cpp=./bin/%.o)

# Output executable
TARGET = tcpipstack

$(TARGET) : $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^

bin/%.o: src/%.cpp $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm bin/*.o
	rmdir bin
	rm $(TARGET)

.PHONY: clean

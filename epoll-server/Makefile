# This project's headers plus the repo-root exceptions.h it reuses
INCLUDES = -I./include -I../include

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread $(INCLUDES)

# exceptions.cpp lives at the repo root and is shared, not duplicated here
SRC_DIRS = src ../src
vpath %.cpp $(SRC_DIRS)

SOURCES = socket_wrapper.cpp epoll_wrapper.cpp thread_pool.cpp server.cpp main.cpp exceptions.cpp
OBJ = $(addprefix bin/,$(SOURCES:.cpp=.o))

TARGET = epoll-server

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^

bin/%.o: %.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf bin $(TARGET)

.PHONY: clean

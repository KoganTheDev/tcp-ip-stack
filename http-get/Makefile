# A second program on the same stack, built the same way epoll-server is: the
# shared Ethernet/ARP/IP/TCP/UDP sources in ../src are compiled here rather than
# duplicated or turned into a library, so a change to the stack is picked up by
# both programs on the next build.

INCLUDES = -I./include -I../include

CXX = g++

# -MMD -MP records which headers each object actually included and feeds that
# back in below, so editing a header rebuilds what depends on it. Without it a
# stale object links silently - see epoll-server/Makefile for the version of
# that failure this project actually hit.
CXXFLAGS = -std=c++17 -Wall -Wextra -MMD -MP $(INCLUDES)

SRC_DIRS = src ../src
vpath %.cpp $(SRC_DIRS)

# Discovered, not hand-listed. A list maintained in two places eventually is
# not.
SOURCES = $(notdir $(wildcard src/*.cpp) $(wildcard ../src/*.cpp))
OBJ = $(addprefix bin/,$(SOURCES:.cpp=.o))
DEPS = $(OBJ:.o=.d)

TARGET = http-get

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^

bin/%.o: %.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -rf bin $(TARGET)

.PHONY: clean

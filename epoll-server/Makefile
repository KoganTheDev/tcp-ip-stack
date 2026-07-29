# This project's headers plus the repo-root protocol/network stack headers
INCLUDES = -I./include -I../include

CXX = g++

# -MMD -MP makes the compiler emit a .d file recording every header each object
# actually included, which is then fed back in below. Without it this Makefile
# had no header dependencies at all, so editing a header rebuilt nothing and the
# link quietly reused stale objects - the failure mode is a build that succeeds
# locally and cannot possibly succeed from a clean checkout.
#
# -MMD rather than -MD: system headers are excluded, because they do not change
# between builds and tracking them costs rebuild time for nothing. -MP emits a
# phony target for each header, so deleting or renaming a header is a rebuild
# rather than "No rule to make target".
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread -MMD -MP $(INCLUDES)

# The root project's Ethernet/ARP/IP/TCP stack lives in ../src and is shared,
# not duplicated here
SRC_DIRS = src ../src
vpath %.cpp $(SRC_DIRS)

# Discovered, not hand-listed. The stack file list used to be typed out here,
# and drifted: ip_reassembler.cpp was added to the stack and never added here,
# so the link only worked at all because an older object was still sitting in
# bin/. A list that has to be maintained in two places will eventually be
# maintained in one.
SOURCES = $(notdir $(wildcard src/*.cpp) $(wildcard ../src/*.cpp))
OBJ = $(addprefix bin/,$(SOURCES:.cpp=.o))
DEPS = $(OBJ:.o=.d)

TARGET = epoll-server

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^

bin/%.o: %.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Dash-prefixed: the .d files do not exist on the first build, and their absence
# is not an error - the object they describe has not been compiled yet, so
# there is nothing stale to catch.
-include $(DEPS)

clean:
	rm -rf bin $(TARGET)

.PHONY: clean

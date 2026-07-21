# This project's headers plus the repo-root protocol/network stack headers
INCLUDES = -I./include -I../include

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread $(INCLUDES)

# The root project's Ethernet/ARP/IP/TCP stack lives in ../src and is shared,
# not duplicated here
SRC_DIRS = src ../src
vpath %.cpp $(SRC_DIRS)

LOCAL_SOURCES = epoll_wrapper.cpp thread_pool.cpp completion_queue.cpp server.cpp main.cpp
STACK_SOURCES = exceptions.cpp bytes.cpp utils.cpp network_addresses.cpp \
                protocol_layer.cpp raw.cpp ethernet.cpp arp.cpp ip.cpp tcp.cpp udp.cpp \
                tcp_connection.cpp udp_socket.cpp tun_wrapper.cpp system_network_object.cpp network_stack.cpp \
                logger.cpp

SOURCES = $(LOCAL_SOURCES) $(STACK_SOURCES)
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

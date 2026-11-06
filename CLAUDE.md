# tcp-ip-stack

Userspace TCP/IP stack in C++17 (Ethernet, ARP, IPv4, TCP, UDP, ICMP) over a Linux TAP device. See README.md for the architecture diagram.

## Layout
- include/, src/ : the stack
- tests/src/, tests/include/ : test runner (new tests/src/*.cpp files are picked up by the Makefile wildcard, no wiring needed)
- epoll-server/ : the application built on the stack (its own Makefile). Only thread_pool.cpp and completion_queue.cpp are linked into the tests.
- scripts/ : end-to-end shell tests (veth, router, http-get)

## Commands
- Build and run tests: `make test`
- Address + UB sanitizers: `make asan`
- Thread sanitizer: `make tsan`
- Clean: `make clean`

Compiler is g++ with `-std=c++17 -Wall -g -pthread`.

## Rules
- Before saying a change is done, run `make test`. For anything touching threads, also `make tsan`. For memory or parsing changes, also `make asan`.
- The sanitizer targets do a full `make clean` rebuild on purpose. Do not try to reuse objects from a normal build.
- A TSan abort with exit 66 at startup is environmental (ASLR/seccomp), not a race. See the comment above the `tsan` target.
- Do not run scripts/*.sh without asking. They set up network devices and may need root or a TAP device.
- Keep the Makefile comments explaining why a target is shaped the way it is; update them if behaviour changes.

# epoll-server

A multithreaded TCP echo server on Linux, built directly on `epoll` - no framework.

## Architecture

- `SocketWrapper` - non-blocking listening socket (`socket`/`bind`/`listen`/`accept`)
- `EpollWrapper` - thin wrapper over `epoll_create1`/`epoll_ctl`/`epoll_wait`
- `ThreadPool` - fixed-size worker pool with a task queue
- `Server` - one thread runs the `epoll_wait` loop and accepts connections; each ready
  client fd is handed to the thread pool as a task. Client fds are registered
  `EPOLLIN | EPOLLET | EPOLLONESHOT`, so a fd is only ever in one worker's hands at a
  time - it gets re-armed after that worker finishes reading, instead of being locked.

## Build & run

```sh
make
./epoll-server
```

Listens on port 8080, echoes back whatever it reads. `Ctrl+C` shuts it down cleanly.

## Status

Scaffold stage - single-`epoll`-instance-shared-across-threads architecture, not yet
load-tested. See the effort/project pages in the LLM wiki for the open decisions
(e.g. `SO_REUSEPORT` sharding as an alternative to the shared-instance model here).

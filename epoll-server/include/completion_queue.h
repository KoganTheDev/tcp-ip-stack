#pragma once

#include <functional>
#include <deque>
#include <mutex>

// The only safe way for a ThreadPool worker to hand a result back to the
// reactor thread. NetworkStack/TcpConnection are not thread-safe - a single
// TAP fd is the only "NIC" this stack has, and everything reading/writing it
// must happen on one thread. A worker computes a result, pushes a closure
// here (push() is the only method safe to call off the reactor thread), and
// the reactor's epoll loop wakes on get_fd() and runs every queued closure
// via drain_and_run() - on the reactor thread, where touching the stack is
// safe.
class CompletionQueue
{
public:
    CompletionQueue();
    ~CompletionQueue();

    CompletionQueue(const CompletionQueue&) = delete;
    CompletionQueue& operator=(const CompletionQueue&) = delete;

    int get_fd() const { return _event_fd; }

    // Safe to call from any thread.
    void push(std::function<void()> task);

    // Must only be called from the reactor thread, after get_fd() is
    // reported readable by epoll.
    void drain_and_run();

private:
    int _event_fd;
    std::mutex _mutex;
    std::deque<std::function<void()>> _tasks;
};

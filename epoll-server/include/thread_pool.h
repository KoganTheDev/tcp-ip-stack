#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>

class ThreadPool
{
public:
    explicit ThreadPool(size_t worker_count);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    void submit(std::function<void()> task);

    // Stops accepting work, lets the workers drain whatever is already queued,
    // and joins them. Idempotent, and called by the destructor - so an owner
    // that needs the workers provably stopped *before* its own members start
    // being destroyed can call it explicitly first. That is not a theoretical
    // concern: worker tasks capture their owner, so anything they touch has to
    // outlive the join, and member destruction order alone is a fragile way to
    // guarantee that.
    void shutdown();

private:
    void _worker_loop();

    std::vector<std::thread> _workers;
    std::queue<std::function<void()>> _tasks;
    std::mutex _queue_mutex;
    std::condition_variable _condition;
    std::atomic<bool> _stopping;
};

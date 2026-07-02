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

private:
    void _worker_loop();

    std::vector<std::thread> _workers;
    std::queue<std::function<void()>> _tasks;
    std::mutex _queue_mutex;
    std::condition_variable _condition;
    std::atomic<bool> _stopping;
};

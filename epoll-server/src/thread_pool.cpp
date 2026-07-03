#include "thread_pool.h"
#include <iostream>

ThreadPool::ThreadPool(size_t worker_count)
    : _stopping(false)
{
    for (size_t i = 0; i < worker_count; ++i)
    {
        this->_workers.emplace_back(&ThreadPool::_worker_loop, this);
    }
}

ThreadPool::~ThreadPool()
{
    this->_stopping = true;
    this->_condition.notify_all();

    for (std::thread& worker : this->_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
}

void ThreadPool::submit(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lock(this->_queue_mutex);
        this->_tasks.push(std::move(task));
    }
    this->_condition.notify_one();
}

void ThreadPool::_worker_loop()
{
    while (true)
    {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(this->_queue_mutex);
            this->_condition.wait(lock, [this]
            {
                return this->_stopping.load() || !this->_tasks.empty();
            });

            if (this->_stopping.load() && this->_tasks.empty())
            {
                return;
            }

            task = std::move(this->_tasks.front());
            this->_tasks.pop();
        }

        // a task throwing must never escape a worker thread - an uncaught
        // exception here calls std::terminate and takes the whole process down
        // with it, over what should be at most one broken connection
        try
        {
            task();
        }
        catch (const std::exception& e)
        {
            std::cerr << "ThreadPool: task threw: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "ThreadPool: task threw a non-std::exception" << std::endl;
        }
    }
}

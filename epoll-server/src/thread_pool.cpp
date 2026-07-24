#include "thread_pool.h"
#include "logger.h"

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
    // Set the stop flag AND signal under the lock. Setting _stopping without
    // it is a lost-wakeup: a worker sitting between "checked the predicate,
    // saw no reason to wake" and "actually blocked in wait()" is still holding
    // the lock, so taking it here guarantees the worker is genuinely blocked
    // (and registered as a waiter) before notify_all() fires - otherwise the
    // wakeup can be missed and join() below hangs forever.
    {
        std::lock_guard<std::mutex> lock(this->_queue_mutex);
        this->_stopping = true;
        this->_condition.notify_all();
    }

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
    // Push and signal under the same lock. Signalling after unlocking is a
    // valid idiom too (the task was queued under the lock), but keeping the
    // notify inside keeps the whole enqueue-and-wake atomic and free of the
    // "notify with no lock held" hazard - the per-submit cost is negligible on
    // this path.
    std::lock_guard<std::mutex> lock(this->_queue_mutex);
    this->_tasks.push(std::move(task));
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
            LOG_ERROR("ThreadPool: task threw: " << e.what());
        }
        catch (...)
        {
            LOG_ERROR("ThreadPool: task threw a non-std::exception");
        }
    }
}

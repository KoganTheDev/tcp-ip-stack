#include "completion_queue.h"
#include "exceptions.h"
#include "logger.h"

#include <sys/eventfd.h>
#include <unistd.h>

CompletionQueue::CompletionQueue()
{
    this->_event_fd = eventfd(0, EFD_NONBLOCK);
    if (this->_event_fd < 0)
    {
        throw EXCEPTION(SystemException, "eventfd() failed");
    }
}

CompletionQueue::~CompletionQueue()
{
    close(this->_event_fd);
}

void CompletionQueue::push(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lock(this->_mutex);
        this->_tasks.push_back(std::move(task));
    }

    uint64_t one = 1;
    if (write(this->_event_fd, &one, sizeof(one)) < 0)
    {
        // the reactor will still find this task next time it drains the
        // queue for any other reason - losing the wakeup isn't losing the work
        LOG_WARNING("CompletionQueue: failed to signal eventfd");
    }
}

void CompletionQueue::drain_and_run()
{
    uint64_t count = 0;
    while (read(this->_event_fd, &count, sizeof(count)) > 0)
    {
        // just draining the counter - the work itself lives in _tasks
    }

    std::deque<std::function<void()>> ready;
    {
        std::lock_guard<std::mutex> lock(this->_mutex);
        ready.swap(this->_tasks);
    }

    for (auto& task : ready)
    {
        try
        {
            task();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("CompletionQueue: task threw: " << e.what());
        }
        catch (...)
        {
            // These run on the REACTOR thread, so an escaping exception does
            // not merely lose one completion - it unwinds out of the event loop
            // and takes the whole server with it. ThreadPool has caught both
            // forms since it was written; this file caught only std::exception,
            // which left a narrow but real path to std::terminate on the one
            // thread that cannot afford to die.
            LOG_ERROR("CompletionQueue: task threw a non-standard exception");
        }
    }
}

#include "test.h"
#include "thread_pool.h"
#include "completion_queue.h"

#include <atomic>
#include <chrono>
#include <set>
#include <thread>
#include <vector>

// The only concurrent code in this project, and until now the only code with no
// tests at all. That mattered more than a coverage number: `make tsan` ran the
// whole suite under ThreadSanitizer and proved nothing, because every test in it
// was single-threaded. TSan can only report a race it actually observes, so a
// clean run over sequential code is not evidence of anything.
//
// The README claimed exercising this needed a TAP device. It does not - only
// ThreadPool's workers and CompletionQueue's eventfd, both of which work on any
// Linux machine with no privilege at all. Server does need a channel, but it
// already accepts an injected one.
namespace
{
    // Long enough that workers genuinely overlap, short enough not to slow the
    // suite. Used only where the test is about concurrency rather than result.
    void brief_pause()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

TEST(EveryTaskSubmittedToThePoolRunsExactlyOnce)
{
    constexpr int TASK_COUNT = 200;
    std::atomic<int> total{0};
    std::vector<std::atomic<int>> per_task(TASK_COUNT);
    for (auto& count : per_task)
    {
        count.store(0);
    }

    {
        ThreadPool pool(4);
        for (int i = 0; i < TASK_COUNT; i++)
        {
            pool.submit([&, i]()
            {
                per_task[i].fetch_add(1);
                total.fetch_add(1);
            });
        }
        // The destructor is the join. Asserting after the scope is what makes
        // this a test of "shutdown drains" rather than of "we waited long
        // enough", which would be a race dressed as a test.
    }

    test_assert(total.load() == TASK_COUNT,
                "every submitted task must run - got " + std::to_string(total.load()) +
                " of " + std::to_string(TASK_COUNT));
    for (int i = 0; i < TASK_COUNT; i++)
    {
        test_assert(per_task[i].load() == 1,
                    "task " + std::to_string(i) + " ran " +
                    std::to_string(per_task[i].load()) + " times, not once");
    }
}

TEST(TasksSubmittedFromManyThreadsAreAllRun)
{
    // submit() takes the same lock the workers pop under, so concurrent
    // producers are the case most likely to lose one.
    constexpr int PRODUCERS = 8;
    constexpr int PER_PRODUCER = 50;
    std::atomic<int> total{0};

    {
        ThreadPool pool(4);
        std::vector<std::thread> producers;
        for (int p = 0; p < PRODUCERS; p++)
        {
            producers.emplace_back([&pool, &total]()
            {
                for (int i = 0; i < PER_PRODUCER; i++)
                {
                    pool.submit([&total]() { total.fetch_add(1); });
                }
            });
        }
        for (std::thread& producer : producers)
        {
            producer.join();
        }
    }

    test_assert(total.load() == PRODUCERS * PER_PRODUCER,
                "no task may be lost across concurrent producers - got " +
                std::to_string(total.load()));
}

TEST(ShutdownDrainsQueuedWorkRatherThanDiscardingIt)
{
    // The distinction that matters on a clean exit: a pool that stops its
    // workers and throws away what is still queued silently loses whatever the
    // application had already handed over.
    constexpr int TASK_COUNT = 100;
    std::atomic<int> completed{0};

    ThreadPool pool(2);
    for (int i = 0; i < TASK_COUNT; i++)
    {
        pool.submit([&completed]()
        {
            brief_pause(); // guarantee a real backlog behind the first few
            completed.fetch_add(1);
        });
    }
    pool.shutdown();

    test_assert(completed.load() == TASK_COUNT,
                "shutdown must drain the queue, not discard it - " +
                std::to_string(completed.load()) + " of " + std::to_string(TASK_COUNT) + " ran");
}

TEST(ShutdownIsIdempotent)
{
    // Server calls shutdown() explicitly and then the destructor runs. A second
    // call joining already-joined threads would be undefined behaviour.
    ThreadPool pool(2);
    std::atomic<int> ran{0};
    pool.submit([&ran]() { ran.fetch_add(1); });

    pool.shutdown();
    pool.shutdown();

    test_assert(ran.load() == 1, "the task still ran exactly once");
}

TEST(AThrowingTaskDoesNotKillItsWorker)
{
    // A worker lost to an escaping exception is invisible: the pool keeps
    // accepting work and quietly runs it on fewer threads, until the last
    // worker dies and everything stops. Both exception forms are caught, which
    // is why the non-standard one is tested too.
    constexpr int TASK_COUNT = 60;
    std::atomic<int> survived{0};

    {
        ThreadPool pool(2);
        for (int i = 0; i < TASK_COUNT; i++)
        {
            if (i % 3 == 0)
            {
                pool.submit([]() { throw std::runtime_error("deliberate"); });
            }
            else if (i % 3 == 1)
            {
                pool.submit([]() { throw 42; }); // not derived from std::exception
            }
            else
            {
                pool.submit([&survived]() { survived.fetch_add(1); });
            }
        }
    }

    test_assert(survived.load() == TASK_COUNT / 3,
                "work submitted after a throwing task must still run - got " +
                std::to_string(survived.load()) + " of " + std::to_string(TASK_COUNT / 3));
}

TEST(SubmittingAfterShutdownIsRefusedRatherThanSilentlyQueued)
{
    // The workers are gone by then, so anything accepted here would sit in the
    // queue forever. Neither outcome runs the task; the difference is whether
    // the pool admits it. Silently accepting work that will never happen is how
    // an application ends up believing it sent a response.
    ThreadPool pool(2);
    pool.shutdown();

    std::atomic<int> ran{0};
    bool accepted = pool.submit([&ran]() { ran.fetch_add(1); });

    // Both assertions are needed, and the first is the one that bites. Without
    // the refusal the task is queued behind workers that have already exited,
    // so it never runs either - ran == 0 is true whether the pool refuses or
    // silently swallows it. Only the return value tells them apart.
    test_assert(!accepted, "the pool must report that it refused the task");
    test_assert(ran.load() == 0, "and the task must not run - there are no workers left");
    // And the pool must still destruct cleanly with that submission behind it,
    // which it would not if the task were sitting in the queue holding a
    // reference to a local that is about to go out of scope.
}

TEST(CompletionQueueRunsEverythingPushedToIt)
{
    CompletionQueue queue;
    std::atomic<int> total{0};

    for (int i = 0; i < 50; i++)
    {
        queue.push([&total]() { total.fetch_add(1); });
    }
    queue.drain_and_run();

    test_assert(total.load() == 50, "every pushed completion must run once");
}

TEST(CompletionQueueDeliversWorkPushedFromOtherThreads)
{
    // Its actual job: workers finish off the reactor thread and hand results
    // back for the reactor to apply. Nothing may be lost in that handover.
    constexpr int PRODUCERS = 6;
    constexpr int PER_PRODUCER = 40;
    CompletionQueue queue;
    std::atomic<int> total{0};

    std::vector<std::thread> producers;
    for (int p = 0; p < PRODUCERS; p++)
    {
        producers.emplace_back([&queue, &total]()
        {
            for (int i = 0; i < PER_PRODUCER; i++)
            {
                queue.push([&total]() { total.fetch_add(1); });
            }
        });
    }
    for (std::thread& producer : producers)
    {
        producer.join();
    }

    queue.drain_and_run();

    test_assert(total.load() == PRODUCERS * PER_PRODUCER,
                "no completion may be lost in the handover - got " + std::to_string(total.load()));
}

TEST(AThrowingCompletionDoesNotEscapeToTheReactor)
{
    // These run on the reactor thread, so an escaping exception does not lose
    // one completion - it unwinds out of the event loop and takes the server
    // with it. This file caught only std::exception until recently, leaving a
    // narrow path to std::terminate on the one thread that cannot afford it.
    CompletionQueue queue;
    std::atomic<int> ran_after{0};

    queue.push([]() { throw std::runtime_error("deliberate"); });
    queue.push([]() { throw 42; }); // not derived from std::exception
    queue.push([&ran_after]() { ran_after.fetch_add(1); });

    queue.drain_and_run(); // must return normally

    test_assert(ran_after.load() == 1,
                "completions queued behind a throwing one must still run");
}

TEST(DrainingAnEmptyCompletionQueueIsHarmless)
{
    // The reactor calls this whenever the eventfd reports readable, and a
    // spurious wakeup is possible by design: push() inserts under the mutex
    // before writing the fd, so a drain can legitimately find nothing.
    CompletionQueue queue;
    queue.drain_and_run();
    queue.drain_and_run();

    std::atomic<int> ran{0};
    queue.push([&ran]() { ran.fetch_add(1); });
    queue.drain_and_run();

    test_assert(ran.load() == 1, "the queue must still work after empty drains");
}

// Per-test watchdog: a test that runs too long is named, every thread's
// backtrace is dumped, and the process aborts.
//
// Why: once the build gate died with only "make: *** Terminated" and the last
// line "[ RUN ] ...", after an outer timeout killed the whole run. A hang left
// no evidence of where it was stuck. With this, a hang aborts the run within
// the limit, naming the test and showing where each thread is blocked.
//
// Limit: TEST_WATCHDOG_S seconds (0 disables). Default 120 s, which is about
// 25x the slowest regular test (~4 s). Sanitizer builds default to 5x that
// (they run several times slower) and the opt-in long runs (SOAK, or
// ECHO_REAL_STRESS) to an hour. An explicit TEST_WATCHDOG_S always wins.
//
// Backtraces: gdb attached to ourselves. Yama's ptrace_scope=1 only lets an
// ancestor trace a process, and gdb is our child, so startup calls
// prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY). Without gdb, or if it fails, only
// the test name and elapsed time are printed.
//
// Not racy: the current test and its start time live behind one mutex, and
// the thread sleeps on a condition variable that OnTestProgramEnd signals
// before joining, so it never outlives the run or keeps the process alive.
#include <gtest/gtest.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY (-1UL)
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define WATCHDOG_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define WATCHDOG_SANITIZED 1
#endif
#endif

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr long DEFAULT_LIMIT_S = 120;
#ifdef WATCHDOG_SANITIZED
    constexpr long SANITIZER_FACTOR = 5;
#else
    constexpr long SANITIZER_FACTOR = 1;
#endif
    constexpr long LONG_RUN_LIMIT_S = 3600;

    bool env_set(const char* name)
    {
        const char* v = std::getenv(name);
        return v != nullptr && *v != '\0' && std::string(v) != "0";
    }

    long limit_seconds()
    {
        if (const char* v = std::getenv("TEST_WATCHDOG_S"))
        {
            char* end = nullptr;
            const long s = std::strtol(v, &end, 10);
            if (end != v && s >= 0)
            {
                return s;
            }
        }
        if (env_set("SOAK") || env_set("ECHO_REAL_STRESS"))
        {
            return LONG_RUN_LIMIT_S;
        }
        return DEFAULT_LIMIT_S * SANITIZER_FACTOR;
    }

    // gdb's output goes to stderr. fork+exec only, so it is safe from a
    // thread of a process that has other threads.
    void dump_backtraces()
    {
        const std::string pid = std::to_string(getpid());
        const pid_t child = fork();
        if (child < 0)
        {
            return;
        }
        if (child == 0)
        {
            dup2(STDERR_FILENO, STDOUT_FILENO);
            execlp("gdb", "gdb", "-p", pid.c_str(), "-batch", "-ex", "thread apply all bt",
                   static_cast<char*>(nullptr));
            _exit(127);
        }
        for (int waited_s = 0; waited_s < 60; ++waited_s)
        {
            int status = 0;
            if (waitpid(child, &status, WNOHANG) != 0)
            {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
                {
                    std::fprintf(stderr, "[ WATCHDOG ] gdb not available, no backtraces\n");
                }
                return;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
    }

    class Watchdog : public ::testing::EmptyTestEventListener
    {
    public:
        void OnTestProgramStart(const ::testing::UnitTest& /*unit*/) override
        {
            _limit_s = limit_seconds();
            if (_limit_s == 0)
            {
                return;
            }
            // The thread must not take process-directed signals: the SIGURG
            // differential tests count signals delivered to the process, and a
            // second thread that does not block them would swallow some. The
            // new thread inherits the creator's mask, so block around creation.
            sigset_t all;
            sigset_t saved;
            sigfillset(&all);
            pthread_sigmask(SIG_BLOCK, &all, &saved);
            _thread = std::thread([this] { run(); });
            pthread_sigmask(SIG_SETMASK, &saved, nullptr);
        }

        void OnTestStart(const ::testing::TestInfo& info) override
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _name = std::string(info.test_suite_name()) + "." + info.name();
            _start = Clock::now();
            _running = true;
        }

        void OnTestEnd(const ::testing::TestInfo& /*info*/) override
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _running = false;
        }

        void OnTestProgramEnd(const ::testing::UnitTest& /*unit*/) override
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                _stop = true;
            }
            _cv.notify_all();
            if (_thread.joinable())
            {
                _thread.join();
            }
        }

    private:
        void run()
        {
            std::unique_lock<std::mutex> lock(_mutex);
            while (!_stop)
            {
                _cv.wait_for(lock, std::chrono::seconds(1));
                if (_stop || !_running)
                {
                    continue;
                }
                const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - _start).count();
                if (elapsed >= _limit_s)
                {
                    std::fprintf(stderr,
                                 "\n[ WATCHDOG ] %s still running after %lld s (limit %ld s, TEST_WATCHDOG_S)\n",
                                 _name.c_str(), static_cast<long long>(elapsed), _limit_s);
                    std::fflush(stderr);
                    dump_backtraces();
                    std::fprintf(stderr, "[ WATCHDOG ] aborting\n");
                    std::abort();
                }
            }
        }

        std::mutex _mutex;
        std::condition_variable _cv;
        std::thread _thread;
        std::string _name;
        Clock::time_point _start;
        long _limit_s = 0;
        bool _running = false;
        bool _stop = false;
    };

    // Registered at static-init time because main() comes from gmock_main.
    const bool REGISTERED = []
    {
        // Harmless if it fails (non-Yama kernel): gdb then just may not attach.
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        ::testing::UnitTest::GetInstance()->listeners().Append(new Watchdog);
        return true;
    }();
}

// Hangs forever, but only in the child of WatchdogTest.AbortsAHangNamingTheTest:
// DISABLED_ keeps it out of every normal run.
TEST(WatchdogChild, DISABLED_HangsForever)
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Re-executes this binary on the hanging test with a 2 s limit and checks that
// it dies by SIGABRT, quickly, with the test named on stderr.
TEST(WatchdogTest, AbortsAHangNamingTheTest)
{
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    const auto start = Clock::now();
    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0)
    {
        dup2(fds[1], STDERR_FILENO);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        setenv("TEST_WATCHDOG_S", "2", 1);
        execl("/proc/self/exe", "run_tests", "--gtest_also_run_disabled_tests",
              "--gtest_filter=WatchdogChild.DISABLED_HangsForever", static_cast<char*>(nullptr));
        _exit(127);
    }
    close(fds[1]);
    std::string output;
    char buf[4096];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof(buf))) > 0)
    {
        output.append(buf, static_cast<size_t>(n));
    }
    close(fds[0]);
    int status = 0;
    ASSERT_EQ(waitpid(child, &status, 0), child);
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - start).count();

    ASSERT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT) << "status " << status << "\n" << output;
    ASSERT_TRUE(output.find("WatchdogChild.DISABLED_HangsForever still running") != std::string::npos) << output;
    // 2 s limit + up to 1 s tick + gdb attach; far below a real hang.
    ASSERT_LT(elapsed, 50) << output;
    if (system("command -v gdb >/dev/null 2>&1") == 0)
    {
        ASSERT_TRUE(output.find("Thread") != std::string::npos) << "no backtrace in:\n" << output;
    }
}

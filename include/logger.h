#pragma once

#include <string>
#include <mutex>
#include <fstream>
#include <sstream>

enum class LogLevel
{
    DEBUG,
    INFO,
    WARNING,
    ERROR,
};

// A thread-safe replacement for the raw std::cerr/std::cout calls that used
// to be scattered across this project - real motivation: epoll-server's
// ThreadPool runs up to 4 worker threads concurrently (see thread_pool.h),
// and std::cerr's own operator<< chaining isn't atomic across multiple
// calls, so two threads logging at once could interleave/tear a line of
// output. Every log() call is serialized under one mutex instead.
//
// A Meyer's singleton (like EXCEPTION() in exceptions.h is a free macro
// rather than an object), since there's no existing "context" object
// threaded through the ~20 call sites this replaces - forcing one in just
// to hand a Logger reference around would be a bigger change than the
// logging itself.
class Logger
{
public:
    static Logger& instance();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Below the configured minimum level, returns immediately without
    // taking the lock - cheap for DEBUG-level calls left in place in a
    // run that isn't asking for them.
    void log(LogLevel level, const std::string& message,
              const std::string& file, const std::string& func, unsigned int line);

    // Overrides whatever LOG_LEVEL set (or its INFO default) - independent
    // of the environment, mainly for tests.
    void set_level(LogLevel level);

private:
    Logger();

    static const char* _level_name(LogLevel level);
    static std::string _timestamp();

    std::mutex _mutex;
    LogLevel _min_level;
    std::ofstream _file_sink; // closed (never opened) unless LOG_FILE was set
};

// Stream-style so existing "x << a << b" call sites need minimal rewriting -
// the __FILE__/__func__/__LINE__ auto-capture mirrors EXCEPTION()'s macro in
// exceptions.h. (std::ostringstream() << x).str() is the same idiom used to
// build a message inline for a thrown exception - operator<< on a temporary
// stream is legal; the temporary lives until the end of the full expression.
#define LOG_DEBUG(x)   Logger::instance().log(LogLevel::DEBUG,   (std::ostringstream() << x).str(), __FILE__, __func__, __LINE__)
#define LOG_INFO(x)    Logger::instance().log(LogLevel::INFO,    (std::ostringstream() << x).str(), __FILE__, __func__, __LINE__)
#define LOG_WARNING(x) Logger::instance().log(LogLevel::WARNING, (std::ostringstream() << x).str(), __FILE__, __func__, __LINE__)
#define LOG_ERROR(x)   Logger::instance().log(LogLevel::ERROR,   (std::ostringstream() << x).str(), __FILE__, __func__, __LINE__)

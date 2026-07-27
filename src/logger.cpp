#include "logger.h"

#include <cstdlib>
#include <ctime>
#include <iostream>

Logger& Logger::instance()
{
    static Logger logger;
    return logger;
}

Logger::Logger()
    : _min_level(LogLevel::INFO)
{
    const char* level_env = std::getenv("LOG_LEVEL");
    if (level_env)
    {
        std::string level_str(level_env);
        if (level_str == "DEBUG") this->_min_level = LogLevel::DEBUG;
        else if (level_str == "INFO") this->_min_level = LogLevel::INFO;
        else if (level_str == "WARNING") this->_min_level = LogLevel::WARNING;
        else if (level_str == "ERROR") this->_min_level = LogLevel::ERROR;
        // anything else (typo, unrecognized value): keep the INFO default
        // rather than fail the program over a malformed env var
    }

    const char* file_env = std::getenv("LOG_FILE");
    if (file_env)
    {
        this->_file_sink.open(file_env, std::ios::app);
        if (!this->_file_sink.is_open())
        {
            std::cerr << "Logger: failed to open LOG_FILE=\"" << file_env
                       << "\" - continuing with console-only logging" << std::endl;
        }
    }
}

void Logger::set_level(LogLevel level)
{
    std::lock_guard<std::mutex> lock(this->_mutex);
    this->_min_level = level;
}

const char* Logger::_level_name(LogLevel level)
{
    switch (level)
    {
    case LogLevel::DEBUG:   return "DEBUG";
    case LogLevel::INFO:    return "INFO";
    case LogLevel::WARNING: return "WARNING";
    case LogLevel::ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

std::string Logger::_timestamp()
{
    std::time_t now = std::time(nullptr);
    std::tm local_tm{};
    localtime_r(&now, &local_tm); // thread-safe, unlike ctime()/localtime()

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_tm);
    return std::string(buffer);
}

void Logger::log(LogLevel level, const std::string& message,
                  const std::string& file, const std::string& func, unsigned int line)
{
    if (level < this->_min_level)
    {
        return; // cheap: no lock taken for a level nobody asked to see
    }

    std::ostringstream formatted;
    formatted << "[" << _timestamp() << "] [" << _level_name(level) << "] "
              << file << ":" << line << " (" << func << "): " << message;

    std::lock_guard<std::mutex> lock(this->_mutex);
    std::cerr << formatted.str() << std::endl;
    if (this->_file_sink.is_open())
    {
        this->_file_sink << formatted.str() << std::endl;
    }
}

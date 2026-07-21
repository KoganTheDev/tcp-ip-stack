#include "test.h"
#include "logger.h"

#include <functional>
#include <iostream>
#include <sstream>

namespace
{
    // Logger always writes to std::cerr directly rather than caching a
    // stream reference at construction, so swapping its rdbuf() is enough
    // to capture output for a test - no change to Logger itself needed.
    std::string capture_stderr(std::function<void()> action)
    {
        std::ostringstream captured;
        std::streambuf* old_buf = std::cerr.rdbuf(captured.rdbuf());
        action();
        std::cerr.rdbuf(old_buf);
        return captured.str();
    }
}

TEST(BelowMinimumLevelProducesNoOutput)
{
    Logger::instance().set_level(LogLevel::WARNING);

    std::string output = capture_stderr([]
    {
        LOG_INFO("this should not appear");
    });

    test_assert(output.empty(), "a message below the configured minimum level should produce no output");

    Logger::instance().set_level(LogLevel::INFO); // restore the default for any test that runs after this one
}

TEST(AtOrAboveMinimumLevelProducesFormattedOutput)
{
    Logger::instance().set_level(LogLevel::WARNING);

    std::string output = capture_stderr([]
    {
        LOG_ERROR("something went wrong");
    });

    test_assert(!output.empty(), "a message at or above the configured minimum level should produce output");
    test_assert(output.find("ERROR") != std::string::npos, "the log line should include the level name");
    test_assert(output.find("something went wrong") != std::string::npos, "the log line should include the message text");

    Logger::instance().set_level(LogLevel::INFO);
}

// Same level as the threshold (not just strictly above) must still log -
// off-by-one is an easy mistake in a "< min_level" filter check.
TEST(MessageExactlyAtMinimumLevelIsLogged)
{
    Logger::instance().set_level(LogLevel::WARNING);

    std::string output = capture_stderr([]
    {
        LOG_WARNING("borderline message");
    });

    test_assert(!output.empty(), "a message exactly at the configured minimum level should still be logged");
    test_assert(output.find("WARNING") != std::string::npos, "the log line should reflect the WARNING level");

    Logger::instance().set_level(LogLevel::INFO);
}

// The stream-style macro must support chained "<<" the same way the
// std::cerr call sites it replaces did - not just a single string literal.
TEST(MacroSupportsStreamStyleConcatenation)
{
    Logger::instance().set_level(LogLevel::INFO);

    std::string output = capture_stderr([]
    {
        LOG_INFO("value=" << 42 << ", ok=" << true);
    });

    test_assert(output.find("value=42, ok=1") != std::string::npos,
        "the macro should support chained << concatenation like the std::cerr calls it replaces");
}

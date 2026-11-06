#include "test_support.h"
#include "logger.h"
#include "sim/pkt_runner.h"
#include "sim/sim_fixture.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

// Runs every tests/scripts/*.pkt (not subdirectories) as one test each. The
// syntax is documented in tests/include/sim/pkt_runner.h.
//
// tests/scripts/pending/ holds scripts for behaviour the stack does not have
// yet - each fails today, on purpose. They are not run by default; point
// PKT_SCRIPTS at a file or directory to run those instead:
//
//     PKT_SCRIPTS=tests/scripts/pending ./build/debug/run_tests --gtest_filter='*PktScript*'
//
// When one fails, the exchange is written to <build dir>/sim-pcaps like the
// simulator's captures, and the failure shows the script line, what the stack
// sent instead, and the trace up to that point.
namespace
{
    std::vector<std::string> script_paths()
    {
        std::string where = PKT_SCRIPT_DIR;
        if (const char* env = std::getenv("PKT_SCRIPTS"); env != nullptr && *env != '\0')
            where = env;
        std::vector<std::string> paths;
        std::error_code error;
        if (std::filesystem::is_regular_file(where, error))
            return {where};
        for (const auto& entry : std::filesystem::directory_iterator(where, error))
        {
            if (entry.is_regular_file() && entry.path().extension() == ".pkt")
                paths.push_back(entry.path().string());
        }
        std::sort(paths.begin(), paths.end()); // directory order is unspecified
        return paths;
    }

    std::string test_name(const ::testing::TestParamInfo<std::string>& info)
    {
        std::string name = std::filesystem::path(info.param).stem().string();
        for (char& c : name)
        {
            if (!std::isalnum(static_cast<unsigned char>(c)))
                c = '_';
        }
        return name;
    }
}

class PktScript : public ::testing::TestWithParam<std::string>
{};

TEST_P(PktScript, Passes)
{
    if (std::getenv("LOG_LEVEL") == nullptr)
        Logger::instance().set_level(LogLevel::WARNING);
    PktResult result = run_pkt_script(GetParam());
    if (std::getenv("LOG_LEVEL") == nullptr)
        Logger::instance().set_level(LogLevel::INFO);
    if (!result.passed)
    {
        sim_dump_capture(result.capture, "", "script exchange");
        sim_dump_trace(result.capture, "");
    }
    ASSERT_TRUE(result.passed) << result.message;
}

// Allowed to be empty: PKT_SCRIPTS may name a directory with no scripts.
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(PktScript);
INSTANTIATE_TEST_SUITE_P(Scripts, PktScript, ::testing::ValuesIn(script_paths()), test_name);

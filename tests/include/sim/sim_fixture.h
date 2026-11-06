#pragma once

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include "logger.h"
#include "sim/pcap_writer.h"
#include "sim/sim_network.h"
#include "sim/tcp_frame.h"

// Where failure captures go: $SIM_PCAP_DIR if set, else <build dir>/sim-pcaps
// (SIM_PCAP_DEFAULT_DIR is defined by CMake), else ./sim-pcaps.
inline std::string sim_pcap_dir()
{
    if (const char* env = std::getenv("SIM_PCAP_DIR"); env != nullptr && *env != '\0')
        return env;
#ifdef SIM_PCAP_DEFAULT_DIR
    return SIM_PCAP_DEFAULT_DIR;
#else
    return "sim-pcaps";
#endif
}

// "<Suite>.<Test><suffix>.pcap" for the running test, with the '/' that
// parameterized names contain ("Seeds/SimTransfer.OneWay/17") made safe for a
// file name.
inline std::string sim_pcap_path_for_current_test(const std::string& suffix)
{
    const ::testing::TestInfo* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string name = std::string(info->test_suite_name()) + "." + info->name();
    for (char& c : name)
    {
        if (c == '/')
            c = '_';
    }
    return sim_pcap_dir() + "/" + name + suffix + ".pcap";
}

// Writes a capture for the running test and says where, in the test output
// and as a JUnit XML property. Returns the path, or "" if it could not write.
inline std::string sim_dump_capture(const PcapWriter& capture, const std::string& suffix, const std::string& what)
{
    std::error_code ignored;
    std::filesystem::create_directories(sim_pcap_dir(), ignored);
    std::string path = sim_pcap_path_for_current_test(suffix);
    if (!capture.write_file(path))
    {
        std::cerr << "[ SIM PCAP ] could not write " << path << "\n";
        return "";
    }
    std::cerr << "[ SIM PCAP ] " << what << " (" << capture.size() << " frames): " << path << "\n";
    ::testing::Test::RecordProperty("sim_pcap" + suffix, path);
    return path;
}

// The same capture as text, one tcpdump-like line per frame, for machines
// without tcpdump and for pasting into a bug report.
inline void sim_dump_trace(const PcapWriter& capture, const std::string& suffix)
{
    std::string path = sim_pcap_path_for_current_test(suffix);
    path.replace(path.size() - 5, 5, ".txt");
    std::ofstream out(path);
    for (const PcapWriter::Record& record : capture.records())
    {
        out << std::setw(10) << std::fixed << std::setprecision(3) << static_cast<double>(record.timestamp_us) / 1000.0
            << " ms  " << tcp_frame::describe(record.frame) << "\n";
    }
    if (out)
        std::cerr << "[ SIM PCAP ] as text: " << path << "\n";
}

// Base fixture for simulator tests. The test creates `net`; if the test
// fails, TearDown writes what the network carried to
// <build dir>/sim-pcaps/<Suite>.<Test>.pcap (frames as delivered) and
// ...<Test>.tx.pcap (frames as transmitted, drops included), a .txt rendering
// of each, and prints the paths. Passing tests write nothing.
//
// Also turns the stack's logging down to warnings for the test's duration: a
// lossy transfer logs every retransmission at INFO, which buries the one
// line of output that matters. Setting LOG_LEVEL in the environment (e.g.
// LOG_LEVEL=DEBUG to trace one seed) overrides that.
class SimFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        _quieted_logger = std::getenv("LOG_LEVEL") == nullptr;
        if (_quieted_logger)
            Logger::instance().set_level(LogLevel::WARNING);
    }

    void TearDown() override
    {
        if (HasFailure() && net != nullptr)
        {
            std::cerr << "[ SIM PCAP ] seed " << net->seed() << ", failed at t=" << net->now_ms() << "ms\n"
                      << net->describe_links();
            sim_dump_capture(net->delivered_capture(), "", "frames as delivered");
            sim_dump_capture(net->transmitted_capture(), ".tx", "frames as transmitted");
            sim_dump_trace(net->delivered_capture(), "");
            sim_dump_trace(net->transmitted_capture(), ".tx");
        }
        // Destroyed here rather than with the fixture so the stacks go before
        // the logger level is restored (they may log while shutting down).
        net.reset();
        if (_quieted_logger)
            Logger::instance().set_level(LogLevel::INFO); // the default, which other suites expect
    }

    std::unique_ptr<SimNetwork> net;

private:
    bool _quieted_logger = false;
};

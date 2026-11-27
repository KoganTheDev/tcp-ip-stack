#include <gtest/gtest.h>

#include <iostream>
#include <string>
#include <vector>

#include "bind_matrix.h"

// bind() and listen() conflicts as Linux decides them (inet_csk_bind_conflict,
// udp_lib_lport_inuse), per family, per local address, with SO_REUSEADDR and
// SO_REUSEPORT. The rows and scenarios are in bind_matrix.h and below; this
// file runs them on ustack against the probed answers, and on the kernel
// against ustack.
using namespace bind_matrix;

namespace
{
    // The scenarios that need more than two binds: each returns a list of
    // "step: result" lines.
    template <class S, class Settle>
    std::vector<std::string> run_scenarios(S& stack, Settle settle)
    {
        std::vector<std::string> trace;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };
        auto call = [](int rc)
        {
            return rc == 0 ? std::string("ok") : result_text(errno);
        };

        // Two SO_REUSEADDR sockets bound to one port: the first to listen
        // wins, the other's listen() is refused.
        {
            int a = open_socket(stack, SOCK_STREAM, Side{AF_INET, "0.0.0.0", RA});
            int b = open_socket(stack, SOCK_STREAM, Side{AF_INET, "0.0.0.0", RA});
            note("RA bind a", bind_side(stack, a, SOCK_STREAM, Side{AF_INET, "0.0.0.0", RA}, 0));
            uint16_t port = bound_port(stack, a);
            note("RA bind b", bind_side(stack, b, SOCK_STREAM, Side{AF_INET, "0.0.0.0", RA}, port));
            note("RA listen b", call(stack.listen(b, 8)));
            note("RA listen a", call(stack.listen(a, 8)));
            stack.close(a);
            stack.close(b);
        }

        // SO_REUSEPORT is read when the next socket binds: set on a listener
        // after the fact, it still lets another SO_REUSEPORT socket in.
        {
            int a = open_socket(stack, SOCK_STREAM, Side{AF_INET, "127.0.0.1", 0});
            note("late RP bind a", bind_side(stack, a, SOCK_STREAM, Side{AF_INET, "127.0.0.1", LISTEN}, 0));
            uint16_t port = bound_port(stack, a);
            int one = 1;
            note("late RP set", call(stack.setsockopt(a, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))));
            int b = open_socket(stack, SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP});
            note("late RP bind b", bind_side(stack, b, SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, port));
            stack.close(a);
            stack.close(b);
        }

        // A connection outlives its listener - in TIME_WAIT, or still open -
        // and holds the port against a new bind unless both set
        // SO_REUSEADDR (or both SO_REUSEPORT).
        struct Leftover
        {
            const char* name;
            bool time_wait; // else still ESTABLISHED
            int listener_flags;
            int new_flags;
            const char* new_address;
        };
        const Leftover leftovers[] = {
            {"TW noRA/noRA", true, 0, 0, "127.0.0.1"},
            {"TW noRA/RA", true, 0, RA, "127.0.0.1"},
            {"TW RA/RA", true, RA, RA, "127.0.0.1"},
            {"TW RA/noRA", true, RA, 0, "127.0.0.1"},
            {"TW noRA/noRA other address", true, 0, 0, "127.0.0.2"},
            {"TW noRA/noRA wildcard", true, 0, 0, "0.0.0.0"},
            {"TW RA/RA wildcard", true, RA, RA, "0.0.0.0"},
            {"TW RP/RP", true, RP, RP, "127.0.0.1"},
            {"TW RP/noRP", true, RP, 0, "127.0.0.1"},
            {"EST noRA/noRA", false, 0, 0, "127.0.0.1"},
            {"EST RA/RA", false, RA, RA, "127.0.0.1"},
            {"EST noRA/RA", false, 0, RA, "127.0.0.1"},
        };
        for (const Leftover& leftover : leftovers)
        {
            Side listen_side{AF_INET, "127.0.0.1", leftover.listener_flags | LISTEN};
            int listener = open_socket(stack, SOCK_STREAM, listen_side);
            REQUIRE_TRUE(bind_side(stack, listener, SOCK_STREAM, listen_side, 0) == "ok", "listener");
            uint16_t port = bound_port(stack, listener);
            int client = stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            Address target = make_address(AF_INET, "127.0.0.1", port);
            static_cast<void>(stack.connect(client, target.get(), target.length));
            settle(50);
            int accepted = stack.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
            REQUIRE_TRUE(accepted >= 0, "accept");
            if (leftover.time_wait)
            {
                stack.close(accepted); // the server closes first: its end goes to TIME_WAIT
                settle(50);
                stack.close(client);
                settle(50);
            }
            stack.close(listener);
            Side new_side{AF_INET, leftover.new_address, leftover.new_flags};
            int fresh = open_socket(stack, SOCK_STREAM, new_side);
            std::string bound = bind_side(stack, fresh, SOCK_STREAM, new_side, port);
            std::string listened = bound == "ok" ? call(stack.listen(fresh, 8)) : "-";
            note(leftover.name, bound + " listen " + listened);
            stack.close(fresh);
            if (!leftover.time_wait)
            {
                stack.close(accepted);
                stack.close(client);
                settle(50);
            }
        }

        // An active open holds its ephemeral port: an explicit bind to it is
        // refused, SO_REUSEADDR or not (the connecting socket did not set it).
        {
            Side listen_side{AF_INET, "127.0.0.1", LISTEN};
            int listener = open_socket(stack, SOCK_STREAM, listen_side);
            REQUIRE_TRUE(bind_side(stack, listener, SOCK_STREAM, listen_side, 0) == "ok", "listener");
            uint16_t port = bound_port(stack, listener);
            int client = stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            Address target = make_address(AF_INET, "127.0.0.1", port);
            static_cast<void>(stack.connect(client, target.get(), target.length));
            settle(50);
            uint16_t client_port = bound_port(stack, client);
            int plain = open_socket(stack, SOCK_STREAM, Side{AF_INET, "127.0.0.1", 0});
            note("bind a client's port",
                 bind_side(stack, plain, SOCK_STREAM, Side{AF_INET, "127.0.0.1", 0}, client_port));
            int reuse = open_socket(stack, SOCK_STREAM, Side{AF_INET, "127.0.0.1", RA});
            note("bind a client's port RA",
                 bind_side(stack, reuse, SOCK_STREAM, Side{AF_INET, "127.0.0.1", RA}, client_port));
            for (int fd : {plain, reuse, client, listener})
            {
                stack.close(fd);
            }
            settle(50);
        }
        return trace;
    }

    std::vector<std::string> expected_scenarios()
    {
        return {
            "RA bind a: ok",
            "RA bind b: ok",
            "RA listen b: ok",
            "RA listen a: EADDRINUSE",
            "late RP bind a: ok",
            "late RP set: ok",
            "late RP bind b: ok",
            "TW noRA/noRA: EADDRINUSE listen -",
            "TW noRA/RA: EADDRINUSE listen -",
            "TW RA/RA: ok listen ok",
            "TW RA/noRA: EADDRINUSE listen -",
            "TW noRA/noRA other address: ok listen ok",
            "TW noRA/noRA wildcard: EADDRINUSE listen -",
            "TW RA/RA wildcard: ok listen ok",
            "TW RP/RP: ok listen ok",
            "TW RP/noRP: EADDRINUSE listen -",
            "EST noRA/noRA: EADDRINUSE listen -",
            "EST RA/RA: ok listen ok",
            "EST noRA/RA: EADDRINUSE listen -",
            "bind a client's port: EADDRINUSE",
            "bind a client's port RA: EADDRINUSE",
        };
    }

    std::string row_text(int type, const Row& row)
    {
        return std::string(type == SOCK_STREAM ? "tcp " : "udp ") + side_text(row.first) + " / "
               + side_text(row.second);
    }
}

TEST(BindRules, MatrixMatchesLinux)
{
    UstackLoopback harness;
    std::string report;
    for (int type : {SOCK_STREAM, SOCK_DGRAM})
    {
        for (const Row& row : rows())
        {
            std::string expected = std::string("ok/") + (type == SOCK_STREAM ? row.tcp : row.udp);
            std::string got = run_row(harness.stack(), type, row);
            if (got != expected)
            {
                report += "  " + row_text(type, row) + ": got " + got + ", Linux " + expected + "\n";
            }
        }
    }
    ASSERT_TRUE(report.empty()) << "bind rules that differ from Linux:\n" << report;
}

TEST(BindRules, ScenariosMatchLinux)
{
    UstackLoopback harness;
    std::vector<std::string> got = run_scenarios(harness.stack(), [&](int ms) { harness.settle(ms); });
    std::vector<std::string> expected = expected_scenarios();
    ASSERT_EQ(got.size(), expected.size());
    std::string report;
    for (size_t i = 0; i < got.size(); i++)
    {
        if (got[i] != expected[i])
        {
            report += "  got   " + got[i] + "\n  Linux " + expected[i] + "\n";
        }
    }
    ASSERT_TRUE(report.empty()) << report;
}

// The same rows and scenarios on the kernel running the suite.
TEST(BindRulesDifferential, MatrixAndScenariosMatchTheKernel)
{
    if (!kernel_has_loopback_addresses())
    {
        GTEST_SKIP() << "::1 or 127.0.0.2 cannot be bound here";
    }
    UstackLoopback harness;
    ustack::KernelStack kernel;
    std::string report;
    for (int type : {SOCK_STREAM, SOCK_DGRAM})
    {
        for (const Row& row : rows())
        {
            std::string ours = run_row(harness.stack(), type, row);
            std::string theirs = run_row(kernel, type, row);
            if (ours != theirs)
            {
                report += "  " + row_text(type, row) + ": ustack " + ours + ", kernel " + theirs + "\n";
            }
        }
    }
    std::vector<std::string> ours = run_scenarios(harness.stack(), [&](int ms) { harness.settle(ms); });
    std::vector<std::string> theirs = run_scenarios(kernel, [](int ms) { usleep(static_cast<useconds_t>(ms) * 1000); });
    ASSERT_EQ(ours.size(), theirs.size());
    for (size_t i = 0; i < ours.size(); i++)
    {
        if (ours[i] != theirs[i])
        {
            report += "  ustack " + ours[i] + "\n  kernel " + theirs[i] + "\n";
        }
    }
    ASSERT_TRUE(report.empty()) << "differences from the kernel:\n" << report;
}

#include <gtest/gtest.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// getsockopt(TCP_INFO) on ustack::Stack and on the kernel (KernelStack), as one
// scenario each. Values that depend on timing, the congestion state or the
// path (rtt, rto, mss, windows) cannot match exactly, so the trace records
// what an application relies on: the state, the options that were negotiated,
// whether a field is set at all, the units (an rtt of at least 1000 microsec
// where the path is slower than a millisecond, cwnd and ssthresh in segments),
// the counters that follow the sequence space exactly (bytes_acked counts the
// SYN, bytes_received does not), and the optlen rules. Compared line by line,
// as in test_stack_differential.cpp.
//
// Found by probing: on Linux a socket in TIME_WAIT reads TCP_CLOSE (the
// timewait sock has taken over), and an unconnected socket reads TCP_CLOSE with
// rto 1 s, cwnd 10, ssthresh 0x7fffffff and snd_mss 536.
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    std::string flag(bool value)
    {
        return value ? "yes" : "no";
    }

    template <class S>
    std::string info_shape(S& s, int fd)
    {
        tcp_info info;
        std::memset(&info, 0, sizeof(info));
        socklen_t length = sizeof(info);
        if (s.getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) != 0)
        {
            return failure();
        }
        return "len=" + std::to_string(length) + " state=" + std::to_string(info.tcpi_state)
               + " opts=" + std::to_string(info.tcpi_options) + " wscale=" + flag(info.tcpi_snd_wscale != 0) + "/"
               + flag(info.tcpi_rcv_wscale != 0) + " rto>=200ms=" + flag(info.tcpi_rto >= 200000)
               + " rto<=60s=" + flag(info.tcpi_rto <= 60000000) + " rtt>0=" + flag(info.tcpi_rtt > 0)
               + " rtt<10s=" + flag(info.tcpi_rtt < 10000000) + " mss>0=" + flag(info.tcpi_snd_mss > 0)
               + " cwnd=" + std::to_string(info.tcpi_snd_cwnd >= 1 && info.tcpi_snd_cwnd <= 100 ? 1 : 0)
               + " ssthresh_inf=" + flag(info.tcpi_snd_ssthresh == 0x7fffffff)
               + " unacked=" + std::to_string(info.tcpi_unacked) + " retrans=" + std::to_string(info.tcpi_retransmits)
               + "/" + std::to_string(info.tcpi_total_retrans) + " acked=" + std::to_string(info.tcpi_bytes_acked)
               + " received=" + std::to_string(info.tcpi_bytes_received)
               + " rcv_space>0=" + flag(info.tcpi_rcv_space > 0);
    }

    template <class S>
    std::string optlen_case(S& s, int fd, socklen_t given)
    {
        char buffer[1024];
        std::memset(buffer, 0xAA, sizeof(buffer));
        socklen_t length = given;
        if (s.getsockopt(fd, IPPROTO_TCP, TCP_INFO, buffer, &length) != 0)
        {
            return failure();
        }
        size_t untouched = 0;
        while (untouched < sizeof(buffer) && static_cast<unsigned char>(buffer[sizeof(buffer) - 1 - untouched]) == 0xAA)
        {
            untouched++;
        }
        return "len=" + std::to_string(length) + " tail_untouched=" + flag(untouched >= sizeof(buffer) - given);
    }

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    template <class H>
    Pair connect_pair(H& h)
    {
        using S = typename H::StackT;
        S& server = h.server_stack();
        S& client = h.client_stack();
        int listener = server.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(listener >= 0, failure());
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        REQUIRE_TRUE(server.listen(listener, 8) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        int cfd = client.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(cfd >= 0, failure());
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, failure());
        h.settle(50);
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        return {cfd, sfd, listener};
    }

    template <class H>
    std::vector<std::string> run_scenario()
    {
        using S = typename H::StackT;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };

        int loose = client.socket(AF_INET, SOCK_STREAM, 0);
        note("fresh socket", info_shape(client, loose));

        Pair pair = connect_pair(h);
        note("listener", info_shape(server, pair.listener));
        note("client, connected", info_shape(client, pair.client));
        note("server, connected", info_shape(server, pair.server));

        std::string data(20000, 'q');
        size_t sent = 0;
        for (int i = 0; i < 50 && sent < data.size(); i++)
        {
            ssize_t n = client.send(pair.client, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            sent += n > 0 ? static_cast<size_t>(n) : 0;
            h.settle(20);
        }
        std::string sink(65536, '\0');
        size_t got = 0;
        for (int i = 0; i < 50 && got < sent; i++)
        {
            ssize_t n = server.recv(pair.server, sink.data(), sink.size(), MSG_DONTWAIT);
            got += n > 0 ? static_cast<size_t>(n) : 0;
            h.settle(20);
        }
        h.settle(500);
        note("bytes sent", std::to_string(sent) + " of " + std::to_string(data.size()));
        note("client, after 20000 bytes", info_shape(client, pair.client));
        note("server, after 20000 bytes", info_shape(server, pair.server));

        note("optlen 0", optlen_case(client, pair.client, 0));
        note("optlen 1", optlen_case(client, pair.client, 1));
        note("optlen 8", optlen_case(client, pair.client, 8));
        note("optlen 100", optlen_case(client, pair.client, 100));
        note("optlen 1024", optlen_case(client, pair.client, 1024));
        {
            tcp_info info;
            socklen_t length = static_cast<socklen_t>(-1);
            int rc = client.getsockopt(pair.client, IPPROTO_TCP, TCP_INFO, &info, &length);
            note("optlen -1", rc == 0 ? "ok" : failure());
            length = sizeof(info);
            rc = client.getsockopt(pair.client, IPPROTO_TCP, TCP_INFO, nullptr, &length);
            note("optval null", rc == 0 ? "ok" : failure());
            rc = client.setsockopt(pair.client, IPPROTO_TCP, TCP_INFO, &info, sizeof(info));
            note("setsockopt", rc == 0 ? "ok" : failure());
            int udp = client.socket(AF_INET, SOCK_DGRAM, 0);
            length = sizeof(info);
            rc = client.getsockopt(udp, IPPROTO_TCP, TCP_INFO, &info, &length);
            note("udp socket", rc == 0 ? "ok" : failure());
        }

        REQUIRE_TRUE(client.shutdown(pair.client, SHUT_WR) == 0, failure());
        h.settle(500);
        note("client, FIN_WAIT2", info_shape(client, pair.client));
        note("server, CLOSE_WAIT", info_shape(server, pair.server));
        REQUIRE_TRUE(server.close(pair.server) == 0, failure());
        h.settle(500);
        note("client, TIME_WAIT", info_shape(client, pair.client));
        return trace;
    }

    void compare_traces(const std::vector<std::string>& ustack, const std::vector<std::string>& kernel)
    {
        ASSERT_EQ(ustack.size(), kernel.size()) << "the scenario took a different path";
        std::string report;
        for (size_t i = 0; i < ustack.size(); i++)
        {
            if (ustack[i] != kernel[i])
            {
                report += "  ustack: " + ustack[i] + "\n  kernel: " + kernel[i] + "\n\n";
            }
        }
        EXPECT_TRUE(report.empty()) << "unexplained differences:\n" << report;
        if (!report.empty())
        {
            for (const std::string& line : kernel)
            {
                std::cerr << "kernel: " << line << "\n";
            }
        }
    }
}

TEST(StackDifferentialTcpInfo, MatchesTheKernel)
{
    compare_traces(run_scenario<SimHarness>(), run_scenario<KernelHarness>());
}

TEST(StackDifferentialTcpInfo, LoopbackMatchesTheKernel)
{
    compare_traces(run_scenario<SimLoopbackHarness>(), run_scenario<KernelHarness>());
}

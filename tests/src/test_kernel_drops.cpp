#include "test_support.h"
#include "network_stack.h"
#include "fake_packet_channel.h"
#include "raw_packet_channel.h"

#include <memory>

// PACKET_STATISTICS is reset by every read, so what a socket reports is "drops
// since the last look". These cover the arithmetic that turns that into a
// running total, and the stack summing it over its interfaces; the getsockopt
// call itself needs CAP_NET_RAW and is not exercised here.
namespace
{
    // A channel that reports a fixed drop count, as a RawPacketChannel would.
    class DroppingChannel : public FakePacketChannel
    {
    public:
        explicit DroppingChannel(uint64_t drops) : _drops(drops) {}
        uint64_t kernel_drops() override { return this->_drops; }

    private:
        uint64_t _drops;
    };

    InterfaceConfig config_for(const char* mac, const char* ip)
    {
        InterfaceConfig config;
        config.mac = MacAddress(mac);
        config.ip = IPv4Address(ip);
        config.prefix_length = 24;
        return config;
    }
}

TEST(KernelDropTotal, StartsAtZero)
{
    KernelDropTotal total;
    ASSERT_TRUE(total.total() == 0) << "no readings, no drops";
}

TEST(KernelDropTotal, SumsReadingsThatTheKernelResets)
{
    KernelDropTotal total;
    total.add_reading(5);
    total.add_reading(0);
    total.add_reading(7);
    ASSERT_TRUE(total.total() == 12) << "each reading is only the drops since the previous one";
}

TEST(KernelDropTotal, DoesNotWrapAt32Bits)
{
    KernelDropTotal total;
    total.add_reading(0xFFFFFFFFu);
    total.add_reading(0xFFFFFFFFu);
    ASSERT_TRUE(total.total() == 2ull * 0xFFFFFFFFull) << "tp_drops is 32 bits, the running total is not";
}

TEST(NetworkStackKernelDrops, ChannelsWithNoStatisticsReportZero)
{
    auto stack = std::make_unique<NetworkStack>(std::make_unique<FakePacketChannel>(),
                                                config_for("aa:bb:cc:dd:ee:ff", "10.0.0.2"));
    ASSERT_TRUE(stack->kernel_drops() == 0) << "a TAP-style channel has no kernel drop counter";
}

TEST(NetworkStackKernelDrops, SumsOverInterfaces)
{
    auto stack = std::make_unique<NetworkStack>(std::make_unique<DroppingChannel>(3),
                                                config_for("aa:bb:cc:dd:ee:ff", "10.0.0.2"));
    stack->add_interface(std::make_unique<DroppingChannel>(4), config_for("aa:bb:cc:dd:ee:01", "10.0.1.2"));
    stack->add_interface(std::make_unique<FakePacketChannel>(), config_for("aa:bb:cc:dd:ee:02", "10.0.2.2"));
    ASSERT_TRUE(stack->kernel_drops() == 7) << "the stack-wide figure is the sum of its channels'";
}

// The receive-buffer request tries SO_RCVBUFFORCE first and falls back to
// SO_RCVBUF, which the kernel clamps; this is that selection without a socket.
TEST(RequestReceiveBuffer, UsesTheForcedCallAndSkipsTheFallbackWhenItWorks)
{
    int plain_calls = 0;
    ReceiveBufferResult result = request_receive_buffer([] { return true; },
                                                        [&]
                                                        {
                                                            plain_calls++;
                                                            return true;
                                                        });
    ASSERT_TRUE(result == ReceiveBufferResult::FORCED) << "the forced call succeeded";
    ASSERT_TRUE(plain_calls == 0) << "so the plain one must not run and shrink it";
}

TEST(RequestReceiveBuffer, FallsBackToThePlainCallWithoutPrivilege)
{
    ReceiveBufferResult result = request_receive_buffer([] { return false; }, [] { return true; });
    ASSERT_TRUE(result == ReceiveBufferResult::CLAMPED) << "no CAP_NET_ADMIN: the clamped request is what is left";
}

TEST(RequestReceiveBuffer, ReportsFailureWhenNeitherIsAccepted)
{
    ReceiveBufferResult result = request_receive_buffer([] { return false; }, [] { return false; });
    ASSERT_TRUE(result == ReceiveBufferResult::FAILED) << "both refused";
}

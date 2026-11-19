#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <memory>
#include <vector>

// Receiver-side D-SACK (RFC 2883 section 4). When a data segment arrives that
// the receiver already has - below RCV.NXT, or inside what the reorder buffer
// holds - the next ACK reports that range as its FIRST SACK block, so the
// sender can tell a spurious retransmission from a loss. When the duplicate lies
// inside an out-of-order range, the second block is that range. Only with SACK
// negotiated; the report is made once.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    using Blocks = std::vector<Tcp::SackBlock>;

    struct Ack
    {
        uint32_t ack;
        Blocks blocks;
    };

    // Our ISN is 1000 and the peer's 500, so its first data byte is 501.
    struct Receiver
    {
        explicit Receiver(bool sack = true)
            : c(8080, IPv4Address("10.0.0.1"), 12345, 1000, [this](const Tcp& h, const Bytes&)
                { acks.push_back({h.get_acknowledgement_number(), h.get_sack_blocks()}); })
        {
            c.accept_incoming_syn(500, 1460, true, 7, true, 5000, sack);
            c.on_segment(*segment(501, 1001, 0));
            acks.clear();
        }

        std::unique_ptr<Tcp> segment(uint32_t seq, uint32_t ack, size_t length)
        {
            auto s = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, FLAG_ACK, 65535, 0, 0);
            s->set_timestamp_option(5001, 1);
            if (length > 0)
                *s /= std::make_unique<Raw>(Bytes(static_cast<unsigned int>(length)));
            return s;
        }

        // The peer sends [start, end) of its stream and we return the ACK it drew.
        const Ack& data(uint32_t start, uint32_t end)
        {
            size_t before = acks.size();
            c.on_segment(*segment(start, 1001, end - start));
            // An in-order segment's ack may be delayed; the cases here that
            // need an ack either duplicate or arrive out of order.
            REQUIRE_TRUE(acks.size() == before + 1, "the segment should have drawn exactly one ack");
            return acks.back();
        }

        TcpConnection c;
        std::vector<Ack> acks;
    };

    ::testing::AssertionResult is_blocks(const Blocks& got, const Blocks& want)
    {
        if (got.size() != want.size())
            return ::testing::AssertionFailure() << got.size() << " blocks, wanted " << want.size();
        for (size_t i = 0; i < got.size(); i++)
        {
            if (got[i].start != want[i].start || got[i].end != want[i].end)
                return ::testing::AssertionFailure() << "block " << i << " is " << got[i].start << ":" << got[i].end
                                                     << ", wanted " << want[i].start << ":" << want[i].end;
        }
        return ::testing::AssertionSuccess();
    }
}

TEST(TcpDsack, ADuplicateBelowRcvNxtIsTheFirstBlock)
{
    Receiver r;
    r.c.on_segment(*r.segment(501, 1001, 100)); // in order: acked later
    r.acks.clear();
    const Ack& ack = r.data(501, 601); // the same 100 bytes again
    ASSERT_EQ(ack.ack, 601u);
    ASSERT_TRUE(is_blocks(ack.blocks, {{501, 601}}));
    ASSERT_EQ(r.c.stats().dsacks_sent, 1u);
}

TEST(TcpDsack, TheReportIsMadeOnceAndLaterAcksAreNormal)
{
    Receiver r;
    r.c.on_segment(*r.segment(501, 1001, 100));
    r.data(501, 601);
    const Ack& next = r.data(701, 801); // out of order: a normal SACK
    ASSERT_TRUE(is_blocks(next.blocks, {{701, 801}}));
    ASSERT_EQ(r.c.stats().dsacks_sent, 1u);
}

TEST(TcpDsack, ADuplicateInsideAnOutOfOrderRangeIsFollowedByThatRange)
{
    Receiver r;
    r.data(701, 801);
    r.data(801, 901); // the range is now 701:901
    const Ack& ack = r.data(701, 801);
    ASSERT_EQ(ack.ack, 501u);
    ASSERT_TRUE(is_blocks(ack.blocks, {{701, 801}, {701, 901}})) << "RFC 2883 section 4: D-SACK, then its superset";
    ASSERT_EQ(r.c.stats().dsacks_sent, 1u);
}

TEST(TcpDsack, TheOtherRangesFollowTheDuplicatesRange)
{
    Receiver r;
    r.data(701, 801);
    r.data(1001, 1101);
    const Ack& ack = r.data(1001, 1101); // duplicate of the later range
    ASSERT_TRUE(is_blocks(ack.blocks, {{1001, 1101}, {1001, 1101}, {701, 801}}));
}

TEST(TcpDsack, APartialDuplicateBelowRcvNxtReportsOnlyTheDuplicatePart)
{
    Receiver r;
    r.c.on_segment(*r.segment(501, 1001, 100)); // RCV.NXT = 601
    r.acks.clear();
    const Ack& ack = r.data(551, 651); // 551:601 seen, 601:651 new
    ASSERT_EQ(ack.ack, 651u) << "the new tail is delivered";
    ASSERT_TRUE(is_blocks(ack.blocks, {{551, 601}}));
    ASSERT_EQ(r.c.stats().dsacks_sent, 1u);
}

TEST(TcpDsack, APartialDuplicateOfAnOutOfOrderRangeReportsOnlyTheDuplicatePart)
{
    Receiver r;
    r.data(701, 801);
    const Ack& ack = r.data(751, 851); // 751:801 held, 801:851 new
    ASSERT_TRUE(is_blocks(ack.blocks, {{751, 801}, {701, 851}}));
    ASSERT_EQ(r.c.stats().dsacks_sent, 1u);
}

TEST(TcpDsack, NewDataIsNotReportedAsADuplicate)
{
    Receiver r;
    r.data(701, 801);
    const Ack& ack = r.data(901, 1001);
    ASSERT_TRUE(is_blocks(ack.blocks, {{901, 1001}, {701, 801}}));
    ASSERT_EQ(r.c.stats().dsacks_sent, 0u);
}

TEST(TcpDsack, WithoutSackNegotiatedNothingIsReported)
{
    Receiver r(false);
    r.c.on_segment(*r.segment(501, 1001, 100));
    r.acks.clear();
    const Ack& ack = r.data(501, 601);
    ASSERT_TRUE(ack.blocks.empty());
    ASSERT_EQ(r.c.stats().dsacks_sent, 0u);
}

#include "test.h"
#include "dns.h"
#include "dns_resolver.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace
{
    const IPv4Address SERVER("8.8.8.8");
    const IPv4Address OTHER_SERVER("1.1.1.1");
    const IPv4Address ANSWER("93.184.216.34");

    // Builds a raw DNS message byte by byte, so the parser tests can construct
    // shapes this stack's own encoder would never emit - which is the entire
    // point, since the hostile inputs are exactly those shapes.
    struct MessageBuilder
    {
        Bytes wire;

        MessageBuilder(uint16_t id, uint16_t flags, uint16_t qd, uint16_t an,
                       uint16_t ns = 0, uint16_t ar = 0)
        {
            wire.append_int<uint16_t>(id);
            wire.append_int<uint16_t>(flags);
            wire.append_int<uint16_t>(qd);
            wire.append_int<uint16_t>(an);
            wire.append_int<uint16_t>(ns);
            wire.append_int<uint16_t>(ar);
        }

        void name(const std::string& n)
        {
            size_t start = 0;
            while (start < n.size())
            {
                size_t dot = n.find('.', start);
                size_t len = (dot == std::string::npos ? n.size() : dot) - start;
                wire.append_int<uint8_t>(static_cast<uint8_t>(len));
                for (size_t i = 0; i < len; i++)
                {
                    wire.append_int<uint8_t>(static_cast<uint8_t>(n[start + i]));
                }
                if (dot == std::string::npos) break;
                start = dot + 1;
            }
            wire.append_int<uint8_t>(0);
        }

        void pointer(uint16_t offset)
        {
            wire.append_int<uint16_t>(static_cast<uint16_t>(0xc000 | offset));
        }

        void question_tail(uint16_t type = DNS_TYPE_A)
        {
            wire.append_int<uint16_t>(type);
            wire.append_int<uint16_t>(DNS_CLASS_IN);
        }

        void a_record_tail(const IPv4Address& ip, uint32_t ttl = 300)
        {
            wire.append_int<uint16_t>(DNS_TYPE_A);
            wire.append_int<uint16_t>(DNS_CLASS_IN);
            wire.append_int<uint32_t>(ttl);
            wire.append_int<uint16_t>(4);
            Bytes octets = ip.get_address();
            wire.insert(wire.end(), octets.begin(), octets.end());
        }
    };

    // A well-formed answer: one question, one A record whose name is a
    // compression pointer back to the question - which is what every real
    // server sends.
    Bytes good_response(uint16_t id, const std::string& name,
                        const IPv4Address& ip = ANSWER, uint32_t ttl = 300)
    {
        MessageBuilder b(id, 0x8180, 1, 1); // response, recursion available
        b.name(name);
        b.question_tail();
        b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
        b.a_record_tail(ip, ttl);
        return b.wire;
    }

    bool throws_on_parse(const Bytes& wire)
    {
        try
        {
            Dns parsed(wire);
        }
        catch (const BaseException&)
        {
            return true;
        }
        return false;
    }

    struct SentQuery
    {
        IPv4Address server;
        uint16_t source_port;
        std::unique_ptr<Dns> message;
    };

    class ResolverHarness
    {
    public:
        ResolverHarness()
            : resolver([this](const IPv4Address& s, uint16_t sp, const Bytes& payload)
                       { sent.push_back({s, sp, std::make_unique<Dns>(payload)}); },
                       0xA5A5A5A5)
        {
            resolver.set_servers({SERVER, OTHER_SERVER});
        }

        const SentQuery& last() const { return sent.back(); }

        // Feeds a reply back as if it came from the server that was asked, on
        // the port that asked - the happy path every spoofing test then varies
        // one field of.
        void reply(const Bytes& payload)
        {
            resolver.on_datagram(last().server, DnsResolver::SERVER_PORT, last().source_port, payload);
        }

        DnsResolver resolver;
        std::vector<SentQuery> sent;
        std::map<std::string, std::vector<IPv4Address>> results;
        int callbacks = 0;

        DnsResolver::ResolvedFn recorder()
        {
            return [this](const std::string& n, const std::vector<IPv4Address>& a)
            {
                results[n] = a;
                callbacks++;
            };
        }
    };
}

// --- the parser, and the one feature that makes it dangerous ----------------

TEST(AQuestionAndAnswerSurviveARoundTrip)
{
    Dns query;
    query.set_id(0x1234);
    query.set_recursion_desired(true);
    query.add_question(DnsQuestion{"example.com", DNS_TYPE_A, DNS_CLASS_IN});

    Dns parsed(query.to_bytes());

    test_assert(parsed.get_id() == 0x1234, "id should survive");
    test_assert(parsed.recursion_desired(), "RD should survive - it is what makes this a stub query");
    test_assert(!parsed.is_response(), "a query is not a response");
    test_assert(parsed.questions().size() == 1, "one question");
    test_assert(parsed.questions()[0].name == "example.com", "name should survive");
}

TEST(ACompressionPointerIsFollowedAndLeavesTheOffsetPastThePointerItself)
{
    // The subtle half of compression: a compressed name occupies TWO bytes
    // where it appears, however long it expands to. Advancing by the expanded
    // length instead desynchronises every record after the first, which is why
    // this test checks the record parsed *after* the pointer as well as the
    // name itself.
    MessageBuilder b(0x4242, 0x8180, 1, 2);
    b.name("example.com");
    b.question_tail();
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.a_record_tail(IPv4Address("10.0.0.1"));
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.a_record_tail(IPv4Address("10.0.0.2"));

    Dns parsed(b.wire);

    test_assert(parsed.answers().size() == 2, "both records should parse");
    test_assert(parsed.answers()[0].name == "example.com", "the pointer should expand");
    test_assert(parsed.answers()[1].name == "example.com", "and so should the second");
    test_assert(parsed.answers()[0].address() == IPv4Address("10.0.0.1"), "first address");
    test_assert(parsed.answers()[1].address() == IPv4Address("10.0.0.2"),
                "the second record must start where the two-byte pointer ended");
}

TEST(APointerToItselfIsRefusedRatherThanLoopingForever)
{
    // The classic DNS parser CVE. A naive expander hangs here, and since this
    // runs on an unsolicited UDP datagram, hanging is remote denial of service
    // against anything that resolves a name.
    MessageBuilder b(1, 0x8180, 1, 0);
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE)); // points at itself

    test_assert(throws_on_parse(b.wire), "a self-referential pointer must be refused");
}

TEST(TwoPointersAimedAtEachOtherAreRefused)
{
    // The same attack with one level of indirection, which defeats a
    // "does it point at itself" check but not a "must point backwards" one.
    MessageBuilder b(1, 0x8180, 1, 0);
    uint16_t first = static_cast<uint16_t>(Dns::HEADER_SIZE);
    b.pointer(static_cast<uint16_t>(first + 2)); // forwards, to the second
    b.pointer(first);                            // back to the first

    test_assert(throws_on_parse(b.wire), "a two-pointer cycle must be refused");
}

TEST(AForwardPointerIsRefusedEvenWhenItWouldTerminate)
{
    // Perfectly terminating, and still refused. Requiring backwards-only is
    // what makes a cycle impossible by construction rather than merely bounded
    // - and a forward pointer is also how a name is made to reference bytes
    // that have not been validated yet.
    MessageBuilder b(1, 0x8180, 1, 0);
    uint16_t start = static_cast<uint16_t>(Dns::HEADER_SIZE);
    b.pointer(static_cast<uint16_t>(start + 2));
    b.name("example.com");

    test_assert(throws_on_parse(b.wire), "a forward pointer must be refused on principle");
}

TEST(ALabelLongerThanSixtyThreeBytesIsRefused)
{
    MessageBuilder b(1, 0x8180, 1, 0);
    b.wire.append_int<uint8_t>(64); // one over the maximum, and not a pointer
    for (int i = 0; i < 64; i++) b.wire.append_int<uint8_t>('a');
    b.wire.append_int<uint8_t>(0);

    test_assert(throws_on_parse(b.wire), "a 64-byte label must be refused");
}

TEST(AReservedLabelPrefixIsRefused)
{
    // 0b01 and 0b10 have never been assigned. Treating them as a length is how
    // two parsers end up disagreeing about the same bytes.
    MessageBuilder b(1, 0x8180, 1, 0);
    b.wire.append_int<uint8_t>(0x80);
    b.wire.append_int<uint8_t>(0x00);

    test_assert(throws_on_parse(b.wire), "a reserved length prefix must be refused");
}

TEST(ATruncatedRecordIsRefusedRatherThanReadPastTheEnd)
{
    MessageBuilder b(1, 0x8180, 1, 1);
    b.name("example.com");
    b.question_tail();
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.wire.append_int<uint16_t>(DNS_TYPE_A);
    b.wire.append_int<uint16_t>(DNS_CLASS_IN);
    b.wire.append_int<uint32_t>(300);
    b.wire.append_int<uint16_t>(4); // claims four bytes of address, supplies none

    test_assert(throws_on_parse(b.wire), "rdata running past the end must be refused");
}

TEST(AnAbsurdRecordCountDoesNotPreallocateAnything)
{
    // The counts are attacker-chosen 16-bit numbers in a datagram of a few
    // hundred bytes. A parser that reserves what they claim allocates 65535
    // records from a 12-byte message.
    MessageBuilder b(1, 0x8180, 0, 65535);

    test_assert(throws_on_parse(b.wire),
                "a count with no records behind it must fail on the missing bytes");
}

TEST(AnUnknownRecordTypeSurvivesTheParse)
{
    // An unrecognised type in a response is completely normal. Failing on it
    // would make this resolver hostage to whatever a server chooses to include.
    MessageBuilder b(1, 0x8180, 1, 1);
    b.name("example.com");
    b.question_tail();
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.wire.append_int<uint16_t>(99); // no such type here
    b.wire.append_int<uint16_t>(DNS_CLASS_IN);
    b.wire.append_int<uint32_t>(60);
    b.wire.append_int<uint16_t>(3);
    for (int i = 0; i < 3; i++) b.wire.append_int<uint8_t>(0xab);

    Dns parsed(b.wire);
    test_assert(parsed.answers().size() == 1, "the record should parse");
    test_assert(parsed.answers()[0].rdata.size() == 3, "with its data kept verbatim");
    test_assert(parsed.answers()[0].address() == IPv4Address(),
                "and no address, since it is not an A record");
}

// --- the resolver, and what stops a forged answer ---------------------------

TEST(AQuerySetsRecursionDesiredAndAsksTheFirstServer)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    test_assert(h.sent.size() == 1, "one query should go out");
    test_assert(h.last().server == SERVER, "to the first configured server");
    test_assert(h.last().message->recursion_desired(),
                "RD is what makes this a stub - the server does the walk");
    test_assert(h.last().message->questions().size() == 1, "asking one question");
    test_assert(h.last().message->questions()[0].name == "example.com", "for the right name");
}

TEST(EveryQueryGetsAFreshRandomSourcePort)
{
    // The single highest-value thing a stub resolver does. A fixed source port
    // leaves an attacker only the 16-bit id to guess; a random one doubles the
    // work to ~32 bits. Pre-2008 resolvers used a fixed port, and Kaminsky's
    // work is what made that indefensible.
    ResolverHarness h;
    for (int i = 0; i < 8; i++)
    {
        h.resolver.resolve("host" + std::to_string(i) + ".example.com", h.recorder());
    }

    std::vector<uint16_t> ports;
    std::vector<uint16_t> ids;
    for (const SentQuery& q : h.sent)
    {
        ports.push_back(q.source_port);
        ids.push_back(q.message->get_id());
    }

    for (size_t i = 0; i < ports.size(); i++)
    {
        test_assert(ports[i] >= 49152, "ports must be in the ephemeral range");
        for (size_t j = i + 1; j < ports.size(); j++)
        {
            test_assert(ports[i] != ports[j], "outstanding queries must not share a source port");
            test_assert(ids[i] != ids[j], "nor a transaction id");
            test_assert(ports[i] + 1 != ports[j], "and ports must not be a counter");
            test_assert(ids[i] + 1 != ids[j], "nor ids");
        }
    }
}

TEST(AnAnswerOnTheRightPortWithTheRightIdIsAccepted)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    h.reply(good_response(h.last().message->get_id(), "example.com"));

    test_assert(h.callbacks == 1, "the callback should fire exactly once");
    test_assert(h.results["example.com"].size() == 1, "with one address");
    test_assert(h.results["example.com"][0] == ANSWER, "the one the server gave");
}

TEST(AnAnswerWithTheWrongTransactionIdIsIgnored)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    uint16_t real_id = h.last().message->get_id();

    h.reply(good_response(static_cast<uint16_t>(real_id ^ 0xffff), "example.com"));

    test_assert(h.callbacks == 0, "a forged id must not answer the query");

    // And crucially the real answer still works: a forged reply must not be
    // able to cancel the outstanding query, or guessing wrong would be a
    // denial of service even when guessing right fails.
    h.reply(good_response(real_id, "example.com"));
    test_assert(h.callbacks == 1, "the genuine answer must still be accepted afterwards");
}

TEST(AnAnswerArrivingOnTheWrongPortIsIgnored)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    uint16_t wrong_port = static_cast<uint16_t>(h.last().source_port + 1);
    h.resolver.on_datagram(SERVER, DnsResolver::SERVER_PORT, wrong_port,
                           good_response(h.last().message->get_id(), "example.com"));

    test_assert(h.callbacks == 0, "the port is half the entropy - it must be checked");
}

TEST(AnAnswerFromAnAddressThatWasNotAskedIsIgnored)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    h.resolver.on_datagram(IPv4Address("6.6.6.6"), DnsResolver::SERVER_PORT,
                           h.last().source_port,
                           good_response(h.last().message->get_id(), "example.com"));

    test_assert(h.callbacks == 0, "a reply must come from the server that was asked");
}

TEST(AnAnswerForADifferentNameIsIgnored)
{
    // The shape a poisoning attempt takes when the attacker got the port and
    // the id right but is aiming at another name.
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    h.reply(good_response(h.last().message->get_id(), "evil.example.net"));

    test_assert(h.callbacks == 0, "the question section must echo what was asked");
}

TEST(AMalformedReplyDoesNotFailTheOutstandingQuery)
{
    // Failing here would let one garbage datagram deny resolution of any name.
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    uint16_t id = h.last().message->get_id();

    h.reply(Bytes(4));
    h.reply(Bytes());
    test_assert(h.callbacks == 0, "garbage must be dropped, not answered");

    h.reply(good_response(id, "example.com"));
    test_assert(h.callbacks == 1, "and the real answer must still land");
}

TEST(AnAnswerIsCachedAndServedWithoutASecondQuery)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    h.reply(good_response(h.last().message->get_id(), "example.com"));
    size_t after_first = h.sent.size();

    h.resolver.resolve("example.com", h.recorder());

    test_assert(h.sent.size() == after_first, "a cached name must not be queried again");
    test_assert(h.callbacks == 2, "but the callback must still fire");
}

TEST(TheCacheIsCaseInsensitiveAndIgnoresATrailingDot)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    h.reply(good_response(h.last().message->get_id(), "example.com"));
    size_t after_first = h.sent.size();

    h.resolver.resolve("EXAMPLE.com.", h.recorder());

    test_assert(h.sent.size() == after_first, "DNS names are case-insensitive and may be rooted");
}

TEST(ACachedAnswerExpiresWhenItsTtlRunsOut)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    h.reply(good_response(h.last().message->get_id(), "example.com", ANSWER, 5));
    size_t after_first = h.sent.size();

    h.resolver.on_time_passed(6000);
    h.resolver.resolve("example.com", h.recorder());

    test_assert(h.sent.size() == after_first + 1, "an expired name must be asked again");
}

TEST(ASecondRequestForAnInFlightNameJoinsItRatherThanRacingIt)
{
    // Two queries for one name would be two chances for an attacker to win the
    // race, on top of being wasteful.
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    h.resolver.resolve("example.com", h.recorder());

    test_assert(h.sent.size() == 1, "only one query should be in flight");

    h.reply(good_response(h.last().message->get_id(), "example.com"));
    test_assert(h.callbacks == 2, "but both callers must be answered");
}

TEST(AnUnansweredQueryRetriesThenMovesToTheNextServer)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());
    test_assert(h.last().server == SERVER, "first server first");

    h.resolver.on_time_passed(2100);
    test_assert(h.sent.size() == 2, "a retry");
    test_assert(h.last().server == SERVER, "still the first server");

    h.resolver.on_time_passed(2100);
    test_assert(h.sent.size() == 3, "then the second server");
    test_assert(h.last().server == OTHER_SERVER, "a dead server must not stall resolution");
}

TEST(AQueryNoServerAnswersFailsRatherThanHangingForever)
{
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    for (int i = 0; i < 6; i++)
    {
        h.resolver.on_time_passed(2100);
    }

    test_assert(h.callbacks == 1, "the callback must fire exactly once, even on failure");
    test_assert(h.results["example.com"].empty(), "with no addresses");
    test_assert(!h.resolver.busy(), "and nothing left outstanding");
}

TEST(NxdomainIsAnAnswerNotAFailureToGetOne)
{
    // Asking the next server would be asking the same question of somebody
    // less likely to know.
    ResolverHarness h;
    h.resolver.resolve("nope.example.com", h.recorder());

    MessageBuilder b(h.last().message->get_id(), 0x8183, 1, 0); // rcode 3
    b.name("nope.example.com");
    b.question_tail();
    h.reply(b.wire);

    test_assert(h.callbacks == 1, "NXDOMAIN answers the query");
    test_assert(h.results["nope.example.com"].empty(), "with nothing");
    test_assert(h.sent.size() == 1, "and must not be retried against another server");
}

TEST(ATruncatedAnswerFailsRatherThanReturningAPartialAddressSet)
{
    // DNS over TCP is out of scope, and a partial answer set is worse than
    // none - the address it omits may be the only one that works.
    ResolverHarness h;
    h.resolver.resolve("example.com", h.recorder());

    Bytes wire = good_response(h.last().message->get_id(), "example.com");
    wire[2] = static_cast<byte_t>(wire[2] | 0x02); // set TC
    h.reply(wire);

    test_assert(h.callbacks == 1, "a truncated answer must resolve the call");
    test_assert(h.results["example.com"].empty(), "as a failure, not a partial success");
}

TEST(FollowingAnAliasUsesAFreshIdAndPort)
{
    // A CNAME chase is a new query on the network, so reusing the id and port
    // would hand an attacker who saw the first one the second for free.
    ResolverHarness h;
    h.resolver.resolve("www.example.com", h.recorder());
    uint16_t first_id = h.last().message->get_id();
    uint16_t first_port = h.last().source_port;

    MessageBuilder b(first_id, 0x8180, 1, 1);
    b.name("www.example.com");
    b.question_tail();
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.wire.append_int<uint16_t>(DNS_TYPE_CNAME);
    b.wire.append_int<uint16_t>(DNS_CLASS_IN);
    b.wire.append_int<uint32_t>(300);
    Bytes target;
    {
        MessageBuilder inner(0, 0, 0, 0);
        inner.wire = Bytes();
        inner.name("example.com");
        target = inner.wire;
    }
    b.wire.append_int<uint16_t>(static_cast<uint16_t>(target.size()));
    b.wire.insert(b.wire.end(), target.begin(), target.end());
    h.reply(b.wire);

    test_assert(h.sent.size() == 2, "the alias should be chased");
    test_assert(h.last().message->questions()[0].name == "example.com", "asking for the target");
    test_assert(h.last().message->get_id() != first_id, "with a fresh transaction id");
    test_assert(h.last().source_port != first_port, "and a fresh source port");
    test_assert(h.callbacks == 0, "the original caller is still waiting");

    h.reply(good_response(h.last().message->get_id(), "example.com"));
    test_assert(h.callbacks == 1, "and is answered once the target resolves");
    test_assert(h.results["example.com"][0] == ANSWER, "with the target's address");
}

TEST(ResolvingWithNoServersConfiguredFailsImmediately)
{
    std::vector<SentQuery> sent;
    DnsResolver resolver([&sent](const IPv4Address& s, uint16_t sp, const Bytes& p)
                         { sent.push_back({s, sp, std::make_unique<Dns>(p)}); },
                         12345);
    int calls = 0;
    resolver.resolve("example.com", [&calls](const std::string&, const std::vector<IPv4Address>& a)
                     { calls++; test_assert(a.empty(), "no addresses"); });

    test_assert(calls == 1, "the callback must fire even with nowhere to ask");
    test_assert(sent.empty(), "and nothing should go on the wire");
}

TEST(AQueryThatGivesUpStillReleasesItsPort)
{
    // The failure path matters as much as the success path: a name that never
    // resolves must not leave its socket behind, or a host with a dead DNS
    // server leaks faster than one with a working one.
    std::vector<uint16_t> bound;
    std::vector<uint16_t> released;

    DnsResolver resolver(
        [&bound](const IPv4Address&, uint16_t source_port, const Bytes&)
        {
            // Retransmissions reuse the port they already hold, which mirrors
            // bind_udp() returning the existing socket rather than a second one.
            if (std::find(bound.begin(), bound.end(), source_port) == bound.end())
            {
                bound.push_back(source_port);
            }
        },
        0xBEEFCAFE);
    resolver.set_release_port_callback([&released](uint16_t port) { released.push_back(port); });
    resolver.set_servers({SERVER, OTHER_SERVER});

    resolver.resolve("nowhere.example.com",
                     [](const std::string&, const std::vector<IPv4Address>&) {});
    test_assert(bound.size() == 1, "one port taken");
    test_assert(released.empty(), "and not released while the query is still trying");

    for (int i = 0; i < 6; i++)
    {
        resolver.on_time_passed(2100); // exhaust both servers
    }

    test_assert(!resolver.busy(), "the query should have given up");
    test_assert(released.size() == bound.size(),
                "every port taken must be released exactly once - " +
                std::to_string(bound.size()) + " taken, " +
                std::to_string(released.size()) + " released");
    test_assert(released[0] == bound[0], "and it must be the port that was taken");
}

TEST(AResolvedQueryReleasesItsPortToo)
{
    ResolverHarness h;
    std::vector<uint16_t> released;
    h.resolver.set_release_port_callback([&released](uint16_t port) { released.push_back(port); });

    h.resolver.resolve("example.com", h.recorder());
    uint16_t port = h.last().source_port;
    h.reply(good_response(h.last().message->get_id(), "example.com"));

    test_assert(h.callbacks == 1, "the query should have been answered");
    test_assert(released.size() == 1, "and its port released exactly once");
    test_assert(released[0] == port, "the port it used");
}

TEST(AnAliasChaseReleasesTheFirstPortBeforeTakingASecond)
{
    // The CNAME path abandons its port for a fresh one mid-query. That is the
    // other place a port stops being used, and it is easy to miss because the
    // caller is still waiting.
    ResolverHarness h;
    std::vector<uint16_t> released;
    h.resolver.set_release_port_callback([&released](uint16_t port) { released.push_back(port); });

    h.resolver.resolve("www.example.com", h.recorder());
    uint16_t first_port = h.last().source_port;

    MessageBuilder b(h.last().message->get_id(), 0x8180, 1, 1);
    b.name("www.example.com");
    b.question_tail();
    b.pointer(static_cast<uint16_t>(Dns::HEADER_SIZE));
    b.wire.append_int<uint16_t>(DNS_TYPE_CNAME);
    b.wire.append_int<uint16_t>(DNS_CLASS_IN);
    b.wire.append_int<uint32_t>(300);
    Bytes target;
    {
        MessageBuilder inner(0, 0, 0, 0);
        inner.wire = Bytes();
        inner.name("example.com");
        target = inner.wire;
    }
    b.wire.append_int<uint16_t>(static_cast<uint16_t>(target.size()));
    b.wire.insert(b.wire.end(), target.begin(), target.end());
    h.reply(b.wire);

    test_assert(released.size() == 1, "the abandoned port must be released as the alias is chased");
    test_assert(released[0] == first_port, "specifically the first one");
    test_assert(h.last().source_port != first_port, "and a fresh one taken");
}

#include "test.h"
#include "exceptions.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "dhcp.h"
#include "dns.h"

#include <random>

// Feeds random and truncated bytes into every protocol class's from_bytes()
// constructor. The point isn't the specific outcome per input - malformed
// input rejecting itself with a BaseException is correct behavior - it's
// that nothing here should ever crash the process (segfault, UB) or throw
// anything other than the documented BaseException. A fixed seed keeps
// every run reproducible: a failure here should fail the same way every
// time, not depend on when you happened to run it.
namespace
{
    constexpr unsigned int FUZZ_SEED = 0xC0FFEE;
    constexpr int FUZZ_ITERATIONS = 2000;

    Bytes random_bytes(std::mt19937& rng, size_t max_len)
    {
        std::uniform_int_distribution<size_t> len_dist(0, max_len);
        std::uniform_int_distribution<int> byte_dist(0, 255);

        size_t len = len_dist(rng);
        Bytes data(len);
        for (size_t i = 0; i < len; i++)
        {
            data[i] = static_cast<byte_t>(byte_dist(rng));
        }
        return data;
    }

    template <typename ProtocolClass>
    void fuzz_from_bytes(size_t max_len)
    {
        std::mt19937 rng(FUZZ_SEED);
        for (int i = 0; i < FUZZ_ITERATIONS; i++)
        {
            Bytes data = random_bytes(rng, max_len);
            try
            {
                ProtocolClass instance(data);
            }
            catch (const BaseException&)
            {
                // malformed input correctly rejected - that's the expected outcome
            }
        }
    }
}

TEST(EthernetFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Ethernet>(128);
}

TEST(ArpFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Arp>(64);
}

TEST(IpFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Ip>(128);
}

TEST(TcpFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Tcp>(128);
}

TEST(UdpFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Udp>(128);
}

TEST(IcmpFromBytesNeverCrashesOnGarbage)
{
    fuzz_from_bytes<Icmp>(128);
}

// Truncated-but-plausible-looking input is worth testing separately from
// pure noise: a header that claims a length longer than the data actually
// present is the classic way an off-by-one in bounds checking gets missed.
TEST(TruncatedButPlausibleHeadersDoNotCrash)
{
    // A real Ethernet+IP+TCP header's opening bytes, cut off at every
    // possible length - including lengths that pass Ethernet's own size
    // check but leave IP/TCP with too little to work with.
    Bytes full = Bytes::from_hex(
        "aabbccddeeff001122334455080045000028000140004006"
        "0000ac100a63ac100a0c00500050000000000000000050022000000000"
    );

    for (size_t len = 0; len <= full.size(); len++)
    {
        Bytes truncated = full.slice(0, len);
        try
        {
            Ethernet ethernet(truncated);
        }
        catch (const BaseException&)
        {
            // expected for most truncation lengths
        }
    }
}

TEST(DhcpFromBytesNeverCrashesOnGarbage)
{
    // The one parser here that runs before this host has an address at all,
    // on datagrams from any source, with nothing in the protocol
    // authenticating any of it - and whose options are tag/length/value with
    // an attacker-chosen length. 512 rather than 128 so the generator can
    // actually reach past the 240-byte fixed header into the options, which
    // is the part worth fuzzing.
    fuzz_from_bytes<Dhcp>(512);
}

TEST(DnsFromBytesNeverCrashesOnGarbage)
{
    // Name compression makes this the most dangerous parser in the stack: a
    // label byte can be a 14-bit offset back into the same buffer, chosen by
    // whoever sent the datagram. Random bytes hit that path constantly - about
    // one label byte in four has both top bits set - so this is a real test of
    // the backwards-only rule and the jump cap rather than a formality.
    fuzz_from_bytes<Dns>(512);
}

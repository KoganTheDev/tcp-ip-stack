// Parsing a DNS response whose records name their owner by compression pointer,
// which is what every real server sends and the path the pointer-loop defences
// in dns.cpp guard.

#include <benchmark/benchmark.h>

#include "bytes.h"
#include "dns.h"

namespace
{
    // header | question www.example.com A IN | CNAME (pointer to the question
    // name) -> web.example.com, itself ending in a pointer into the question's
    // "example.com" | N A records, owner = pointer to the CNAME target.
    Bytes response_with_compression(int a_records)
    {
        Bytes m = Bytes::from_hex("1234"
                                  "8180"
                                  "0001");
        m.append_int<uint16_t>(static_cast<uint16_t>(1 + a_records));
        m |= Bytes::from_hex("00000000");
        // question: 3www7example3com0 (name starts at offset 12)
        m |= Bytes::from_hex("03777777"
                             "076578616d706c65"
                             "03636f6d"
                             "00"
                             "0001"
                             "0001");
        // CNAME owner = pointer to offset 12; rdata = 3web then pointer to "example.com" (offset 16)
        const size_t cname_target_at = m.size() + 2 + 2 + 2 + 4 + 2;
        m |= Bytes::from_hex("c00c"
                             "0005"
                             "0001"
                             "0000012c");
        m.append_int<uint16_t>(6);
        m |= Bytes::from_hex("03776562"
                             "c010");
        for (int i = 0; i < a_records; i++)
        {
            m.append_int<uint16_t>(static_cast<uint16_t>(0xc000 | cname_target_at));
            m |= Bytes::from_hex("0001"
                                 "0001"
                                 "0000012c"
                                 "0004");
            m.append_int<uint32_t>(0x5db8d800u + static_cast<uint32_t>(i));
        }
        return m;
    }
}

static void BM_DnsParseResponse(benchmark::State& state)
{
    const Bytes wire = response_with_compression(static_cast<int>(state.range(0)));
    for (auto _ : state)
    {
        Dns message(wire);
        benchmark::DoNotOptimize(message);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(wire.size()));
}
BENCHMARK(BM_DnsParseResponse)->Arg(1)->Arg(8)->Arg(32);

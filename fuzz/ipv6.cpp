#include "parser_harness.h"
#include "ipv6.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return fuzz_parser<Ipv6>(data, size);
}

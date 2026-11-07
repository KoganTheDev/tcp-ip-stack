#include "parser_harness.h"
#include "arp.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return fuzz_parser<Arp>(data, size);
}

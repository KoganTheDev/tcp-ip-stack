#include "parser_harness.h"
#include "ethernet.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return fuzz_parser<Ethernet>(data, size);
}

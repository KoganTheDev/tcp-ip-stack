#pragma once

// Shared body of the one-parser-per-binary harnesses. Each harness file is a
// single line naming the class, so the contract being fuzzed is the same for
// all of them and is stated once:
//
//   - from_bytes() on arbitrary input either succeeds or throws BaseException.
//     Anything else (a crash, UB, an out-of-bounds read, another exception
//     type, an allocation sized by the input) is a finding. This is the same
//     contract tests/src/test_protocol_fuzz.cpp asserts for fixed inputs.
//   - A message that parsed can then be printed and re-serialized without
//     crashing. That reaches code (to_string(), to_bytes()) that raw parsing
//     alone never executes, and is where a field the parser accepted but the
//     serializer cannot represent would show up.

#include <cstddef>
#include <cstdint>

#include "bytes.h"
#include "exceptions.h"

template <typename ProtocolClass>
int fuzz_parser(const uint8_t* data, size_t size)
{
    Bytes input(static_cast<unsigned int>(size));
    for (size_t i = 0; i < size; i++)
    {
        input[i] = data[i];
    }
    try
    {
        ProtocolClass message(input);
        (void)message.to_string();
        (void)message.to_bytes();
    }
    catch (const BaseException&)
    {
        // malformed input correctly rejected
    }
    return 0;
}

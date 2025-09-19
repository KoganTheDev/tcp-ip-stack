#include "bytes.h"
#include "test.h"
#include "exceptions.h"
#include "utils.h"

// Test case for Bytes constructors and size
TEST(BytesConstructors)
{
    Bytes empty_bytes;
    test_assert(empty_bytes.size() != 0, "Default constructor should create an empty Bytes object");

    Bytes string_bytes("hello");
    test_assert(string_bytes.size() != 5, "String constructor size is incorrect");

    std::vector<byte_t> vec = {1, 2, 3};
    Bytes vec_bytes(vec);
    test_assert(vec_bytes.size() != 3, "Vector constructor size is incorrect");
    test_assert(vec_bytes[0] != 1, "Vector constructor content is incorrect");

    Bytes length_bytes(10);
    test_assert(length_bytes.size() != 10, "Length constructor size is incorrect");
}

// Test case for from_hex and to_hex methods
TEST(HexConversion)
{
    // Test valid hex string
    std::string hex_str = "01020304aaff";
    Bytes bytes_from_hex = Bytes::from_hex(hex_str);
    test_assert(bytes_from_hex.to_hex() != hex_str, "from_hex and to_hex round-trip failed");

    // Test invalid hex string size
    bool exception_caught = false;
    try
    {
        Bytes::from_hex("123");
    }
    catch (const BaseException& e)
    {
        exception_caught = true;
    }
    test_assert(!exception_caught, "from_hex did not throw an exception for invalid size");
}

// Test case for slicing methods
TEST(Slicing)
{
    Bytes bytes = Bytes::from_hex("010203040506");

    // Test slice with index and length
    Bytes sliced1 = bytes.slice(2, 3);
    test_assert(sliced1.to_hex() != "030405", "Slice with length failed");

    // Test slice from index to end
    Bytes sliced2 = bytes.slice(4);
    test_assert(sliced2.to_hex() != "0506", "Slice to end failed");

    // Test out of range slice
    bool exception_caught = false;
    try
    {
        bytes.slice(6, 1);
    }
    catch (const BaseException& e)
    {
        exception_caught = true;
    }
    test_assert(!exception_caught, "Slice did not throw an exception for out of range");
}

// Test case for slice_int template method
TEST(SliceInt)
{
    Bytes bytes = Bytes::from_hex("0102030405060708");

    // Test with uint16_t
    uint16_t val16 = bytes.slice_int<uint16_t>(0);
    test_assert(val16 != 0x0102, "slice_int<uint16_t> failed");

    // Test with uint32_t
    uint32_t val32 = bytes.slice_int<uint32_t>(4);
    test_assert(val32 != 0x05060708, "slice_int<uint32_t> failed");

    // Test out of range
    bool exception_caught = false;
    try
    {
        bytes.slice_int<uint32_t>(6);
    }
    catch (const BaseException& e)
    {
        exception_caught = true;
    }
    test_assert(!exception_caught, "slice_int did not throw an exception for out of range");
}

// Test case for operators
TEST(Operators)
{
    Bytes b1 = Bytes::from_hex("0102");
    Bytes b2 = Bytes::from_hex("0304");

    // Test | operator
    Bytes concatenated = b1 | b2;
    test_assert(concatenated.to_hex() != "01020304", "Concatenation operator | failed");
    
    // Test |= operator
    Bytes b3 = b1;
    b3 |= b2;
    test_assert(b3.to_hex() != "01020304", "Concatenation operator |= failed");

    // Test + operator
    Bytes b4 = Bytes::from_hex("0102");
    Bytes b5 = Bytes::from_hex("0102");
    Bytes sum = b4 + b5;
    test_assert(sum.to_hex() != "0204", "Bit-wise addition operator + failed");

    // Test - operator
    Bytes diff = b5 - b4;
    test_assert(diff.to_hex() != "0000", "Bit-wise subtraction operator - failed");
}

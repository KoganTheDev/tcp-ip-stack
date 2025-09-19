#include "test.h"


void test_assert(bool condition, const std::string& message)
{
    if (!condition)
    {
        throw EXCEPTION(AssertException, message);
    }
}

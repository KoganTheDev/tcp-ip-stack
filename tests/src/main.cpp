#include "test.h"

int main()
{
    // Nonzero when any test failed, so make, CI and the build gate can tell.
    return BaseTest::run_all_tests() == 0 ? 0 : 1;
}

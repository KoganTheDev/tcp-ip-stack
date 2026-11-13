#pragma once

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

// The suite is GoogleTest. In a TEST body, assert with
//
//     ASSERT_TRUE(cond) << "why it matters";
//
// which records the failure and returns from the test. That is the semantics
// the homegrown test_assert() had (a failed check ended the whole test), and
// why ASSERT_* rather than EXPECT_* is the default here: most checks in this
// suite set up the next step, and carrying on after one failed would mostly
// report noise.
//
// ASSERT_* has one catch: it works by `return`, so it only stops the function
// it is written in, and it does not compile at all in a function that returns
// a value. In a helper (or a lambda) it would end the helper and let the test
// continue on bad state. So outside a TEST body, use
//
//     REQUIRE_TRUE(cond, "why it matters");
//
// which records a failure at the call site and then throws. GoogleTest catches
// the exception at the test boundary, so the test stops there, as test_assert
// used to make it. The failure is recorded *before* the throw, so a test that
// accidentally swallows the exception (a catch (...) between the helper and
// the test body) still fails rather than passing silently.
//
// Do not use REQUIRE_TRUE from a thread other than the test's own: an
// exception escaping a std::thread calls std::terminate.
namespace test_support
{
    // Not derived from BaseException, so the tests' own
    // `catch (const BaseException&)` blocks, written to catch the stack's
    // parse errors, cannot swallow it.
    struct RequirementFailed : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    inline void require(bool condition, const std::string& message, const char* expression, const char* file, int line)
    {
        if (condition)
        {
            return;
        }
        ADD_FAILURE_AT(file, line) << "Value of: " << expression << "\n  Actual: false\nExpected: true\n" << message;
        throw RequirementFailed(message);
    }
}

#define REQUIRE_TRUE(condition, message) \
    ::test_support::require(static_cast<bool>(condition), (message), #condition, __FILE__, __LINE__)

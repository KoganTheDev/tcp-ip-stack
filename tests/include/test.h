#pragma once

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#include "exceptions.h"

// Macro to define a new test
#define TEST(name) \
class Test_##name : public BaseTest\
{\
public: \
    Test_##name() : BaseTest(#name, __FILE__) {}\
    void test();\
};\
static Test_##name test_instance_##name;\
void Test_##name::test()


class AssertException : public BaseException
{
public:
    AssertException(const std::string& message, DEFAULT_EXCEPTION_PARAMS) : BaseException(message) {}
};


void test_assert(bool condition, const std::string& message);


class BaseTest;

inline std::vector<BaseTest*>& get_tests() 
{
    static std::vector<BaseTest*> tests;
    return tests;
}

class BaseTest
{
public:
    // The constructor now takes two arguments: the test name and the file name
    BaseTest(const std::string& name, const std::string& file_name) : _name(name), _file_name(file_name)
    {
        // register test
        get_tests().push_back(this);
    }

    ~BaseTest()
    {
        get_tests().erase(std::find(get_tests().begin(), get_tests().end(), this));
    }

    virtual void test() = 0;

    static void run_all_tests()
    {
        int passed_count = 0;
        std::string last_file = ""; // Used to print the file name only once
        for (BaseTest* test : get_tests())
        {
            if (test->_file_name != last_file)
            {
                std::cout << "--- Running tests from " << test->_file_name << " ---" << std::endl;
                last_file = test->_file_name;
            }
            try
            {
                test->test();
                std::cout << "Test '" << test->_name << "' passed" << std::endl;
                passed_count++;
            }
            catch(const BaseException& e)
            {
                std::cout << "Test '" << test->_name << "' failed with exception: " << e.what() << std::endl;
            }
        }
        std::cout << std::endl << passed_count << " / " << get_tests().size() << " tests passed" << std::endl;
    }

private:
    const std::string _name;
    const std::string _file_name;
};

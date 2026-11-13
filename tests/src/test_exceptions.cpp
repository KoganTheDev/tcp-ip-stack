#include "test_support.h"
#include "exceptions.h"

#include <cerrno>
#include <string>

// SystemException appends errno's description. It now comes from
// strerror_r rather than the shared-buffer strerror; this pins that the text
// is still the right one for the errno at construction.
TEST(Exceptions, ASystemExceptionDescribesTheErrnoItWasBuiltWith)
{
    errno = ENOENT;
    SystemException exception("opening the thing");
    std::string text = exception.what();
    ASSERT_TRUE(text.find("opening the thing") == 0) << text;
    ASSERT_TRUE(text.find("error " + std::to_string(ENOENT)) != std::string::npos) << text;
    ASSERT_TRUE(text.find("No such file or directory") != std::string::npos) << text;
}

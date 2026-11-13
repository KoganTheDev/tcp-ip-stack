#include "test_support.h"
#include "system_network_object.h"
#include "exceptions.h"

#include <cstring>
#include <string>

// Bringing an interface up or down used to build the string
// "ip link set <name> up" and hand it to system(), i.e. to /bin/sh - so an
// interface name was shell syntax. It is now an ioctl on an ifreq, and
// building that ifreq is a pure function, tested here without touching any
// real interface.

TEST(SystemNetworkObject, AnInterfaceNameIsCopiedVerbatimNeverInterpreted)
{
    const std::string hostile = "eth0; rm -rf /"; // 14 bytes: fits IFNAMSIZ
    struct ifreq request = interface_request(hostile);
    ASSERT_TRUE(std::string(request.ifr_name) == hostile)
        << "the whole string is one interface name - there is no shell to split it";
}

// A name that does not fit IFNAMSIZ (including its terminator) must be
// refused, not truncated: truncation would silently name a different
// interface - possibly one that exists.
TEST(SystemNetworkObject, ANameTooLongForIfnamsizIsRefusedNotTruncated)
{
    std::string longest(IFNAMSIZ - 1, 'a');
    ASSERT_NO_THROW(interface_request(longest)) << "IFNAMSIZ - 1 characters fit";
    ASSERT_THROW(interface_request(longest + "a"), BaseException) << "IFNAMSIZ characters do not";
    ASSERT_THROW(interface_request(""), BaseException) << "nor does an empty name";
    ASSERT_THROW(interface_request(std::string("eth0\0x", 6)), BaseException)
        << "an embedded NUL would cut the name short";
}

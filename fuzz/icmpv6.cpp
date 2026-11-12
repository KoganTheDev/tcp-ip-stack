// ICMPv6 / NDP. Unlike the one-line harnesses, parsing is not the whole
// surface: from_bytes() keeps the body opaque and the NDP accessors walk it
// lazily, so the option walks (a zero-length option would spin forever in a
// naive loop) and the fixed-offset readers are only reached by calling them.
// Each accessor is called at both option offsets, on whatever the body is,
// because which message type the bytes claim to be does not stop a hostile
// sender from being read as another.

#include <cstddef>
#include <cstdint>

#include "bytes.h"
#include "exceptions.h"
#include "icmpv6.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    Bytes input(static_cast<unsigned int>(size));
    for (size_t i = 0; i < size; i++)
    {
        input[i] = data[i];
    }
    try
    {
        Icmpv6 message(input);
        (void)message.to_string();
        (void)message.to_bytes();
        (void)message.get_options();
        (void)message.get_options(Icmpv6::ROUTER_ADVERTISEMENT_OPTIONS_OFFSET);
        (void)message.get_link_layer_option(NDP_OPTION_SOURCE_LINK_LAYER);
        (void)message.get_link_layer_option(NDP_OPTION_TARGET_LINK_LAYER);
        (void)message.get_target_address();
        (void)message.get_router_flag();
        (void)message.get_solicited_flag();
        (void)message.get_override_flag();
        (void)message.get_ra_hop_limit();
        (void)message.get_router_lifetime();
        (void)message.get_managed_flag();
        (void)message.get_prefix_information();
    }
    catch (const BaseException&)
    {
        // malformed input correctly rejected
    }
    return 0;
}

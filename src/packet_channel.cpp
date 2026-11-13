#include "packet_channel.h"

#include <cerrno>

bool is_transient_write_errno(int error_number)
{
    switch (error_number)
    {
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case ENOBUFS:
    case ENOMEM:
    case EINTR:
    case ENETDOWN:
        return true;
    default:
        return false;
    }
}

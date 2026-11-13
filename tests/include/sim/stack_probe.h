#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "network_stack.h"
#include "tcp_connection.h"

// Read-only views of NetworkStack's internal tables, for tests that ask "did
// this resource come back down?" (see test_soak.cpp). NetworkStack exposes
// behaviour, not the size of its connection table or timer heap, and adding
// accessors to the stack just to be counted would put test plumbing into the
// stack's interface - so the test reads the private members instead.
//
// How, without `#define private public` (which changes the class's layout
// contract and is undefined behaviour): the C++ rules exempt the template
// argument of an explicit instantiation from access checking, so
//
//     template struct Opener<Tag, &NetworkStack::_connections>;
//
// is legal even though _connections is private. Opener's static initializer
// stores a function that applies the pointer-to-member to a stack and hands
// the member to the tag's measure(). Using a pointer to member needs no
// access; only naming the member does, and that happens only in the
// instantiation lines at the bottom. Rename a member and exactly one of
// those lines stops compiling.
//
// Nothing here mutates the stack. Include this from exactly one translation
// unit: the explicit instantiations below may appear once per program.
namespace stack_probe
{
    template <class Tag, auto Member>
    struct Opener
    {
        static inline const bool installed =
            (Tag::read = [](const NetworkStack& stack) -> size_t { return Tag::measure(stack.*Member); }, true);
    };

    struct ConnectionsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& table)
        {
            return table.size();
        }
    };
    struct ConnectionRecordsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& table)
        {
            return table.size();
        }
    };
    struct TimerQueueTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& heap)
        {
            return heap.size();
        }
    };
    struct UdpSocketsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& table)
        {
            return table.size();
        }
    };
    struct ResolverPortsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& ports)
        {
            return ports.size();
        }
    };
    // Entries across every listening port's accept queue.
    struct PendingAcceptsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& by_port)
        {
            size_t total = 0;
            for (const auto& entry : by_port)
            {
                total += entry.second.size();
            }
            return total;
        }
    };
    // SYN_RECEIVED connections across every port.
    struct HalfOpenTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& by_port)
        {
            size_t total = 0;
            for (const auto& entry : by_port)
            {
                total += entry.second.size();
            }
            return total;
        }
    };
    // Tracked cookie slots, one per port that has ever sent a cookie.
    struct CookieSlotsTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& table)
        {
            return table.size();
        }
    };
    // ARP cache entries across interfaces.
    struct ArpEntriesTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& interfaces)
        {
            size_t total = 0;
            for (const auto& interface : interfaces)
            {
                total += interface->arp_table.size();
            }
            return total;
        }
    };
    // Resolutions in flight plus packets parked waiting for one.
    struct ArpPendingTag
    {
        static inline size_t (*read)(const NetworkStack&) = nullptr;
        template <class C>
        static size_t measure(const C& interfaces)
        {
            size_t total = 0;
            for (const auto& interface : interfaces)
            {
                total += interface->arp_requests_in_flight.size() + interface->pending_outbound_connects.size()
                         + interface->pending_outbound_datagrams.size();
            }
            return total;
        }
    };

    // The largest per-connection buffers over every live connection.
    struct ConnectionBuffers
    {
        size_t max_out_of_order_bytes = 0;
        size_t max_reorder_chunks = 0;
        size_t max_unacked_bytes = 0;
        size_t max_receive_queued_bytes = 0;
    };
    struct BuffersTag
    {
        static inline ConnectionBuffers (*read)(const NetworkStack&) = nullptr;
    };
    template <class Tag, auto Member>
    struct BufferOpener
    {
        static inline const bool installed = (Tag::read = [](const NetworkStack& stack) -> ConnectionBuffers
                                              {
                                                  ConnectionBuffers out;
                                                  for (const auto& entry : stack.*Member)
                                                  {
                                                      const TcpConnection* connection = entry.second.connection;
                                                      if (connection == nullptr)
                                                      {
                                                          continue;
                                                      }
                                                      out.max_out_of_order_bytes =
                                                          std::max(out.max_out_of_order_bytes,
                                                                   connection->bytes_out_of_order());
                                                      out.max_reorder_chunks = std::max(out.max_reorder_chunks,
                                                                                        connection->reorder_chunk_count());
                                                      out.max_unacked_bytes =
                                                          std::max(out.max_unacked_bytes, connection->bytes_unacked());
                                                      out.max_receive_queued_bytes =
                                                          std::max(out.max_receive_queued_bytes,
                                                                   connection->bytes_available());
                                                  }
                                                  return out;
                                              },
                                              true);
    };

    // The one place the private names appear.
    template struct Opener<ConnectionsTag, &NetworkStack::_connections>;
    template struct Opener<ConnectionRecordsTag, &NetworkStack::_connections_by_id>;
    template struct Opener<TimerQueueTag, &NetworkStack::_timer_queue>;
    template struct Opener<UdpSocketsTag, &NetworkStack::_udp_sockets>;
    template struct Opener<ResolverPortsTag, &NetworkStack::_resolver_ports>;
    template struct Opener<PendingAcceptsTag, &NetworkStack::_pending_accepts>;
    template struct Opener<HalfOpenTag, &NetworkStack::_half_open_per_port>;
    template struct Opener<CookieSlotsTag, &NetworkStack::_last_cookie_sent_ms>;
    template struct Opener<ArpEntriesTag, &NetworkStack::_interfaces>;
    template struct Opener<ArpPendingTag, &NetworkStack::_interfaces>;
    template struct BufferOpener<BuffersTag, &NetworkStack::_connections_by_id>;

    // A snapshot of every table's size.
    struct Snapshot
    {
        size_t connections = 0;       // the four-tuple table
        size_t connection_records = 0; // the id table; must equal `connections`
        size_t timer_queue = 0;        // heap entries, live and stale
        size_t udp_sockets = 0;
        size_t resolver_ports = 0;
        size_t pending_accepts = 0;
        size_t half_open = 0;
        size_t cookie_slots = 0;
        size_t arp_entries = 0;
        size_t arp_pending = 0;
        ConnectionBuffers buffers;
    };

    inline Snapshot snapshot(const NetworkStack& stack)
    {
        Snapshot s;
        s.connections = ConnectionsTag::read(stack);
        s.connection_records = ConnectionRecordsTag::read(stack);
        s.timer_queue = TimerQueueTag::read(stack);
        s.udp_sockets = UdpSocketsTag::read(stack);
        s.resolver_ports = ResolverPortsTag::read(stack);
        s.pending_accepts = PendingAcceptsTag::read(stack);
        s.half_open = HalfOpenTag::read(stack);
        s.cookie_slots = CookieSlotsTag::read(stack);
        s.arp_entries = ArpEntriesTag::read(stack);
        s.arp_pending = ArpPendingTag::read(stack);
        s.buffers = BuffersTag::read(stack);
        return s;
    }
}

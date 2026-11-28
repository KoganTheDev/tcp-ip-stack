#pragma once

// A private copy of the kernel's `struct tcp_info`, so that nothing here
// depends on which fields the C library's <netinet/tcp.h> happens to declare.
//
// glibc's struct stops at an older field set (Ubuntu 24.04's lacks
// tcpi_bytes_acked, tcpi_bytes_received, tcpi_notsent_bytes, tcpi_snd_wnd and
// tcpi_rcv_wnd), while <linux/tcp.h> has them but cannot be included together
// with <netinet/tcp.h> (the two redefine struct tcp_info and the TCP_* macros).
// So the layout is mirrored here, field for field and in order, from
// include/uapi/linux/tcp.h. That is sound because the UAPI struct only ever
// grows by appending: getsockopt(TCP_INFO) copies min(optlen, kernel size)
// bytes, and the offset of every existing field is frozen as kernel ABI.
//
// Use it for both sides: TCP_INFO on the user-space stack fills it, and a test
// reading the kernel's answer reads the real UAPI layout through it. The
// static_asserts below pin the prefix both structs share against the libc
// definition, so a layout slip here fails the build instead of corrupting a
// read at run time.

#include <netinet/tcp.h>

#include <cstddef>
#include <cstdint>

namespace ustack
{
    struct KernelTcpInfo
    {
        uint8_t tcpi_state;
        uint8_t tcpi_ca_state;
        uint8_t tcpi_retransmits;
        uint8_t tcpi_probes;
        uint8_t tcpi_backoff;
        uint8_t tcpi_options;
        uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
        uint8_t tcpi_delivery_rate_app_limited : 1, tcpi_fastopen_client_fail : 2;

        uint32_t tcpi_rto;
        uint32_t tcpi_ato;
        uint32_t tcpi_snd_mss;
        uint32_t tcpi_rcv_mss;

        uint32_t tcpi_unacked;
        uint32_t tcpi_sacked;
        uint32_t tcpi_lost;
        uint32_t tcpi_retrans;
        uint32_t tcpi_fackets;

        uint32_t tcpi_last_data_sent;
        uint32_t tcpi_last_ack_sent;
        uint32_t tcpi_last_data_recv;
        uint32_t tcpi_last_ack_recv;

        uint32_t tcpi_pmtu;
        uint32_t tcpi_rcv_ssthresh;
        uint32_t tcpi_rtt;
        uint32_t tcpi_rttvar;
        uint32_t tcpi_snd_ssthresh;
        uint32_t tcpi_snd_cwnd;
        uint32_t tcpi_advmss;
        uint32_t tcpi_reordering;

        uint32_t tcpi_rcv_rtt;
        uint32_t tcpi_rcv_space;

        uint32_t tcpi_total_retrans;

        uint64_t tcpi_pacing_rate;
        uint64_t tcpi_max_pacing_rate;
        uint64_t tcpi_bytes_acked;
        uint64_t tcpi_bytes_received;
        uint32_t tcpi_segs_out;
        uint32_t tcpi_segs_in;

        uint32_t tcpi_notsent_bytes;
        uint32_t tcpi_min_rtt;
        uint32_t tcpi_data_segs_in;
        uint32_t tcpi_data_segs_out;

        uint64_t tcpi_delivery_rate;

        uint64_t tcpi_busy_time;
        uint64_t tcpi_rwnd_limited;
        uint64_t tcpi_sndbuf_limited;

        uint32_t tcpi_delivered;
        uint32_t tcpi_delivered_ce;

        uint64_t tcpi_bytes_sent;
        uint64_t tcpi_bytes_retrans;
        uint32_t tcpi_dsack_dups;
        uint32_t tcpi_reord_seen;

        uint32_t tcpi_rcv_ooopack;

        uint32_t tcpi_snd_wnd; // peer's advertised window after scaling, bytes
        uint32_t tcpi_rcv_wnd; // local advertised window after scaling, bytes

        uint32_t tcpi_rehash;

        uint16_t tcpi_total_rto;
        uint16_t tcpi_total_rto_recoveries;
        uint32_t tcpi_total_rto_time;
        uint32_t tcpi_received_ce;
        uint32_t tcpi_delivered_e1_bytes;
        uint32_t tcpi_delivered_e0_bytes;
        uint32_t tcpi_delivered_ce_bytes;
        uint32_t tcpi_received_e1_bytes;
        uint32_t tcpi_received_e0_bytes;
        uint32_t tcpi_received_ce_bytes;
        uint32_t tcpi_ecn_mode : 2, tcpi_accecn_opt_seen : 2, tcpi_accecn_fail_mode : 4, tcpi_options2 : 24;
    };

// The fields every glibc has (the oldest common set, through tcpi_total_retrans)
// must sit at the same offsets in the libc struct and the mirror.
#define USTACK_CHECK_TCP_INFO_OFFSET(field)                                      \
    static_assert(offsetof(KernelTcpInfo, field) == offsetof(::tcp_info, field), \
                  "KernelTcpInfo::" #field " is not at the libc struct tcp_info offset")

    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_state);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_ca_state);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_retransmits);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_probes);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_backoff);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_options);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rto);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_ato);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_snd_mss);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rcv_mss);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_unacked);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_sacked);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_lost);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_retrans);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_fackets);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_last_data_sent);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_last_ack_sent);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_last_data_recv);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_last_ack_recv);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_pmtu);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rcv_ssthresh);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rtt);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rttvar);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_snd_ssthresh);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_snd_cwnd);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_advmss);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_reordering);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rcv_rtt);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_rcv_space);
    USTACK_CHECK_TCP_INFO_OFFSET(tcpi_total_retrans);
#undef USTACK_CHECK_TCP_INFO_OFFSET

    // The mirror must never be smaller than the libc struct, and the first
    // 64-bit field the old libc lacks is pinned to its UAPI offset (the
    // 8-byte header of byte fields precedes tcpi_rto).
    static_assert(sizeof(KernelTcpInfo) >= sizeof(::tcp_info),
                  "KernelTcpInfo is smaller than the libc struct tcp_info");
    static_assert(offsetof(KernelTcpInfo, tcpi_pacing_rate) == 104, "UAPI tcpi_pacing_rate offset");
    static_assert(offsetof(KernelTcpInfo, tcpi_bytes_acked) == 120, "UAPI tcpi_bytes_acked offset");
} // namespace ustack

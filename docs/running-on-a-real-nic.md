# Running the stack on a real network interface

By default this stack runs over a TAP device, where the kernel on the other side of
the interface is its only peer. It can also run over a physical NIC using an
`AF_PACKET` socket, answering for its own IP address on a real network segment:

```sh
sudo ./epoll-server --transport nic --device eth0 --ip 192.168.1.90 --port 8080
```

Read the rest of this page before doing that. One of the rules below is not optional.

## Why this works at all

The stack shares an interface with the kernel's own network stack, which raises an
obvious question: when a TCP segment arrives, why does the kernel not answer it first,
or reset it?

Because of where `AF_PACKET` sits. It taps the receive path before `ip_rcv`, so our
stack gets a copy of every frame regardless of what the kernel later decides. The
kernel then continues its own processing and, finding no local address matching the
destination and no route with forwarding enabled, silently drops the packet. It never
reaches the kernel's TCP, so the kernel cannot send a RST.

That entire argument depends on one thing:

> **The stack's IP must be an address the kernel does not own.**

Point it at the host's own address instead and the kernel's TCP *does* see every
inbound SYN, and resets it before our handshake completes. There is no clean way to
prevent that. The server refuses to start in that case, naming the interface the
address is configured on.

The corollary is that the stack answers ARP for its IP itself. It replies advertising
the interface's **real hardware MAC**, so peers unicast to that address and the NIC's
own filter delivers the frames. That is why promiscuous mode is never needed, and why
the stack never changes machine-wide interface state.

## Test it locally first

There is a self-contained integration test that runs the whole thing over a veth pair
against a peer in its own network namespace. It cannot disturb anything outside that
namespace, and it is repeatable:

```sh
sudo scripts/veth_test.sh
```

Run this before pointing anything at a real network. It is also a stricter test of one
thing than a real NIC: veth does no MAC filtering, so every frame on the link is
delivered and the stack's own L2 destination filter is what has to reject the
irrelevant ones.

## Picking a safe address

1. Find the subnet and gateway:
   ```sh
   ip -4 addr show dev eth0
   ip route
   ```
2. Find your router's DHCP pool from its admin page (often something like
   `.100`-`.200`). Choose an address **outside** the pool and clear of any static
   reservations.
3. Prove it is unclaimed, **from a different machine** on the same segment:
   ```sh
   ping -c3 192.168.1.90            # no reply
   sudo arping -c3 -I eth0 192.168.1.90   # no reply
   ```
4. Check IP forwarding on the server host:
   ```sh
   sysctl net.ipv4.ip_forward
   ```
   If it is `1` - Docker, libvirt, and most VPN clients set it - the kernel will try to
   *route* packets for your chosen address instead of dropping them, and may emit ICMP
   redirects or unreachables. Add:
   ```sh
   sudo iptables -I FORWARD -d 192.168.1.90 -j DROP
   sudo iptables -I FORWARD -s 192.168.1.90 -j DROP
   ```
   These cannot hide traffic from the stack: netfilter runs after the `AF_PACKET` tap.

## Use wired Ethernet

Do this over a cable, not Wi-Fi. Many access points run DHCP snooping or IP source
guard and silently drop frames sourced from an address not leased to that MAC. The
failure is invisible from the host and looks exactly like a bug in the stack. Wired
switches do not care.

## Verifying

Watch the wire in one terminal:

```sh
sudo tcpdump -i eth0 -nvve 'host 192.168.1.90 or arp'
```

Start the server in another. Check the startup line: it prints the transport, device,
resolved MAC and IP, so you can confirm it adopted the interface's real hardware
address.

Then, from a peer machine:

| Check | Expected |
|---|---|
| `ping -c3 192.168.1.90` | Echo replies. In tcpdump: the peer's `who-has`, our ARP reply advertising the real NIC MAC, then echo request/reply. |
| `arp -n \| grep 192.168.1.90` on the peer | The server's real NIC MAC. |
| `nc -v 192.168.1.90 8080`, type lines | Lines echoed back. In tcpdump: SYN / SYN-ACK / ACK, data with sane seq and ack, clean FIN exchange on Ctrl-D. |
| `nc -u -v 192.168.1.90 9999` | ICMP port unreachable, since nothing is bound there. |
| `dd if=/dev/zero bs=1M count=20 \| nc 192.168.1.90 8080` | Sustains without stalling. This is the one that would expose the hardcoded MSS or an event-loop starvation problem. |

And confirm you broke nothing on the host, while the server is still running:

```sh
ping -c3 <your gateway>          # host connectivity intact
curl -sI https://example.com     # still reaches the internet
ip link show eth0                # must NOT contain PROMISC
dmesg | tail                     # no flood of martian-destination lines
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `refusing to start: ... already configured on interface ...` | The chosen IP belongs to the kernel. Pick an unused one; see above. |
| `socket(AF_PACKET, SOCK_RAW) failed` | Needs `CAP_NET_RAW`. Run under `sudo`, or `setcap cap_net_raw,cap_net_admin+ep ./epoll-server`. |
| `interface eth0 is down` | `ip link set eth0 up`. |
| `interface eth0 has MTU 1450, but this stack's segment sizing assumes 1500` | The stack's MSS and fragmentation limits are compiled against 1500. Rejected up front, because the alternative symptom is bulk transfers stalling for no visible reason. |
| **Ping works but TCP and UDP are dropped as bad checksums** | Checksum offload. Only happens on virtual links (veth, loopback) that never leave the host, where the kernel skips computing transport checksums. Fix with `ethtool -K <iface> tx off rx off` on both ends. ICMP is not offloaded, which is why ping still works and gives the symptom away. Not an issue between two real machines. |
| Stack receives nothing at all | Either the interface is not carrying the traffic you expect, or `--mac` was overridden: the NIC will not deliver frames for a MAC it does not own, and this stack deliberately does not enable promiscuous mode. |

## Known limitations on a busy segment

Honest about what has not been done, since none of it is a correctness problem on a
quiet network:

- **Every frame delivered to the socket is parsed in userspace.** The stack drops
  frames not addressed to it, but only after `recvfrom` and a parse. On a busy segment
  a kernel-side `SO_ATTACH_FILTER` would be the real fix. Not done yet, deliberately -
  it is a hand-maintained BPF program whose failure mode is "silently receives
  nothing", and it should follow a measurement rather than a guess.
- **`NetworkStack::poll()` drains without a budget.** A continuously busy channel keeps
  it in its loop, delaying the retransmission timer and the completion queue in the
  epoll server. Harmless for the timer (late retransmissions are just late) and worth
  watching for the completion queue.

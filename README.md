# Router

A software IPv4 router written in C.

## What it does

The router receives raw Ethernet frames on any of its interfaces and decides what to do with them:

- **IPv4 forwarding** — looks up the destination IP in the routing table using longest-prefix match and forwards the packet out the correct interface
- **ARP** — answers ARP requests for its own interfaces, sends ARP requests when the next-hop MAC is unknown, and caches replies
- **ICMP** — replies to echo requests (ping) directed at the router itself, and sends back TTL exceeded (type 11) or destination unreachable (type 3) messages when appropriate

Packets that arrive while waiting for an ARP reply are held in a queue and sent out once the MAC address comes in.

## Implementation details

### Routing table

The routing table is loaded from a text file at startup (`rtable0.txt` / `rtable1.txt`). Entries are sorted by prefix/mask length using `qsort` so that a binary search (`bsearch` wrapper in `search_routes`) can find the longest-prefix match in O(log n). The table supports up to 100,000 entries.

### IPv4 pipeline

On receiving an IPv4 packet the router:

1. Verifies the IP checksum and drops the packet if it doesn't match
2. Checks if the destination is the router's own IP — if so, handles it locally (ICMP echo reply only; other protocols are dropped)
3. Decrements TTL; if TTL reaches 0 or 1 before decrement, sends an ICMP time-exceeded back to the sender
4. Looks up the destination in the routing table; sends ICMP destination unreachable if no route is found
5. Recalculates the IP checksum after the TTL decrement
6. Looks up the next-hop MAC in the ARP cache; if found, rewrites the Ethernet header and forwards; if not, queues the packet and sends an ARP request

### ARP

The ARP cache is a flat array with a cap of 10 entries (enough for the test topology). When a reply arrives, the entry is added to the cache and the oldest queued packet is dequeued and sent. Only one packet is dequeued per ARP reply — this is a simplification that works for the checker's two-router topology.

### ICMP

ICMP error messages (TTL exceeded, destination unreachable) copy the original IP header and first 8 bytes of the original payload into the ICMP payload, per RFC 792. Echo replies swap source/destination in both the Ethernet and IP headers and recalculate both checksums.

### Header definitions

All protocol headers (`ether_hdr`, `ip_hdr`, `icmp_hdr`, `arp_hdr`) are defined in `include/protocols.h` with `__attribute__((packed))` to prevent padding issues.

## Project structure

```
router.c          main router logic
include/
  protocols.h     Ethernet, IP, ICMP, ARP header structs
  lib.h           send_to_link, recv_from_any_link, routing/ARP table types
  queue.h         queue API
  list.h          linked list API
lib/
  lib.c           interface management, checksum, routing table I/O
  queue.c         queue implementation
  list.c          linked list implementation
rtable0.txt       routing table for router 0
rtable1.txt       routing table for router 1
checker/          Mininet-based test topology and checker scripts
Makefile
```

## Build

```bash
make
```

Produces the `router` binary. Requires `gcc`.

To clean build artifacts:

```bash
make clean
```

## Running manually

The router takes the routing table file as the first argument, followed by the interface names:

```bash
./router rtable0.txt rr-0-1 r-0 r-1
```

There are Makefile shortcuts for the two routers in the test topology:

```bash
make run_router0
make run_router1
```

These require the virtual interfaces to already exist (set up by the Mininet topology).

## Running the checker

The checker uses Mininet to spin up a two-router topology and runs a series of tests against it. You need Python 3, Mininet, and root access.

```bash
sudo bash checker/checker.sh
```

This runs `make` first, then starts the topology and tests. Test results are printed to stdout.

## Dependencies

- gcc
- Python 3
- Mininet (`sudo apt install mininet` on Debian/Ubuntu)
- Root privileges for the checker (Mininet needs them)

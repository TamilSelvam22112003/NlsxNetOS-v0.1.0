# NLE2 performance and benchmark record

## Exact-head benchmark results

Current benchmark evidence is from GitHub Actions run **38892600029**, implementation/test head `efacc12f828c2a67cae781a56f98fd4486267dbf`. Both Ubuntu jobs ran 20,000 seal/open iterations with 1,280-byte inner packets, a fixed 32-byte NLE2 AAD header, a 128-bit GCM tag, directional session keys, and IV prefixes. These are in-process measurements; they exclude TUN, sockets, route lookup, and scheduling.

| Runner | Python / cryptography | Seal | Open | Seal + open |
|---|---|---:|---:|---:|
| Ubuntu 22.04; AMD EPYC 7763 64-Core; Linux 6.8.0-1064-azure; iperf3 3.9 | 4.94 Mbit/s UDP check from earlier baseline | **15.93 Mbit/s estimated delivered rate**; **92.04% loss**. Estimate is sender rate adjusted by reported loss because iperf3 3.9 omits `sum_received` in client JSON. | `UDP_ECHO_RETURN_OK 1280`; route-table startup/CA no-change and operator positive-control markers present. |
| Ubuntu 24.04; AMD EPYC 7763 64-Core; Linux 6.17.0-1022-azure; iperf3 3.16 | 3.22 Mbit/s receiver-measured from earlier baseline | **2.67 Mbit/s receiver-measured rate**; **98.26% loss**. | `UDP_ECHO_RETURN_OK 1280`; route-table startup/CA no-change and operator positive-control markers present. |

The in-process seal/open round trip exceeds 100 Mbit/s on both runners. Results vary with runner hardware and library/runtime versions; do not treat these figures as end-to-end throughput.

## End-to-end netns / iperf3 results

The same Actions run exercised the six-node IPv6 lab. The offered-rate benchmark used iperf3 UDP at 200 Mbit/s for 5 seconds with 1,280-byte inner IPv4 packets (1,252-byte UDP payload + 20-byte IPv4 header + 8-byte UDP header). The WAN-node lab captured the actual NLE2 datagram for the pcap confidentiality test.

| Runner | 10 Mbit/s UDP check | 200 Mbit/s offered benchmark | Return-path evidence |
|---|---|---|---|
| Ubuntu 22.04; AMD EPYC 7763 64-Core; Linux 6.8.0-1064-azure; iperf3 3.9 | 4.94 Mbit/s UDP check from earlier baseline; current 200 Mbit/s offered run: **15.93 Mbit/s estimated delivered rate**; **92.04% loss**. Estimate is sender rate adjusted by reported loss because iperf3 3.9 omits `sum_received` in client JSON. | `UDP_ECHO_RETURN_OK 1280`; route-table startup/CA no-change and operator positive-control markers present. |
| Ubuntu 24.04; AMD EPYC 7763 64-Core; Linux 6.17.0-1022-azure; iperf3 3.16 | Current 200 Mbit/s offered run: **2.67 Mbit/s receiver-measured rate**; **98.26% loss**. | `UDP_ECHO_RETURN_OK 1280`; route-table startup/CA no-change and operator positive-control markers present. |

The Ubuntu 22.04 metric is explicitly an estimate derived from the sender rate and receiver-reported packet loss; Ubuntu 24.04 reports the receiver summary directly. The six-node job passed on both OS versions, including TCP traffic, UDP traffic, return-path checks, route-table comparison, WAN-node pcap confidentiality, and vIP lifecycle assertions. Current exact-head log markers: `NLS_ROUTE_TABLE_STARTUP_NO_CA_ROUTE_CHANGE`, `NLS_ROUTE_TABLE_CA_NO_CHANGE`, and `NLS_ROUTE_TABLE_OPERATOR_POSITIVE_CONTROL`.

**Target status:** end-to-end throughput is far below 100 Mbit/s despite in-process AEAD round-trip results of 278.18 Mbit/s on Ubuntu 22.04 and 376.11 Mbit/s on Ubuntu 24.04. The current six-node UDP run delivered 15.93 Mbit/s estimated on Ubuntu 22.04 with 92.04% loss, and 2.67 Mbit/s receiver-measured on Ubuntu 24.04 with 98.26% loss. The target is **NOT MET**. The observed gap indicates the bottleneck is outside the raw AEAD primitive. The likely hot path is per-datagram TUN read/write, Python packet parsing and allocation, UDP socket send/receive, route/session lookup, event-loop scheduling, and associated packet loss/queue pressure. This is a hypothesis based on the in-process versus netns gap, not a profiler-confirmed attribution: no sampling profile or per-stage CPU timing was collected in this run. Do not claim in-process results as end-to-end performance.

## Batching trial

A bounded TUN/UDP batching trial (Actions run **38889159363**, commit `33fd3c457f8f70b193024a059fdbc94cbee65198`) measured 2.70 Mbit/s with 98.18% loss, compared with the unbatched baseline of 2.58 Mbit/s with 95.03% loss on the same reported CPU model. The adjacent 1,280-byte UDP measurement also decreased from 3.51 to 3.38 Mbit/s. This was not a material improvement and loss was worse, so the batching change was reverted.

## Follow-up

- Profile TUN reads, UDP receive/send, queueing, and Python scheduling separately before further optimization.
- Keep the bounded queue, packet ordering, replay checks, and per-packet AEAD unchanged.
- NAT traversal remains **NOT VERIFIED**.

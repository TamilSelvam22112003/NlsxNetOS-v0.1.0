# NLE2 performance and benchmark record

## Exact-head benchmark results

GitHub Actions run **38890480995** validated implementation commit `a779ed904ebc13b0f86321999945af30a9abdc15`. Both Ubuntu jobs ran 20,000 seal/open iterations with 1,280-byte inner packets, a fixed 32-byte NLE2 AAD header, a 128-bit GCM tag, directional session keys, and IV prefixes. These are in-process measurements; they exclude TUN, sockets, route lookup, and scheduling.

| Runner | Python / cryptography | Seal | Open | Seal + open |
|---|---|---:|---:|---:|
| Ubuntu 22.04; AMD EPYC 7763 64-Core; Linux 6.8.0-1064-azure | Python 3.10.12 / cryptography 3.4.8 | 549.19 Mbit/s (53,631.59 pps) | 589.68 Mbit/s (57,586.13 pps) | 282.41 Mbit/s (27,578.75 pps) |
| Ubuntu 24.04; AMD EPYC 7763 64-Core; Linux 6.17.0-1022-azure | Python 3.12.3 / cryptography 41.0.7 | 679.50 Mbit/s (66,357.78 pps) | 744.39 Mbit/s (72,694.03 pps) | 365.89 Mbit/s (35,731.01 pps) |

The in-process seal/open round trip exceeds 100 Mbit/s on both runners. Results vary with runner hardware and library/runtime versions; do not treat these figures as end-to-end throughput.

## End-to-end netns / iperf3 results

The same Actions run exercised the six-node IPv6 lab. The offered-rate benchmark used 200 Mbit/s for 5 seconds with 1,280-byte inner IPv4 packets (1,252-byte UDP payload + 20-byte IPv4 header + 8-byte UDP header).

| Runner | 10 Mbit/s UDP check | 200 Mbit/s offered benchmark | Return-path evidence |
|---|---|---|---|
| Ubuntu 22.04; Intel Xeon Platinum 8573C; Linux 6.8.0-1064-azure; iperf3 3.9 | 4.94 Mbit/s estimated delivered rate; 50.55% loss. Metric is sender rate adjusted by iperf3's reported loss because version 3.9 omits `sum_received` in client JSON. | **6.46 Mbit/s** estimated delivered rate; **96.77% loss**; target not met. | `UDP_ECHO_RETURN_OK 1280` |
| Ubuntu 24.04; AMD EPYC 9V74 80-Core; Linux 6.17.0-1022-azure; iperf3 3.12 | 3.46 Mbit/s receiver rate; 51.79% loss. | **3.22 Mbit/s** receiver rate; **97.48% loss**; target not met. | `UDP_ECHO_RETURN_OK 1280` |

The Ubuntu 22.04 metric is explicitly an estimate derived from the sender rate and receiver-reported packet loss; Ubuntu 24.04 reports the receiver summary directly. The six-node job passed on both OS versions, including TCP traffic, UDP traffic, return-path checks, route-table comparison, and vIP lifecycle assertions.

**Target status:** end-to-end throughput is far below 100 Mbit/s despite in-process AEAD exceeding that target. The gap points to overhead outside the AEAD primitive, likely the single-threaded per-datagram TUN/socket/event-loop and scheduling path. This is a measured inference, not profiler-confirmed attribution; exact stage-level profiling remains open. Do not present in-process results as end-to-end performance.

## Batching trial

A bounded TUN/UDP batching trial (Actions run **38889159363**, commit `33fd3c457f8f70b193024a059fdbc94cbee65198`) measured 2.70 Mbit/s with 98.18% loss, compared with the unbatched baseline of 2.58 Mbit/s with 95.03% loss on the same reported CPU model. The adjacent 1,280-byte UDP measurement also decreased from 3.51 to 3.38 Mbit/s. This was not a material improvement and loss was worse, so the batching change was reverted.

## Follow-up

- Profile TUN reads, UDP receive/send, queueing, and Python scheduling separately before further optimization.
- Keep the bounded queue, packet ordering, replay checks, and per-packet AEAD unchanged.
- NAT traversal remains **NOT VERIFIED**.

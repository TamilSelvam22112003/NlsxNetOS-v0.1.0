# NLE2 performance and benchmark record

## In-process AES-256-GCM benchmark

Measured by GitHub Actions run **38887599960** on Ubuntu 24.04 (the NLE2 benchmark step completed successfully). The exact-head run was based on commit `9c9d82673d8b5be5a322eee52f86a152792a1b6a`; the measured encapsulation implementation is unchanged by the later test-only commits.

- CPU: AMD EPYC 9V45 96-Core Processor
- OS/kernel: Linux 6.17.0-1022-azure, Ubuntu 24.04 runner
- Python: 3.12.3
- cryptography: 41.0.7
- Method: 20,000 operations at 1,280-byte inner-packet size; fixed 32-byte NLE2 AAD header, 128-bit GCM tag, directional session key and IV prefix. In-process only; excludes TUN, sockets, route lookup, and scheduling.

| Operation | Throughput | Packets/s |
|---|---:|---:|
| Seal | 1,366.75 Mbit/s | 133,471.91 |
| Open | 1,313.61 Mbit/s | 128,282.48 |
| Seal + open round trip | 718.81 Mbit/s | 70,196.26 |

The in-process cryptographic loop exceeds the 100 Mbit/s target. These figures are not end-to-end network throughput.

## Netns / iperf3 benchmark

Measured in the six-node IPv6 namespace lab on Ubuntu 24.04 with the same reported CPU model (AMD EPYC 7763 64-Core Processor), Linux 6.17.0-1022-azure, and iperf3 method:

- **Baseline (no batching):** CI run **38887944923**, implementation commit `5d5389e3dad919b809a6a2a41d37dc694c76e7a2`; receiver throughput **2.58 Mbit/s**, packet loss **95.03%**, adjacent `NLS_UDP_1280` measurement **3.51 Mbit/s**. The traffic measurement completed before a separate post-test assertion failed.
- **Batching trial:** CI run **38889159363**, implementation commit `33fd3c457f8f70b193024a059fdbc94cbee65198`; bounded TUN reads and bounded reads on the stable WAN socket; receiver throughput **2.70 Mbit/s**, packet loss **98.18%**, adjacent `NLS_UDP_1280` measurement **3.38 Mbit/s**. The lab passed, but throughput did not materially improve and packet loss was worse.

Method: iperf3 UDP; 1,252-byte UDP payload + 20-byte IPv4 header + 8-byte UDP header = 1,280-byte inner packet; 200 Mbit/s offered rate for 5 seconds.

**Target status:** the end-to-end lab is below 100 Mbit/s. The batching trial was reverted because it did not show a material benefit. The gap between the in-process seal/open rate and netns result points to overhead outside the AEAD primitive—likely the single-threaded per-datagram TUN/socket/event-loop and scheduling path. This is an evidence-based hypothesis, not a profiler-confirmed attribution; exact stage-level profiling remains open. Do not report the in-process result as end-to-end performance.

## Follow-up

- Profile TUN reads, UDP receive/send, queueing, and Python scheduling separately before further optimization.
- Keep the bounded queue, packet ordering, replay checks, and per-packet AEAD unchanged.
- Re-run this benchmark on the final exact head after the rekey/lab fixes. NAT traversal remains **NOT VERIFIED**.

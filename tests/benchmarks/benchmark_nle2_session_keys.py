"""NLE2 AES-256-GCM session-key microbenchmark.

This is an in-process microbenchmark, not an end-to-end network throughput claim.
The separate netns iperf3 result measures the production daemon and routing path.
"""
import argparse
import json
import os
import platform
import time

import cryptography
from nls.encapsulation import open_ip_packet, seal_ip_packet


def cpu_model():
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def make_ipv6_packet(size):
    if size < 40 or size > 65479:
        raise ValueError("size must be 40..65479")
    packet = bytearray(40)
    packet[0] = 0x60
    packet[4:6] = (size - 40).to_bytes(2, "big")
    packet[6] = 17
    packet[7] = 64
    packet[8:24] = bytes.fromhex("20010db8000100000000000000000010")
    packet[24:40] = bytes.fromhex("20010db8000200000000000000000020")
    return bytes(packet) + (b"N" * (size - 40))


def mbps(packet_size, iterations, elapsed):
    return (packet_size * iterations * 8) / max(elapsed, 1e-9) / 1_000_000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--size", type=int, default=1280)
    args = parser.parse_args()
    if args.iterations < 100 or args.iterations > 1_000_000:
        parser.error("--iterations must be 100..1000000")

    key = os.urandom(32)
    session_id = os.urandom(16)
    iv_prefix = os.urandom(4)
    payload = make_ipv6_packet(args.size)
    # Warm-up the same API used by the NLE2 data path.
    warm = seal_ip_packet(key, session_id, 0, iv_prefix, payload)
    assert open_ip_packet(key, warm, session_id, iv_prefix) == payload

    packets = []
    start = time.perf_counter()
    for sequence in range(args.iterations):
        packets.append(seal_ip_packet(key, session_id, sequence, iv_prefix, payload))
    seal_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    for packet in packets:
        assert open_ip_packet(key, packet, session_id, iv_prefix) == payload
    open_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    for sequence in range(args.iterations):
        packet = seal_ip_packet(key, session_id, sequence, iv_prefix, payload)
        assert open_ip_packet(key, packet, session_id, iv_prefix) == payload
    roundtrip_elapsed = time.perf_counter() - start

    result = {
        "benchmark": "nle2_session_key_aes256gcm",
        "method": "in-process; fixed 32-byte AAD header; 128-bit tag; directional key and IV prefix; excludes sockets/TUN/routing",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "cpu_model": cpu_model(),
        "packet_size_bytes": args.size,
        "iterations": args.iterations,
        "seal_mbps": round(mbps(args.size, args.iterations, seal_elapsed), 2),
        "open_mbps": round(mbps(args.size, args.iterations, open_elapsed), 2),
        "roundtrip_mbps": round(mbps(args.size, args.iterations, roundtrip_elapsed), 2),
        "seal_packets_per_second": round(args.iterations / seal_elapsed, 2),
        "open_packets_per_second": round(args.iterations / open_elapsed, 2),
        "roundtrip_packets_per_second": round(args.iterations / roundtrip_elapsed, 2),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

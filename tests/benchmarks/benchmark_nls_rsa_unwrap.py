"""Reproducible single-process RSA-3072 OAEP unwrap microbenchmark.

This measures only the existing per-packet key-unwrapping operation. It is not
an end-to-end throughput test and must not be generalized beyond the runner.
"""
import platform
import statistics
import sys
import time

import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from nls.rsa import unwrap_key, wrap_key

ROUNDS = 5
ITERATIONS = 100

def main():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    wrapped = wrap_key(private.public_key(), b"K" * 32)
    for _ in range(10):
        assert unwrap_key(private, wrapped) == b"K" * 32
    elapsed = []
    for _ in range(ROUNDS):
        start = time.perf_counter_ns()
        for _ in range(ITERATIONS):
            assert unwrap_key(private, wrapped) == b"K" * 32
        elapsed.append((time.perf_counter_ns() - start) / ITERATIONS)
    median_ns = statistics.median(elapsed)
    print("benchmark=nls_rsa3072_oaep_unwrap")
    print(f"python={platform.python_version()}")
    print(f"cryptography={cryptography.__version__}")
    print("rsa_bits=3072")
    print(f"rounds={ROUNDS}")
    print(f"iterations_per_round={ITERATIONS}")
    print(f"median_unwrap_ms={median_ns / 1_000_000:.4f}")
    print(f"single_core_estimated_unwraps_per_second={1_000_000_000 / median_ns:.2f}")
    print(f"platform={platform.platform()}")
    print("scope=decrypt-only; excludes packet parsing, AEAD, socket, routing, and contention")

if __name__ == "__main__":
    main()

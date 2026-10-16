"""Legacy-only RSA-3072 OAEP unwrap baseline.

This reproduces the historical per-packet key-unwrapping cost for comparison
only. The active NLE2 data path does not use RSA wrapping or unwrapping.
"""
import platform
import statistics
import time

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROUNDS = 5
ITERATIONS = 100


def _legacy_wrap(public_key, data_key):
    return public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _legacy_unwrap(private_key, wrapped_key):
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def main():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    wrapped = _legacy_wrap(private.public_key(), b"K" * 32)
    for _ in range(10):
        assert _legacy_unwrap(private, wrapped) == b"K" * 32
    elapsed = []
    for _ in range(ROUNDS):
        start = time.perf_counter_ns()
        for _ in range(ITERATIONS):
            assert _legacy_unwrap(private, wrapped) == b"K" * 32
        elapsed.append((time.perf_counter_ns() - start) / ITERATIONS)
    median_ns = statistics.median(elapsed)
    print("benchmark=legacy_rsa3072_oaep_unwrap_baseline")
    print(f"python={platform.python_version()}")
    print(f"cryptography={cryptography.__version__}")
    print("rsa_bits=3072")
    print(f"rounds={ROUNDS}")
    print(f"iterations_per_round={ITERATIONS}")
    print(f"median_unwrap_ms={median_ns / 1_000_000:.4f}")
    print(f"single_core_estimated_unwraps_per_second={1_000_000_000 / median_ns:.2f}")
    print(f"platform={platform.platform()}")
    print("scope=legacy-baseline-only; excludes NLE2 AEAD, parsing, socket, routing, and contention")


if __name__ == "__main__":
    main()

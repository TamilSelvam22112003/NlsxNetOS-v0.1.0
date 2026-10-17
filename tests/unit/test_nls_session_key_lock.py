"""Concurrency regression tests for NLE2 session-key lifetime."""
import threading
import time

from nls.daemon import NLSDaemon, Session
from nls.replay import ReplayWindow


def test_session_zeroization_waits_until_packet_key_lease_releases():
    session = Session(
        "peer-b",
        ("2001:db8::2", 4789),
        b"S" * 16,
        bytearray(b"K" * 32),
        bytearray(b"R" * 32),
        b"I" * 32,
        b"TXP2",
        b"RXP2",
        ReplayWindow(128),
        time.time(),
        time.time(),
    )
    started = threading.Event()
    finished = threading.Event()

    def zeroize():
        started.set()
        NLSDaemon._zeroize_session(session)
        finished.set()

    with session.key_lock:
        worker = threading.Thread(target=zeroize)
        worker.start()
        assert started.wait(timeout=1)
        time.sleep(0.05)
        assert not finished.is_set(), "session keys were zeroized while packet use held the key lock"
        assert any(session.send_key) and any(session.recv_key)

    worker.join(timeout=1)
    assert not worker.is_alive()
    assert finished.is_set()
    assert not any(session.send_key)
    assert not any(session.recv_key)
    assert session.state == "CLOSED"

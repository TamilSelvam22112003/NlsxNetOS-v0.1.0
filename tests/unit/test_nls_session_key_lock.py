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

def test_pending_handshake_abort_is_scoped_to_peer_and_cleans_runtime_state():
    """Trust invalidation aborts only pending handshakes for the revoked peer."""
    from nls.daemon import NLSDaemon

    class Runtime:
        def __init__(self):
            self.pending = {
                b"revoked": {"peer_id": "router-b", "source_addr": ("2001:db8::2", 4789)},
                b"other": {"peer_id": "router-c", "source_addr": ("2001:db8::3", 4789)},
            }
            self.aborted = []

        def _abort(self, session_id, reason, source_addr=None):
            self.aborted.append((session_id, reason, source_addr))
            self.pending.pop(session_id, None)

    class Owner:
        def __init__(self):
            self.v2 = Runtime()

    owner = Owner()
    NLSDaemon._abort_pending_handshakes(owner, "NLS_PEER_CERT_REVOKED", "router-b")

    assert b"revoked" not in owner.v2.pending
    assert b"other" in owner.v2.pending
    assert owner.v2.aborted == [
        (b"revoked", "NLS_PEER_CERT_REVOKED", ("2001:db8::2", 4789))
    ]


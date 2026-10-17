"""Regression tests for NLS session activity accounting."""
import time
from types import SimpleNamespace

from nls.daemon import NLSDaemon


def _daemon_with_session(*, last_seen, last_tx):
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(session_timeout_seconds=30)
    daemon.sessions = {
        b"session-id": SimpleNamespace(
            state="ESTABLISHED",
            overlap_until=0.0,
            last_seen=last_seen,
            last_tx=last_tx,
        )
    }
    daemon.removed = []
    daemon._remove_session = lambda sid, reason: daemon.removed.append((sid, reason))
    return daemon


def test_transmit_activity_prevents_idle_session_expiry():
    now = time.time()
    daemon = _daemon_with_session(last_seen=now - 45, last_tx=now - 2)

    daemon._cleanup_sessions(time.monotonic())

    assert daemon.removed == []


def test_session_expires_when_both_receive_and_transmit_are_idle():
    now = time.time()
    daemon = _daemon_with_session(last_seen=now - 45, last_tx=now - 40)

    daemon._cleanup_sessions(time.monotonic())

    assert daemon.removed == [(b"session-id", "NLS_SESSION_IDLE_TIMEOUT")]

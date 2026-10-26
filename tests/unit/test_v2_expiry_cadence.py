from types import SimpleNamespace

from nls.v2_runtime import HandshakeV2


class CountingTrustTable:
    def __init__(self, expired_once=()):
        self.calls = 0
        self.expired_once = list(expired_once)

    def expire(self):
        self.calls += 1
        expired, self.expired_once = self.expired_once, []
        return expired


def test_trust_expiry_scan_is_bounded_to_half_second_and_tears_down_expired_session():
    session_id = b"\x01\x02"
    removed = []

    def remove_session(sid, reason):
        removed.append((sid, reason))

    owner = SimpleNamespace(
        cfg=SimpleNamespace(router_id="expiry-cadence-test"),
        sessions={session_id: object()},
        _remove_session=remove_session,
    )
    runtime = HandshakeV2(owner)
    fake_table = CountingTrustTable(expired_once=[session_id.hex()])
    runtime.trust_table = fake_table

    runtime.expire(now=10.0)
    assert fake_table.calls == 1
    assert removed == [(session_id, "NLS_TRUST_TTL_EXPIRED")]

    # Packet-loop calls within the next 500 ms must not re-read persisted JSON.
    runtime.expire(now=10.1)
    runtime.expire(now=10.49)
    assert fake_table.calls == 1

    # The next scan occurs at the bounded cadence and remains functional.
    runtime.expire(now=10.5)
    assert fake_table.calls == 2

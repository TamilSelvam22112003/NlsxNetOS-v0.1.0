"""NLS v1 Prompt 1 six-node lab and strict-xfail attack matrix."""
from __future__ import annotations
import base64, ipaddress, os, shutil, subprocess, threading, time
from types import SimpleNamespace
import pytest
import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from nls.ca_client import ClientSettings, _DIRECTORY_DOMAIN, _validate_lookup_response
from nls.config import PeerConfig
from nls.daemon import NLSDaemon, Session
from nls.encapsulation import open_ip_packet, seal_ip_packet
from nls.handshake import INIT, encode_message
from nls.replay import ReplayWindow
from services.router import config as router_config

pytestmark = pytest.mark.integration
NODES = ("nlsv1-client", "nlsv1-rta", "nlsv1-wan", "nlsv1-rtb", "nlsv1-server", "nlsv1-ca")

def _run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=10)
def _ns(ns, *args, check=True):
    return _run("ip", "netns", "exec", ns, *args, check=check)
def _link(left_ns, left_if, right_ns, right_if, left_addr, right_addr, stem):
    a, b = f"{stem}a", f"{stem}b"
    _run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
    _run("ip", "link", "set", a, "netns", left_ns); _run("ip", "link", "set", b, "netns", right_ns)
    _ns(left_ns, "ip", "link", "set", a, "name", left_if); _ns(right_ns, "ip", "link", "set", b, "name", right_if)
    _ns(left_ns, "ip", "-6", "addr", "add", left_addr, "dev", left_if); _ns(right_ns, "ip", "-6", "addr", "add", right_addr, "dev", right_if)
    _ns(left_ns, "ip", "link", "set", left_if, "up"); _ns(right_ns, "ip", "link", "set", right_if, "up")

@pytest.fixture(scope="module")
def nls_v1_lab():
    """Create client-routerA-WAN-routerB-server plus CA on IPv6 veth pairs."""
    if os.geteuid() != 0: pytest.skip("network namespace lab requires root")
    if shutil.which("ip") is None: pytest.skip("iproute2 is required")
    created=[]
    try:
        for node in NODES:
            _run("ip", "netns", "add", node); created.append(node); _ns(node, "ip", "link", "set", "lo", "up")
        _link(NODES[0],"c0",NODES[1],"ra0","fd00:1::1/64","fd00:1::2/64","n1c")
        _link(NODES[1],"ra1",NODES[2],"w0","fd00:2::1/64","fd00:2::2/64","n1a")
        _link(NODES[2],"w1",NODES[3],"rb0","fd00:3::1/64","fd00:3::2/64","n1b")
        _link(NODES[3],"rb1",NODES[4],"s0","fd00:4::1/64","fd00:4::2/64","n1s")
        _link(NODES[2],"w2",NODES[5],"ca0","fd00:5::1/64","fd00:5::2/64","n1d")
        _ns(NODES[2],"sysctl","-w","net.ipv6.conf.all.forwarding=1")
        _ns(NODES[2],"sysctl","-w","net.ipv6.conf.default.forwarding=1")
        _ns(NODES[0],"ip","-6","route","add","fd00:4::/64","via","fd00:1::2")
        _ns(NODES[1],"ip","-6","route","add","fd00:4::/64","via","fd00:2::2")
        _ns(NODES[2],"ip","-6","route","add","fd00:1::/64","via","fd00:2::1","dev","w0")
        _ns(NODES[2],"ip","-6","route","add","fd00:4::/64","via","fd00:3::2","dev","w1")
        _ns(NODES[3],"ip","-6","route","add","fd00:1::/64","via","fd00:3::1")
        _ns(NODES[4],"ip","-6","route","add","fd00:1::/64","via","fd00:4::1")
        yield {"nodes":NODES,"addresses":{"client":"fd00:1::1","server":"fd00:4::2","ca":"fd00:5::2"}}
    finally:
        for node in reversed(created): _run("ip","netns","del",node,check=False)

@pytest.fixture(scope="module")
def rsa_pair():
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    return key,key.public_key()
def _ipv6_packet(source="fd00::10", destination="fd00::20"):
    return bytes.fromhex("6000000000003b40")+ipaddress.IPv6Address(source).packed+ipaddress.IPv6Address(destination).packed
class _MemoryTun:
    def __init__(self): self.packets=[]
    def write(self,packet): self.packets.append(packet)

def test_lab_fixture_creates_six_nodes_and_ipv6_forwarding(nls_v1_lab):
    """Requirement: six-node IPv6 lab runs and WAN forwarding is enabled."""
    assert len(nls_v1_lab["nodes"])==6
    assert _ns("nlsv1-wan","sysctl","-n","net.ipv6.conf.all.forwarding").stdout.strip()=="1"
    assert "fd00:1::1" in _ns("nlsv1-client","ip","-6","addr","show","dev","c0").stdout







def _client_settings(tmp_path, key):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return ClientSettings(
        endpoint="[::1]:4790", server_id="ca-test", server_public_key=base64.b64encode(public).decode(),
        router_id="router-s", identity_key=tmp_path / "identity.key",
        certificate_file=tmp_path / "router.crt", ca_certificate_file=tmp_path / "root.crt",
        bootstrap_token_file=tmp_path / "bootstrap.token", router_token_file=tmp_path / "router.token",
        policy_file=tmp_path / "policy.json", revocation_file=tmp_path / "revocations.json",
        directory_file=tmp_path / "directory.json",
    )


def test_empty_operator_route_startup_and_reconfiguration_preserve_route_table(nls_v1_lab, tmp_path, monkeypatch):
    """Startup and a second configuration pass must not invent CA-derived routes."""
    from nls import routing

    ns = "nlsv1-client"
    _ns(ns, "ip", "link", "add", "nls-empty", "type", "dummy")
    _ns(ns, "ip", "link", "set", "nls-empty", "up")
    monkeypatch.setattr(
        routing,
        "_run",
        lambda args, check=True: _run("ip", "netns", "exec", ns, *args, check=check),
    )
    monkeypatch.setattr(routing, "STATE_PATH", tmp_path / "empty-routes.json")
    before = _ns(ns, "ip", "-6", "route", "show").stdout
    assert routing.install_tun_routes([], "nls-empty", routes=[]) == []
    assert routing.install_tun_routes([], "nls-empty", routes=[]) == []
    after = _ns(ns, "ip", "-6", "route", "show").stdout
    assert after == before


def test_operator_route_is_kernel_route_change_positive_control(nls_v1_lab, tmp_path, monkeypatch):
    """Only an explicit operator route is expected to mutate the main IPv6 table."""
    from nls import routing

    ns = "nlsv1-client"
    _ns(ns, "ip", "link", "add", "nls0", "type", "dummy")
    _ns(ns, "ip", "link", "set", "nls0", "up")
    monkeypatch.setattr(
        routing,
        "_run",
        lambda args, check=True: _run("ip", "netns", "exec", ns, *args, check=check),
    )
    monkeypatch.setattr(routing, "STATE_PATH", tmp_path / "operator-routes.json")
    config = {"router": {"interfaces": {}, "nls_routes": []}}
    router_config.add_nls_route(config, "2001:db8:dead::/48", "router-b")
    before = _ns(ns, "ip", "-6", "route", "show").stdout
    added = routing.install_tun_routes([], "nls0", routes=config["router"]["nls_routes"])
    after = _ns(ns, "ip", "-6", "route", "show").stdout
    assert "2001:db8:dead::/48" in added
    assert "2001:db8:dead::/48" not in before
    assert "2001:db8:dead::/48 dev nls0" in after


def test_forged_ca_response_rejected(tmp_path):
    """Requirement R14: reject a lookup response lacking a valid pinned-key signature."""
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _client_settings(tmp_path, key)
    nonce = "n" * 43
    payload = {"router_id": "router-d", "record_seq": 1, "status": "ACTIVE",
               "valid_until": int(time.time()) + 20, "client_nonce": nonce}
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope = {
        "payload": payload,
        "signer_public_key": base64.b64encode(public).decode(),
        "signature": base64.b64encode(key.sign(_DIRECTORY_DOMAIN + cbor2.dumps(payload, canonical=True))).decode(),
        "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
    }
    envelope["payload"]["router_id"] = "attacker"
    response = {"type": "lookup-result", "client_nonce": nonce, "record": envelope}
    with pytest.raises(RuntimeError, match="signature verification failed"):
        _validate_lookup_response(response, nonce, settings)
def test_tampered_ciphertext_rejected(nls_v1_lab):
    from nls.encapsulation import seal_ip_packet, open_ip_packet
    key, sid, prefix = b"K" * 32, b"S" * 16, b"IVP2"
    packet = bytearray(seal_ip_packet(key, sid, 1, prefix, _ipv6_packet()))
    packet[-1] ^= 1
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(packet), sid, prefix)


def test_tampered_header_rejected_by_aead(nls_v1_lab):
    from nls.encapsulation import seal_ip_packet, open_ip_packet

    key, sid, prefix = b"K" * 32, b"S" * 16, b"IVP2"
    packet = bytearray(seal_ip_packet(key, sid, 1, prefix, _ipv6_packet()))
    # Change only the sequence field. The header still parses, but because the
    # 32-byte header is AAD, authentication must fail before plaintext is returned.
    packet[31] ^= 1
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(packet), sid, prefix)


def test_replayed_packet_rejected(nls_v1_lab):
    from nls.encapsulation import seal_ip_packet, open_ip_packet
    key, sid, prefix = b"K" * 32, b"S" * 16, b"IVP2"
    packet = seal_ip_packet(key, sid, 1, prefix, _ipv6_packet())
    replay = ReplayWindow(128)
    assert replay.can_accept(1)
    assert open_ip_packet(key, packet, sid, prefix) == _ipv6_packet()
    assert replay.mark(1)
    assert not replay.can_accept(1)


def test_relay_abuse_tampered_and_replayed_datagrams_rejected(nls_v1_lab):
    from nls.encapsulation import seal_ip_packet, open_ip_packet
    key, sid, prefix = b"R" * 32, b"L" * 16, b"IVP2"
    replay = ReplayWindow(128)
    inner = _ipv6_packet("fd00::10", "2001:db8:2::20")
    captured = seal_ip_packet(key, sid, 1, prefix, inner)

    # A passive/active WAN relay can copy or alter the datagram, but cannot
    # make a modified packet authenticate or have a captured sequence accepted twice.
    assert open_ip_packet(key, captured, sid, prefix) == inner
    assert replay.mark(1)
    assert not replay.can_accept(1)
    tampered = bytearray(captured)
    tampered[-1] ^= 0x01
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(tampered), sid, prefix)
    assert replay.highest == 1

    forged_high = bytearray(seal_ip_packet(key, sid, 500000, prefix, inner))
    forged_high[-1] ^= 0x80
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(forged_high), sid, prefix)
    assert replay.highest == 1



def test_simultaneous_rekey_under_concurrent_traffic_zero_loss_repeated_runs():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon, Session
    from nls.source_token import open_source_token_payload
    from nls.v2_runtime import HandshakeV2

    inner = _ipv6_packet("fd00::10", "2001:db8:2::20")
    for iteration in range(5):
        arbitration = HandshakeV2.__new__(HandshakeV2)
        arbitration.owner = SimpleNamespace(cfg=SimpleNamespace(router_id="router-a"))
        arbitration.pending = {b"pending": {"rekey": True, "peer_id": "router-b"}}
        arbitration_drops, arbitration_aborts = [], []
        arbitration._drop = lambda reason, *_args: arbitration_drops.append(reason)
        arbitration._abort = lambda sid, reason, addr=None: arbitration_aborts.append((sid, reason))
        assert arbitration._resolve_simultaneous_rekey("router-b") is False
        assert arbitration_drops == ["NLS_REKEY_SIMULTANEOUS_LOST"]
        assert arbitration_aborts == []

        old_key, new_key = bytes([0x41 + iteration]) * 32, bytes([0x51 + iteration]) * 32
        old_sid, new_sid = bytes([0x61 + iteration]) * 16, bytes([0x71 + iteration]) * 16
        old = Session(
            "router-b", ("2001:db8::2", 4789), old_sid,
            bytearray(old_key), bytearray(b"O" * 32), b"I" * 32,
            b"OLD1", b"ORX1", ReplayWindow(128), time.time(), time.time(),
            send_token="2001:db8::10",
        )
        new = Session(
            "router-b", ("2001:db8::2", 4789), new_sid,
            bytearray(new_key), bytearray(b"N" * 32), b"I" * 32,
            b"NEW1", b"NRX1", ReplayWindow(128), time.time(), time.time(),
            send_token="2001:db8::11",
        )
        midpoint = threading.Event()
        resume = threading.Event()
        captured = []

        class CapturingSocket:
            def __init__(self, sid):
                self.sid = sid
            def sendto(self, packet, endpoint):
                captured.append((self.sid, bytes(packet), endpoint))
                if len(captured) == 100:
                    midpoint.set()
                    assert resume.wait(3), "rekey test traffic was not resumed"

        old.token_lease = SimpleNamespace(sock=CapturingSocket(old_sid))
        new.token_lease = SimpleNamespace(sock=CapturingSocket(new_sid))
        active = {"session": old}
        daemon = NLSDaemon.__new__(NLSDaemon)
        daemon.cfg = SimpleNamespace(rekey_packet_limit=1 << 32, rekey_seconds=3600)
        daemon.sessions = {old_sid: old, new_sid: new}
        daemon.peers = {"router-b": SimpleNamespace(id="router-b", encryption_public_key="unused")}
        daemon.stats = {"tx": 0, "drops": 0, "data_drops": 0}
        daemon.reason_counters = {}
        daemon._packet_destination = lambda _packet: "2001:db8:2::20"
        daemon._session_for_destination = lambda _destination: active["session"]
        results = []

        def send_traffic():
            for _ in range(200):
                results.append(daemon._send_payload(inner))

        sender = threading.Thread(target=send_traffic)
        sender.start()
        assert midpoint.wait(3), "traffic did not reach the make-before-break boundary"
        active["session"] = new
        resume.set()
        sender.join(timeout=5)
        assert not sender.is_alive()
        assert results == [True] * 200
        assert len(captured) == 200

        counts = {old_sid: 0, new_sid: 0}
        for packet_sid, packet, endpoint in captured:
            session = old if packet_sid == old_sid else new
            counter, message_type, body = open_source_token_payload(
                bytes(session.send_key), session.send_iv_prefix, packet,
                session.send_token, session.endpoint[0],
            )
            assert message_type == 0
            assert body == inner
            assert endpoint == session.endpoint
            counts[packet_sid] += 1
        assert counts == {old_sid: 100, new_sid: 100}
        assert old.packets_sent == 100
        assert new.packets_sent == 100


def test_active_data_path_never_calls_per_packet_rsa():
    from types import SimpleNamespace
    from nls import rsa as rsa_module
    from nls.daemon import NLSDaemon, Session
    from nls.source_token import open_source_token_payload

    assert not hasattr(rsa_module, "wrap_key")
    assert not hasattr(rsa_module, "unwrap_key")

    class FakeSocket:
        def __init__(self):
            self.sent = []
        def sendto(self, packet, endpoint):
            self.sent.append((packet, endpoint))

    key, sid, iv_prefix = b"N" * 32, b"R" * 16, b"IVP2"
    session = Session(
        "router-b", ("2001:db8::2", 4789), sid,
        bytearray(key), bytearray(b"D" * 32), b"I" * 32,
        iv_prefix, b"RXV2", ReplayWindow(128), time.time(), time.time(),
        send_token="2001:db8::10",
    )
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(rekey_packet_limit=1 << 32, rekey_seconds=3600)
    daemon.sessions = {sid: session}
    daemon.peers = {"router-b": SimpleNamespace(id="router-b", encryption_public_key="unused")}
    sock = FakeSocket()
    session.token_lease = SimpleNamespace(sock=sock)
    daemon.stats = {"tx": 0, "drops": 0, "data_drops": 0}
    daemon.reason_counters = {}
    daemon._packet_destination = lambda _packet: "2001:db8:2::20"
    daemon._session_for_destination = lambda _destination: session

    inner = _ipv6_packet("fd00::10", "2001:db8:2::20")
    assert daemon._send_payload(inner) is True
    assert len(sock.sent) == 1
    packet, endpoint = sock.sent[0]
    assert endpoint == session.endpoint
    counter, message_type, body = open_source_token_payload(
        key, iv_prefix, packet, session.send_token, session.endpoint[0]
    )
    assert counter == 0
    assert message_type == 0
    assert body == inner


def test_nle2_data_plane_log_canary(caplog):
    from types import SimpleNamespace
    from nls.source_token import seal_source_token_payload
    from nls.daemon import NLSDaemon, Session

    canary = b"INNER-PLAINTEXT-CANARY-4A"
    inner = bytearray(_ipv6_packet())
    inner.extend(canary)
    inner[4:6] = len(canary).to_bytes(2, "big")
    sid, key, prefix = b"C" * 16, b"K" * 32, b"IVP2"
    source_token, local_original_ip = "2001:db8::2", "2001:db8::1"
    packet = bytearray(seal_source_token_payload(
        key, prefix, 1, source_token, local_original_ip, bytes(inner)
    ))
    packet[-1] ^= 1
    session = Session(
        "peer-a", (source_token, 4789), sid, bytearray(b"S" * 32),
        bytearray(key), b"I" * 32, b"TXP2", prefix, ReplayWindow(128),
        time.time(), time.time(), recv_token=source_token,
        local_record={"originalIP": local_original_ip},
    )
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(enforce_inner_source_prefix=False, router_id="local-router")
    daemon.v2 = SimpleNamespace(is_retired_vip=lambda _address: False)
    daemon.sessions = {sid: session}
    daemon.tun = _MemoryTun()
    daemon.stats = {"drops": 0, "data_drops": 0, "rx": 0, "tx": 0}
    daemon.reason_counters = {}
    daemon._validate_inner_destination_prefix = lambda _packet: None
    with caplog.at_level("WARNING", logger="nlsxnetos.nls"):
        daemon._handle_data(bytes(packet), (source_token, 4789, 0, 0), sid)
    assert "NLS_DATA_AUTH_INVALID" in caplog.text
    assert canary.decode() not in caplog.text
    assert key.hex() not in caplog.text
    assert daemon.tun.packets == []

def test_inner_source_spoofing_rejected():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon

    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.v2 = SimpleNamespace(
        _cached_record=lambda peer_id: {"prefixes": ["2001:db8:1::/64"]}
    )
    assert daemon._validate_inner_source_prefix("peer-a", _ipv6_packet("2001:db8:1::10")) is None
    with pytest.raises(ValueError, match="INNER_SRC_NOT_ALLOWED"):
        daemon._validate_inner_source_prefix("peer-a", _ipv6_packet("2001:db8:99::10"))


def test_inner_destination_prefix_policy_rejects_unauthorized_destination():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon

    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(router_id="local-router")
    daemon.v2 = SimpleNamespace(
        _cached_record=lambda router_id: {"prefixes": ["fd00::/64"]}
    )
    assert daemon._validate_inner_destination_prefix(_ipv6_packet()) is None
    with pytest.raises(ValueError, match="INNER_DST_NOT_ALLOWED"):
        daemon._validate_inner_destination_prefix(_ipv6_packet(destination="2001:db8:99::20"))


def test_ca_unreachable_fails_closed(tmp_path, monkeypatch):
    """Requirement R14: ca mode must not fall back to cached trust when lookup is unavailable."""
    import nls.ca_client as client
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _client_settings(tmp_path, key)
    monkeypatch.setattr(client, "_load_root", lambda _path: object())
    monkeypatch.setattr(client, "_local_certificate", lambda *_args: "test-cert")
    def unavailable(*_args, **_kwargs):
        raise OSError("CA unreachable")
    monkeypatch.setattr(client, "_open_channel", unavailable)
    with pytest.raises(OSError, match="CA unreachable"):
        client.lookup(settings, None, "router-d")
def test_rekey_at_packet_or_time_threshold():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon, Session

    now = time.monotonic()
    peer = SimpleNamespace(id="router-b", encryption_public_key="test-key")
    cfg = SimpleNamespace(
        rekey_packet_limit=100, rekey_seconds=100, rekey_overlap_seconds=5,
        session_timeout_seconds=300,
    )
    calls = []
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = cfg
    daemon.peers = {"router-b": peer}
    daemon.v2 = SimpleNamespace(
        pending={},
        start=lambda p, original_ip, rekey=False: calls.append((p.id, rekey)),
    )
    daemon.sessions = {}
    session = Session(
        "router-b", ("2001:db8::2", 4789), b"A" * 16,
        bytearray(b"K" * 32), bytearray(b"R" * 32), b"I" * 32,
        b"TXP2", b"RXP2", ReplayWindow(128), time.time(), time.time(),
        tx_sequence=90,
    )
    session.created_mono = now
    daemon.sessions[session.session_id] = session
    daemon._maybe_rekey_sessions(now)
    assert calls == [("router-b", True)]

    calls.clear()
    daemon.v2.pending.clear()
    session.tx_sequence = 0
    session.created_mono = now - 90
    daemon._maybe_rekey_sessions(now)
    assert calls == [("router-b", True)]



def test_hard_limit_queues_packet_until_rekeyed_session_is_ready():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon, Session
    from nls.source_token import open_source_token_payload

    class FakeSocket:
        def __init__(self):
            self.sent = []
        def sendto(self, packet, endpoint):
            self.sent.append((packet, endpoint))

    peer = SimpleNamespace(id="router-b", encryption_public_key="test-key")
    cfg = SimpleNamespace(rekey_packet_limit=4, rekey_seconds=3600)
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = cfg
    daemon.peers = {"router-b": peer}
    daemon.sessions = {}
    daemon.pending_payloads = {}
    daemon.max_pending_payloads = 64
    daemon.reason_counters = {}
    daemon.stats = {"handshakes": 0, "established": 0, "rx": 0, "tx": 0, "drops": 0, "data_drops": 0}
    starts = []
    pending = {}
    def start_rekey(_peer, _original_ip, rekey=False):
        if rekey and any(state.get("rekey") and state.get("peer_id") == "router-b" for state in pending.values()):
            return
        starts.append(rekey)
        if rekey:
            pending[b"pending"] = {"rekey": True, "peer_id": "router-b"}
    daemon.v2 = SimpleNamespace(pending=pending, start=start_rekey)
    payloads = [
        _ipv6_packet(f"fd00::{index + 10}", "2001:db8:2::20")
        for index in range(3)
    ]
    old = Session(
        "router-b", ("2001:db8::2", 4789), b"O" * 16,
        bytearray(b"O" * 32), bytearray(b"o" * 32), b"I" * 32,
        b"OLD1", b"OLD2", ReplayWindow(128), time.time(), time.time(),
        tx_sequence=4, send_token="2001:db8::10",
    )
    new_key, new_sid, new_iv = b"N" * 32, b"Z" * 16, b"NEW1"
    new = Session(
        "router-b", ("2001:db8::2", 4789), new_sid,
        bytearray(new_key), bytearray(b"D" * 32), b"I" * 32,
        new_iv, b"NEW2", ReplayWindow(128), time.time(), time.time(),
        send_token="2001:db8::11",
    )
    daemon._packet_destination = lambda _packet: "2001:db8:2::20"
    daemon._session_for_destination = lambda _destination: old
    for payload in payloads:
        assert daemon._send_payload(payload) is False
    assert daemon.pending_payloads["router-b"] == payloads
    assert starts == [True]
    new_sock = FakeSocket()
    new.token_lease = SimpleNamespace(sock=new_sock)
    daemon._session_for_destination = lambda _destination: new
    daemon._flush_pending("router-b")
    assert len(new_sock.sent) == len(payloads)
    opened = [
        open_source_token_payload(
            new_key, new_iv, packet, new.send_token, new.endpoint[0]
        )[2]
        for packet, _endpoint in new_sock.sent
    ]
    assert opened == payloads
    assert all(endpoint == new.endpoint for _packet, endpoint in new_sock.sent)
    assert new.packets_sent == len(payloads)

def test_simultaneous_rekey_arbitration_is_deterministic():
    from types import SimpleNamespace
    from nls.v2_runtime import HandshakeV2

    aborted, dropped = [], []
    runtime = HandshakeV2.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(cfg=SimpleNamespace(router_id="router-a"))
    runtime.pending = {b"local": {"rekey": True, "peer_id": "router-b"}}
    runtime._drop = lambda reason, *_args: dropped.append(reason)
    runtime._abort = lambda sid, reason, addr=None: aborted.append((sid, reason))
    assert runtime._resolve_simultaneous_rekey("router-b") is False
    assert dropped == ["NLS_REKEY_SIMULTANEOUS_LOST"]
    assert aborted == []

    runtime.owner.cfg.router_id = "router-z"
    assert runtime._resolve_simultaneous_rekey("router-b") is True
    assert aborted == [(b"local", "NLS_REKEY_SIMULTANEOUS_LOST")]



def test_both_old_and_new_sessions_accept_data_during_overlap():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon, Session
    from nls.source_token import seal_source_token_payload

    old_sid, new_sid = b"O" * 16, b"N" * 16
    old_key, new_key = bytearray(b"O" * 32), bytearray(b"N" * 32)
    old_iv, new_iv = b"OLD1", b"NEW1"
    endpoint = ("2001:db8::2", 4789)
    local_original_ip = "2001:db8::1"
    old = Session(
        "router-b", endpoint, old_sid, bytearray(b"S" * 32), old_key, b"I" * 32,
        b"TXO1", old_iv, ReplayWindow(128), time.time(), time.time(),
        state="OVERLAP", recv_token=endpoint[0],
        local_record={"originalIP": local_original_ip},
    )
    new = Session(
        "router-b", endpoint, new_sid, bytearray(b"T" * 32), new_key, b"I" * 32,
        b"TXN1", new_iv, ReplayWindow(128), time.time(), time.time(),
        state="ESTABLISHED", recv_token=endpoint[0],
        local_record={"originalIP": local_original_ip},
    )
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(enforce_inner_source_prefix=False, router_id="local-router")
    daemon.v2 = SimpleNamespace(is_retired_vip=lambda _address: False)
    daemon.sessions = {old_sid: old, new_sid: new}
    daemon.tun = _MemoryTun()
    daemon.stats = {"rx": 0, "tx": 0, "drops": 0, "data_drops": 0}
    daemon.reason_counters = {}
    daemon._validate_inner_destination_prefix = lambda _packet: None
    inner = _ipv6_packet("fd00::10", "fd00::20")
    old_packet = seal_source_token_payload(bytes(old_key), old_iv, 1, endpoint[0], local_original_ip, inner)
    new_packet = seal_source_token_payload(bytes(new_key), new_iv, 1, endpoint[0], local_original_ip, inner)

    daemon._handle_data(old_packet, endpoint, old_sid)
    daemon._handle_data(new_packet, endpoint, new_sid)

    assert daemon.tun.packets == [inner, inner]
    assert old.recv_replay.highest == 1
    assert new.recv_replay.highest == 1

def test_old_session_is_zeroized_after_overlap():
    from types import SimpleNamespace
    from nls.daemon import NLSDaemon, Session

    old = Session(
        "router-b", ("2001:db8::2", 4789), b"O" * 16,
        bytearray(b"O" * 32), bytearray(b"R" * 32), b"I" * 32,
        b"OLD1", b"OLD2", ReplayWindow(128), time.time(), time.time(),
    )
    send_key, recv_key = old.send_key, old.recv_key
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(rekey_overlap_seconds=5, session_timeout_seconds=300)
    daemon.sessions = {old.session_id: old}
    daemon.reason_counters = {}
    daemon.stats = {"drops": 0}
    daemon._mark_sessions_for_overlap("router-b", b"N" * 16, now_mono=100)
    assert old.state == "OVERLAP"
    assert old.overlap_until == 105
    daemon._cleanup_sessions(106)
    assert old.session_id not in daemon.sessions
    assert old.state == "CLOSED"
    assert not any(send_key) and not any(recv_key)


def test_pcap_contains_no_inner_packet_or_source_plaintext(nls_v1_lab, tmp_path):
    """Capture a real NLE2 UDP frame on the WAN node and inspect its pcap bytes."""
    import struct

    key, sid, iv_prefix = b"P" * 32, b"S" * 16, b"IVP2"
    canary = b"NLE2-WAN-PLAINTEXT-CANARY"
    source = ipaddress.IPv6Address("2001:db8:111::10")
    destination = ipaddress.IPv6Address("2001:db8:222::20")
    inner = bytearray(40)
    inner[0] = 0x60
    inner[4:6] = len(canary).to_bytes(2, "big")
    inner[6] = 17
    inner[7] = 64
    inner[8:24] = source.packed
    inner[24:40] = destination.packed
    inner = bytes(inner) + canary
    nle2_packet = seal_ip_packet(key, sid, 42, iv_prefix, inner)

    # Route R1 -> WAN -> R2 and capture on the actual WAN veth interface.
    _ns("nlsv1-rta", "ip", "-6", "route", "add", "fd00:3::/64", "via", "fd00:2::2")
    capture_code = "\n".join([
        "import socket,time",
        "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))",
        "s.bind(('w0',0)); s.settimeout(0.5); print('READY',flush=True)",
        "end=time.time()+4",
        "while time.time()<end:",
        " try:",
        "  frame=s.recv(65535)",
        "  if len(frame)>=62 and frame[12:14]==bytes.fromhex('86dd') and frame[20]==17 and frame[56:58]==bytes.fromhex('12b5'):",
        "   print(frame.hex(),flush=True); break",
        " except socket.timeout:",
        "  pass",
    ])
    capture = subprocess.Popen(
        ["ip", "netns", "exec", "nlsv1-wan", os.sys.executable, "-c", capture_code],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        assert capture.stdout is not None
        assert capture.stdout.readline().strip() == "READY"
        send_code = (
            "import base64,socket; "
            f"p=base64.b64decode('{base64.b64encode(nle2_packet).decode()}'); "
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
            "s.sendto(p,('fd00:3::2',4789,0,0))"
        )
        _ns("nlsv1-rta", os.sys.executable, "-c", send_code)
        output, _ = capture.communicate(timeout=5)
        frames = [line.strip() for line in output.splitlines() if line.strip()]
        assert frames, "WAN capture did not observe an NLE2 UDP datagram"
        captured_frame = bytes.fromhex(frames[0])
        pcap = tmp_path / "nle2-wan-capture.pcap"
        pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet_header = struct.pack("<IIII", int(time.time()), 0, len(captured_frame), len(captured_frame))
        pcap.write_bytes(pcap_header + packet_header + captured_frame)
        assert pcap.exists() and pcap.stat().st_size > 40
        assert source.packed not in captured_frame
        assert destination.packed not in captured_frame
        assert canary not in captured_frame
    finally:
        if capture.poll() is None:
            capture.terminate()
        try:
            capture.wait(timeout=3)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait(timeout=3)


def _trust_test_daemon(monkeypatch, peer_status="ACTIVE", freshness_seconds=60, revoked_serial=None):
    from types import SimpleNamespace
    from nls import ca_client
    from nls.daemon import NLSDaemon, Session

    # This helper deliberately tests cached-state decisions; the real CA heartbeat
    # is exercised by the live cross-repository integration test.
    monkeypatch.setattr(ca_client, "refresh_live_state", lambda *_args: None)
    monkeypatch.setattr(ca_client, "heartbeat_freshness", lambda *_args: 90)
    now = int(time.time())
    local_record = {
        "router_id": "router-a", "status": "ACTIVE", "certificate_serial": "local-cert",
        "record_seq": 3, "issued_at": now, "valid_until": now + 30,
        "ed25519_public_key": "local-key", "rsa_encryption_public_key": "local-rsa",
        "wan_endpoints": [], "gateway_ips": [], "prefixes": ["2001:db8:1::/64"],
    }
    peer_record = {
        "router_id": "router-b", "status": peer_status, "certificate_serial": "peer-cert",
        "record_seq": 4, "issued_at": now, "valid_until": now + 30,
        "ed25519_public_key": "peer-key", "rsa_encryption_public_key": "peer-rsa",
        "wan_endpoints": [], "gateway_ips": [], "prefixes": ["2001:db8:2::/64"],
    }
    session = Session(
        "router-b", ("2001:db8::2", 4789), b"T" * 16,
        bytearray(b"K" * 32), bytearray(b"R" * 32), b"I" * 32,
        b"TXP2", b"RXP2", ReplayWindow(128), time.time(), time.time(),
    )
    session.peer_certificate_serial = "peer-cert"
    session.peer_record_seq = 4
    session.peer_record = dict(peer_record)
    session.local_record = dict(local_record)
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(router_id="router-a")
    daemon.sessions = {session.session_id: session}
    daemon.reason_counters = {}
    daemon.stats = {"drops": 0}
    daemon.v2 = SimpleNamespace(
        _settings=lambda: SimpleNamespace(heartbeat_seconds=30),
        _cached_record=lambda router_id: local_record if router_id == "router-a" else peer_record,
        compare_fresh_record=lambda *_args: None,
    )
    expiry = now + freshness_seconds
    monkeypatch.setattr(ca_client, "_load_verified_cache", lambda _settings: ({}, {"expires_at": expiry}))
    monkeypatch.setattr(ca_client, "is_revoked", lambda serial, _settings: serial == revoked_serial)
    monkeypatch.setattr("nls.daemon.lsdb.remove", lambda _vip: None)
    return daemon, session


def test_live_revocation_teardown_within_heartbeat_plus_one_second(monkeypatch):
    from nls import ca_client
    daemon, session = _trust_test_daemon(monkeypatch, revoked_serial=None)
    daemon.v2._settings = lambda: SimpleNamespace(heartbeat_seconds=1)
    revoked = {"value": False}
    monkeypatch.setattr(
        ca_client, "is_revoked",
        lambda serial, _settings: revoked["value"] and serial == "peer-cert",
    )
    send_key, recv_key = session.send_key, session.recv_key
    assert daemon._refresh_session_trust() >= 0
    revoked["value"] = True
    started = time.monotonic()
    # Model the next one-second trust heartbeat, then run the same trust refresh
    # used by the daemon loop; teardown must complete no later than heartbeat + 1s.
    time.sleep(1.0)
    assert daemon._refresh_session_trust() >= 0
    elapsed = time.monotonic() - started
    assert elapsed <= 2.0, f"revocation teardown exceeded heartbeat + 1s: {elapsed:.3f}s"
    assert daemon.sessions == {}
    assert not any(send_key) and not any(recv_key)
    assert daemon.reason_counters["NLS_PEER_CERT_REVOKED"] == 1


def test_ca_freshness_loss_zeroizes_and_tears_down_all_sessions(monkeypatch):
    daemon, session = _trust_test_daemon(monkeypatch, freshness_seconds=-1)
    send_key, recv_key = session.send_key, session.recv_key
    assert daemon._refresh_session_trust() == -1
    assert daemon.sessions == {}
    assert not any(send_key) and not any(recv_key)
    assert daemon.reason_counters["NLS_CA_FRESHNESS_LOST"] == 1


def test_disabled_peer_router_tears_down_session(monkeypatch):
    daemon, session = _trust_test_daemon(monkeypatch, peer_status="DISABLED")
    assert daemon._refresh_session_trust() >= 0
    assert session.session_id not in daemon.sessions
    assert daemon.reason_counters["NLS_PEER_STATUS_INVALID"] == 1


def test_disabled_local_router_tears_down_all_sessions(monkeypatch):
    daemon, session = _trust_test_daemon(monkeypatch)
    daemon.v2._cached_record = lambda router_id: {
        "router_id": router_id, "status": "DISABLED", "certificate_serial": "local-cert"
    } if router_id == "router-a" else session.peer_record
    assert daemon._refresh_session_trust() == -1
    assert daemon.sessions == {}
    assert daemon.reason_counters["NLS_LOCAL_STATUS_INVALID"] == 1

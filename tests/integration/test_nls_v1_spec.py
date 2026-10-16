"""NLS v1 Prompt 1 six-node lab and strict-xfail attack matrix."""
from __future__ import annotations
import base64, ipaddress, os, shutil, subprocess, time
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
@pytest.mark.xfail(strict=True,run=False,reason="NLE2 session AEAD is not implemented")
def test_tampered_ciphertext_rejected(nls_v1_lab):
    """Requirement: reject ciphertext modified after authenticated encryption."""
    assert False
@pytest.mark.xfail(strict=True,run=False,reason="NLE2 replay matrix is not implemented")
def test_replayed_packet_rejected(nls_v1_lab):
    """Requirement: reject a sequence already accepted in this session."""
    assert False
@pytest.mark.xfail(strict=True,run=False,reason="NLE2 replay matrix is not implemented")
def test_out_of_window_packet_rejected(nls_v1_lab):
    """Requirement: reject packets outside the 128-packet replay window."""
    assert False
@pytest.mark.xfail(strict=True,reason="Current packet construction permits a valid GCM forgery with recipient public key")
def test_replay_window_poisoning_rejected(rsa_pair):
    """Requirement V7: forged high sequence must not advance replay state."""
    private,public=rsa_pair; sid=b"S"*16; identity=b"I"*32
    session=Session("router-s",("2001:db8::2",4789),sid,b"A"*32,b"B"*32,identity,ReplayWindow(128),time.time(),time.time())
    daemon=NLSDaemon.__new__(NLSDaemon); daemon.cfg=SimpleNamespace(max_clock_skew_seconds=120)
    daemon.encryption_private_key=private; daemon.sessions={sid:session}; daemon.tun=_MemoryTun()
    daemon.stats={"drops":0,"data_drops":0,"rx":0}
    forged=seal_ip_packet(public,sid,500000,"fd00::20",identity,_ipv6_packet())
    daemon._handle_data(forged,("2001:db8::2",4789,0,0))
    assert session.recv_replay.highest==-1
@pytest.mark.xfail(strict=True,reason="open_ip_packet validates AEAD but not sender identity")
def test_data_forgery_from_destination_public_key_rejected(rsa_pair):
    """Requirement V8: recipient public key and public session fields cannot forge DATA."""
    private,public=rsa_pair; sid=b"T"*16; identity=b"J"*32
    forged=seal_ip_packet(public,sid,1,"fd00::20",identity,_ipv6_packet())
    with pytest.raises(ValueError): open_ip_packet(private,forged,sid,identity)






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
@pytest.mark.xfail(strict=True,run=False,reason="Rekey thresholds are not implemented")
def test_rekey_at_packet_or_time_threshold(nls_v1_lab):
    """Requirement: make-before-break rekey at 2^32 packets or one hour."""
    assert False


@pytest.mark.xfail(strict=True,run=False,reason="Packet-capture confidentiality proof is not implemented")
def test_pcap_contains_no_inner_packet_or_source_plaintext(nls_v1_lab):
    """Requirement: pcap shows inner IP packet/source only inside ciphertext."""
    assert False

import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls.control_protocol import client_handshake, server_handshake, public_key_bytes, b64


def test_nls_control_protocol_handshake_and_encrypted_records():
    c, s = socket.socketpair()
    # Bound blocking I/O so a handshake regression fails this test rather than
    # leaving the entire package/security suite stalled indefinitely.
    c.settimeout(5)
    s.settimeout(5)
    client_key, server_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    failures = []

    def server():
        try:
            channel, hello, auth = server_handshake(s, server_key, "ca-test")
            assert hello["router_id"] == "edge-test"
            assert auth is None
            message = channel.recv()
            channel.send({"type": "ok", "received": message["type"]})
            channel.close()
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    try:
        channel = client_handshake(c, client_key, "edge-test",
            b64(public_key_bytes(server_key)), "ca-test")
        channel.send({"type": "health"})
        assert channel.recv() == {"type": "ok", "received": "health"}
        channel.close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert not failures
    finally:
        c.close()
        s.close()


def test_nls_control_endpoint_validation():
    from nls.ca_client import parse_endpoint
    assert parse_endpoint("[2001:db8::10]:4790") == ("2001:db8::10", 4790)
    assert parse_endpoint("192.0.2.1:4790") == ("192.0.2.1", 4790)

def test_nls_control_sequence_exhaustion_requires_reconnect():
    import pytest
    from nls.control_protocol import NLSControlError, NLSControlRecordChannel
    sock = socket.socket()
    channel = NLSControlRecordChannel(
        sock, b"a" * 32, b"b" * 32, b"CLNT", b"SRVR",
        send_sequence=2**64 - 1,
    )
    try:
        with pytest.raises(NLSControlError, match="exhausted"):
            channel.send({"type": "heartbeat"})
    finally:
        sock.close()

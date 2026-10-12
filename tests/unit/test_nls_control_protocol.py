import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls.control_protocol import client_handshake, server_handshake, public_key_bytes, b64


def test_nls_control_protocol_handshake_and_encrypted_records():
    c, s = socket.socketpair()
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
    channel = client_handshake(c, client_key, "edge-test",
        b64(public_key_bytes(server_key)), "ca-test")
    channel.send({"type": "health"})
    assert channel.recv() == {"type": "ok", "received": "health"}
    channel.close()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert not failures


def test_nls_control_endpoint_validation():
    from nls.ca_client import parse_endpoint
    assert parse_endpoint("[2001:db8::10]:4790") == ("2001:db8::10", 4790)
    assert parse_endpoint("192.0.2.1:4790") == ("192.0.2.1", 4790)

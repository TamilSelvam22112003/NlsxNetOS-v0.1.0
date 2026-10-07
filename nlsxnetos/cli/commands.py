    print("Identity key:", cfg.identity_key)
    rsa_key = load_rsa_private_key(cfg.encryption_private_key)
    print("RSA encryption public key:", rsa_public_key_b64(rsa_key))
    print("RSA encryption key:", cfg.encryption_private_key)
    signing_key = load_rsa_signing_private_key(cfg.signing_private_key)
    print("RSA signing public key:", rsa_signing_public_key_b64(signing_key))
    print("RSA signing key:", cfg.signing_private_key)


def nls_status():
    from nlsxnetos.nls.config import load

    cfg = load()
    print("NLS enabled:", cfg.enabled)
    print("Protocol version:", cfg.protocol_version)
    print("Listen:", cfg.listen_address, cfg.listen_port)
    print("Bind interface:", cfg.bind_interface or "kernel routing")
    print("Router ID:", cfg.router_id)
    print("Peers:", len(cfg.peers))
    print("TUN:", cfg.tun.enabled, cfg.tun.name)
    for peer in cfg.peers:
        print(f"Peer {peer.id}: {peer.endpoint} CA={peer.router_ca_id}")
        if peer.allowed_prefixes:
            print(f"  Allowed destination prefixes: {', '.join(peer.allowed_prefixes)}")


def nls_self_test():
    import ipaddress
    import tempfile

    from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
    from nlsxnetos.nls.rsa import load_or_create as load_rsa_private_key
    from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
    from nlsxnetos.nls.rsa_signing import (
        load_or_create as load_rsa_signing_private_key,
        public_key_b64 as rsa_signing_public_key_b64,
    )

    original = bytearray(20)
    original[0] = 0x45
    original[2:4] = (20).to_bytes(2, "big")
    original[8] = 64
    original[9] = 6
    original[12:16] = ipaddress.IPv4Address("10.0.0.10").packed
    original[16:20] = ipaddress.IPv4Address("203.0.113.10").packed
    original = bytes(original) + b"nls-rsa-data-plane"
    identity = bytes(range(32))

    with tempfile.TemporaryDirectory(prefix="nlsxnetos-self-test-") as temp_dir:
        rsa_private = load_rsa_private_key(os.path.join(temp_dir, "rsa.pem"))
        rsa_public = rsa_public_key_b64(rsa_private)
        signing_private = load_rsa_signing_private_key(os.path.join(temp_dir, "signing.pem"))
        signing_public = rsa_signing_public_key_b64(signing_private)
        wrapped = seal_ip_packet(
            rsa_public,
            signing_private,
            bytes(16),
            1,
            "203.0.113.10",
            identity,
            original,
        )
        decoded = open_ip_packet(
            rsa_private,
            wrapped,
            bytes(16),
            identity,
            signing_public,
        )
        assert decoded["payload"] == original
        assert ipaddress.IPv4Address("10.0.0.10").packed not in wrapped[:HEADER.size]
        assert b"nls-rsa-data-plane" not in wrapped
    print("NLS RSA data-plane self-test: PASS")

    print("Identity key:", cfg.identity_key)
    rsa_key = load_rsa_private_key(cfg.encryption_private_key)
    print("RSA encryption public key:", rsa_public_key_b64(rsa_key))
    print("RSA encryption key:", cfg.encryption_private_key)
    signing_key = load_rsa_signing_private_key(cfg.signing_private_key)
    print("RSA signing public key:", rsa_signing_public_key_b64(signing_key))
    print("RSA signing key:", cfg.signing_private_key)


def nls_status():
    from nlsxnetos.nls.config import load

    cfg = load()
    print("NLS enabled:", cfg.enabled)
    print("Protocol version:", cfg.protocol_version)
    print("Listen:", cfg.listen_address, cfg.listen_port)
    print("Bind interface:", cfg.bind_interface or "kernel routing")
    print("Router ID:", cfg.router_id)
    print("Peers:", len(cfg.peers))
    print("TUN:", cfg.tun.enabled, cfg.tun.name)
    for peer in cfg.peers:
        print(f"Peer {peer.id}: {peer.endpoint} CA={peer.router_ca_id}")
        if peer.allowed_prefixes:
            print(f"  Allowed destination prefixes: {', '.join(peer.allowed_prefixes)}")


def nls_self_test():
    import ipaddress

    from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
    from nlsxnetos.nls.rsa import load_or_create as load_rsa_private_key
    from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
    from nlsxnetos.nls.rsa_signing import load_or_create as load_rsa_signing_private_key, public_key_b64 as rsa_signing_public_key_b64

    original = bytearray(20)
    original[0] = 0x45
    original[2:4] = (20).to_bytes(2, "big")
    original[8] = 64
    original[9] = 6
    original[12:16] = ipaddress.IPv4Address("10.0.0.10").packed
    original[16:20] = ipaddress.IPv4Address("203.0.113.10").packed
    original = bytes(original) + b"nls-rsa-data-plane"
    identity = bytes(range(32))
    key_base = os.path.join(tempfile.gettempdir(), "nlsxnetos-self-test-" + uuid.uuid4().hex)
    rsa_private = load_rsa_private_key(key_base + "-rsa.pem")
    rsa_public = rsa_public_key_b64(rsa_private)
    signing_private = load_rsa_signing_private_key(key_base + "-signing.pem")
    signing_public = rsa_signing_public_key_b64(signing_private)
    wrapped = seal_ip_packet(
        rsa_public,
        rsa_private,
        signing_private,
        bytes(16),
        1,
        "203.0.113.10",
        identity,
        original,
    )
    decoded = open_ip_packet(
        rsa_private,
        wrapped,
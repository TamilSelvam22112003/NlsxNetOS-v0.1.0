from nlsxnetos.nls.handshake import INIT, RESPONSE, initiator_key, new_init, responder_key


def test_router_ca_certificate_is_bound_to_handshake():
    from nlsxnetos.nls.identity import load_or_create, public_key_b64

    a = load_or_create("/tmp/nlsx-test-a-ed25519.key")
    b = load_or_create("/tmp/nlsx-test-b-ed25519.key")
    a_pub = public_key_b64(a)
    b_pub = public_key_b64(b)

    pending = new_init("R1", a_pub, a, "R2", "CERT-R1", 1234)
    response, _, _ = responder_key(
        pending.init_obj,
        b,
        b_pub,
        "R2",
        "R1",
        a_pub,
        "CERT-R1",
        1234,
    )

    assert response["certificate"] == "CERT-R1"
    initiator_key(pending, response, b_pub, "CERT-R2", 1234)


def test_router_ca_certificate_mismatch_is_rejected():
    from nlsxnetos.nls.identity import load_or_create, public_key_b64

    a = load_or_create("/tmp/nlsx-test-c-ed25519.key")
    b = load_or_create("/tmp/nlsx-test-d-ed25519.key")
    a_pub = public_key_b64(a)
    b_pub = public_key_b64(b)

    pending = new_init("R1", a_pub, a, "R2", "CERT-R1", 1234)
    response, _, _ = responder_key(
        pending.init_obj, b, b_pub, "R2", "R1", a_pub, "CERT-R1", 1234
    )

    try:
        initiator_key(pending, response, b_pub, "WRONG-CERT", 1234)
    except ValueError as exc:
        assert "certificate mismatch" in str(exc)
    else:
        raise AssertionError("certificate mismatch was accepted")

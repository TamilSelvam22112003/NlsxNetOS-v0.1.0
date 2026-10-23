import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls.identity import public_key_b64
from nls.handshake import new_init, responder_key, initiator_key

def test_mutual_handshake_derives_directional_keys_and_trust_binding():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    bpub=public_key_b64(b)
    endpoint="[2001:db8::2]:4789"
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,endpoint,"rsa-a")
    response,b_send,b_recv=responder_key(
        pending.init_obj,b,bpub,"router-b","router-b",apub,10,endpoint,"rsa-a",
        local_router_ca_id=20,local_endpoint="[2001:db8::3]:4789",local_encryption_public_key="rsa-b",
    )
    a_send,a_recv=initiator_key(
        pending,response,bpub,expected_router_ca_id=20,
        expected_endpoint="[2001:db8::3]:4789",expected_encryption_public_key="rsa-b",
    )
    assert a_send==b_recv and a_recv==b_send and a_send!=a_recv
    assert pending.init_obj["vip"] == response["vip"]
    assert response["original_ip"] == "2001:db8:10::1"

def test_wrong_identity_is_rejected():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    c=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,"[2001:db8::2]:4789","rsa-a")
    with pytest.raises(ValueError):
        responder_key(
            pending.init_obj,b,public_key_b64(b),"router-b","router-a",public_key_b64(c),10,"[2001:db8::2]:4789"
        )

def test_wrong_router_ca_binding_is_rejected():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,"[2001:db8::2]:4789","rsa-a")
    with pytest.raises(ValueError):
        responder_key(
            pending.init_obj,b,public_key_b64(b),"router-b","router-b",apub,11,"[2001:db8::2]:4789"
        )


def test_destination_router_ca_record_mismatch_is_rejected():
    a = Ed25519PrivateKey.generate()
    b = Ed25519PrivateKey.generate()
    apub = public_key_b64(a)
    bpub = public_key_b64(b)
    pending = new_init(
        "router-a", apub, a, "router-b", "2001:db8:10::1", 10, apub,
        "[2001:db8::2]:4789", "rsa-a",
    )
    response, _, _ = responder_key(
        pending.init_obj, b, bpub, "router-b", "router-b", apub, 10,
        "[2001:db8::2]:4789", "rsa-a", local_router_ca_id=20,
        local_endpoint="[2001:db8::3]:4789", local_encryption_public_key="rsa-b",
    )
    with pytest.raises(ValueError, match="destination Router-CA identity record mismatch"):
        initiator_key(
            pending, response, bpub, expected_router_ca_id=20,
            expected_endpoint="[2001:db8::3]:4789", expected_encryption_public_key="wrong-rsa",
        )

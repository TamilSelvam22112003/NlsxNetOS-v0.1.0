import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls.identity import public_key_b64
from nls.handshake import new_init, responder_key, initiator_key, TEMP_VIP_NETWORK, INIT, sign

def test_mutual_handshake_derives_directional_keys_and_trust_binding():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    bpub=public_key_b64(b)
    endpoint="[2001:db8::2]:4789"
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,endpoint)
    response,b_send,b_recv=responder_key(
        pending.init_obj,b,bpub,"router-b","router-b",apub,10,endpoint
    )
    a_send,a_recv=initiator_key(pending,response,bpub)
    assert a_send==b_recv and a_recv==b_send and a_send!=a_recv
    assert pending.init_obj["vip"] == response["vip"]
    assert response["original_ip"] == "2001:db8:10::1"

def test_wrong_identity_is_rejected():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    c=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,"[2001:db8::2]:4789")
    with pytest.raises(ValueError):
        responder_key(
            pending.init_obj,b,public_key_b64(b),"router-b","router-a",public_key_b64(c),10,"[2001:db8::2]:4789"
        )

def test_wrong_router_ca_binding_is_rejected():
    a=Ed25519PrivateKey.generate()
    b=Ed25519PrivateKey.generate()
    apub=public_key_b64(a)
    pending=new_init("router-a",apub,a,"router-b","2001:db8:10::1",10,apub,"[2001:db8::2]:4789")
    with pytest.raises(ValueError):
        responder_key(
            pending.init_obj,b,public_key_b64(b),"router-b","router-b",apub,11,"[2001:db8::2]:4789"
        )


def test_temporary_vip_is_within_reserved_prefix_and_has_large_random_space():
    a = Ed25519PrivateKey.generate()
    apub = public_key_b64(a)
    first = new_init("router-a", apub, a, "router-b", "2001:db8::1", 10, apub, "[2001:db8::2]:4789")
    second = new_init("router-a", apub, a, "router-b", "2001:db8::1", 10, apub, "[2001:db8::2]:4789")
    import ipaddress
    first_vip = ipaddress.IPv6Address(first.init_obj["vip"])
    second_vip = ipaddress.IPv6Address(second.init_obj["vip"])
    assert first_vip in TEMP_VIP_NETWORK
    assert second_vip in TEMP_VIP_NETWORK
    assert first_vip != second_vip


def test_modified_vip_in_signed_handshake_is_rejected():
    a = Ed25519PrivateKey.generate()
    b = Ed25519PrivateKey.generate()
    apub = public_key_b64(a)
    bpub = public_key_b64(b)
    endpoint = "[2001:db8::2]:4789"
    pending = new_init("router-a", apub, a, "router-b", "2001:db8:10::1", 10, apub, endpoint)
    pending.init_obj["vip"] = "fd42:100::1"
    with pytest.raises(ValueError, match="authentication"):
        responder_key(pending.init_obj, b, bpub, "router-b", "router-b", apub, 10, endpoint)


def test_signed_vip_outside_reserved_prefix_is_rejected():
    a = Ed25519PrivateKey.generate()
    b = Ed25519PrivateKey.generate()
    apub = public_key_b64(a)
    bpub = public_key_b64(b)
    endpoint = "[2001:db8::2]:4789"
    pending = new_init("router-a", apub, a, "router-b", "2001:db8:10::1", 10, apub, endpoint)
    modified = dict(pending.init_obj)
    modified["vip"] = "fd42:100::1"
    modified = sign(modified, INIT, a)
    with pytest.raises(ValueError, match="reserved temporary-identity prefix"):
        responder_key(modified, b, bpub, "router-b", "router-b", apub, 10, endpoint)

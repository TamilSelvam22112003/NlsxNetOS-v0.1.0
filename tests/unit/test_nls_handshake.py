import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nlsxnetos.nls.identity import public_key_b64
from nlsxnetos.nls.handshake import new_init, responder_key, initiator_key

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

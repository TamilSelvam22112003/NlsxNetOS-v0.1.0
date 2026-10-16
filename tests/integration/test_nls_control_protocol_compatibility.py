"""Cross-repository compatibility tests for duplicated NLS Control v1 modules."""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import nls.control_protocol as router_control
import nls_nexos_core.control_protocol as ca_control

def test_shared_wire_constants_match():
    """Both copies expose identical control framing and protocol constants."""
    for name in ("MAGIC","VERSION","CLIENT_HELLO","SERVER_HELLO","CLIENT_FINISHED","SERVER_FINISHED","DATA","HEADER_SIZE","MAX_FRAME","MAX_CLOCK_SKEW_SECONDS","KDF_INFO"):
        assert getattr(router_control,name)==getattr(ca_control,name)

def test_canonical_encoding_and_signature_preimage_match():
    """Canonical payload and signature bytes must be identical."""
    obj={"router_id":"router-test","nonce":"abc","nested":{"b":2,"a":1}}
    assert router_control.canonical(obj)==ca_control.canonical(obj)
    assert router_control.signing_bytes(router_control.CLIENT_HELLO,obj)==ca_control.signing_bytes(ca_control.CLIENT_HELLO,obj)

def test_signed_objects_verify_cross_copy():
    """An object signed by either copy verifies in the other."""
    key=Ed25519PrivateKey.generate()
    obj={"identity_public_key":base64.b64encode(router_control.public_key_bytes(key)).decode("ascii"),"nonce":"compat"}
    signed_router=router_control.sign_object(obj,router_control.CLIENT_HELLO,key)
    signed_ca=ca_control.sign_object(obj,ca_control.CLIENT_HELLO,key)
    assert signed_router==signed_ca
    assert ca_control.verify_object(signed_router,ca_control.CLIENT_HELLO)==router_control.verify_object(signed_ca,router_control.CLIENT_HELLO)

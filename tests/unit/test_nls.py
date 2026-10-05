from nlsxnetos.nls.crypto import generate_keypair,derive_key
from nlsxnetos.nls.protocol import NLSProtocol
def test_nls_round_trip_and_replay():
    ap,au=generate_keypair(); bp,bu=generate_keypair(); a,b=derive_key(ap,bu),derive_key(bp,au)
    p=NLSProtocol(a).seal(1,b"hello"); r=NLSProtocol(b); assert r.open(p)==b"hello"
    try: r.open(p)
    except ValueError as e: assert "replay" in str(e)
    else: raise AssertionError("replay accepted")
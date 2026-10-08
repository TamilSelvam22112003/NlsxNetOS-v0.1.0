import pytest
from nls.protocol import NLSProtocol
def test_aead_round_trip_and_replay_rejection():
 key=bytes(range(32)); sid=bytes.fromhex("00112233445566778899aabbccddeeff")
 sender=NLSProtocol(key,session_id=sid); receiver=NLSProtocol(key,session_id=sid); packet=sender.seal(1,b"ipv6 payload")
 assert receiver.open(packet)==b"ipv6 payload"
 with pytest.raises(ValueError,match="replay"): receiver.open(packet)
def test_session_binding_rejects_wrong_session():
 key=bytes(range(32)); a=NLSProtocol(key,session_id=bytes(16)); b=NLSProtocol(key,session_id=b"1"*16); packet=a.seal(1,b"x")
 with pytest.raises(ValueError): b.open(packet)

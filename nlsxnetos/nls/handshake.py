import hashlib,json,secrets,time
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .identity import b64,unb64,decode_public_key

MAGIC=b"NLSH"; VERSION=1; INIT=1; RESPONSE=2; MAX_HANDSHAKE=8192; INFO=b"NlsxNetOS-NLS-v1-session"
MAX_CLOCK_SKEW=120

def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(",",":")).encode()

def encode_message(kind,obj):
 body=canonical(obj)
 if len(body)>MAX_HANDSHAKE: raise ValueError("NLS handshake message too large")
 return MAGIC+bytes([VERSION,kind])+len(body).to_bytes(2,"big")+body

def decode_message(packet):
 if len(packet)<8 or packet[:4]!=MAGIC or packet[4]!=VERSION: raise ValueError("invalid NLS handshake")
 length=int.from_bytes(packet[6:8],"big")
 if length>MAX_HANDSHAKE or len(packet)!=8+length: raise ValueError("invalid NLS handshake length")
 return packet[5],json.loads(packet[8:].decode())

def _signing_bytes(kind,obj):
 unsigned=dict(obj); unsigned.pop("signature",None); return b"NLS1-HS1|"+bytes([kind])+b"|"+canonical(unsigned)

def sign(obj,kind,private_key):
 out=dict(obj); out["signature"]=b64(private_key.sign(_signing_bytes(kind,out))); return out

def verify(obj,kind,expected_public_key):
 try:
  if obj.get("identity_public_key")!=expected_public_key: raise ValueError("peer identity public-key mismatch")
  decode_public_key(expected_public_key).verify(unb64(str(obj["signature"])),_signing_bytes(kind,obj))
 except (KeyError,ValueError,InvalidSignature,TypeError) as exc: raise ValueError("NLS peer authentication failed") from exc

def _timestamp_ok(value):
 try:
  return abs(int(time.time())-int(value))<=MAX_CLOCK_SKEW
 except (TypeError,ValueError) as exc:
  raise ValueError("invalid NLS handshake timestamp") from exc

@dataclass
class PendingHandshake:
 session_id:bytes; private_ephemeral:X25519PrivateKey; initiator_public:str; peer_id:str; created_at:int; init_obj:dict

def new_init(router_id,identity_public,private_key,peer_id,original_ip,router_ca_id,router_ca_public_key,endpoint):
 eph=X25519PrivateKey.generate(); sid=secrets.token_bytes(16)
 vip="fd00:4e4c:53:"+secrets.token_hex(2)+"::"+secrets.token_hex(4)
 certificate={"router_ca_id":router_ca_id,"subject":router_id,"public_key":identity_public,"endpoint":endpoint,"ca_public_key":router_ca_public_key}
 obj={"router_id":router_id,"peer_id":peer_id,"identity_public_key":identity_public,"ephemeral_public_key":b64(eph.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)),"session_id":sid.hex(),"timestamp":int(time.time()),"nonce":b64(secrets.token_bytes(16)),"protocol_version":1,"vip":vip,"original_ip":original_ip,"certificate":certificate}
 return PendingHandshake(sid,eph,identity_public,peer_id,int(time.time()),sign(obj,INIT,private_key))

def derive_session(shared,sid,initiator_public,responder_public):
 salt=hashlib.sha256(b"NLS1-TRANSCRIPT|"+sid+initiator_public+responder_public).digest()
 material=HKDF(algorithm=hashes.SHA256(),length=64,salt=salt,info=INFO).derive(shared)
 return material[:32],material[32:]

def responder_key(init_obj,private_key,identity_public,router_id,expected_peer_id,expected_public_key,expected_router_ca_id=None,expected_endpoint=None):
 verify(init_obj,INIT,expected_public_key)
 if expected_peer_id not in (None,"*") and init_obj.get("peer_id") != expected_peer_id: raise ValueError("peer-id mismatch")
 if int(init_obj.get("protocol_version",0)) != 1: raise ValueError("unsupported NLS protocol version")
 _timestamp_ok(init_obj.get("timestamp"))
 cert=init_obj.get("certificate")
 if not isinstance(cert,dict) or cert.get("router_ca_id") != expected_router_ca_id or cert.get("subject") != init_obj.get("router_id") or cert.get("public_key") != expected_public_key or cert.get("endpoint") != expected_endpoint:
  raise ValueError("Router-CA certificate binding mismatch")
 try:
  import ipaddress
  vip=ipaddress.ip_address(init_obj.get("vip",""))
  if vip.version != 6 or not vip.is_private:
   raise ValueError
 except ValueError as exc:
  raise ValueError("invalid NLS temporary vIP") from exc
 original_ip=str(init_obj.get("original_ip",""))
 try: ipaddress.ip_address(original_ip)
 except Exception as exc: raise ValueError("invalid original IP") from exc
 sid=bytes.fromhex(init_obj["session_id"])
 if len(sid)!=16: raise ValueError("invalid NLS session id")
 eph_peer=X25519PublicKey.from_public_bytes(unb64(init_obj["ephemeral_public_key"])); eph=X25519PrivateKey.generate(); shared=eph.exchange(eph_peer)
 if not any(shared): raise ValueError("invalid X25519 shared secret")
 initiator_to_responder,responder_to_initiator=derive_session(shared,sid,unb64(expected_public_key),unb64(identity_public))
 obj={"router_id":router_id,"peer_id":init_obj["router_id"],"identity_public_key":identity_public,"ephemeral_public_key":b64(eph.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)),"session_id":init_obj["session_id"],"timestamp":int(time.time()),"protocol_version":1,"vip":init_obj["vip"],"original_ip":original_ip,"init_digest":hashlib.sha256(canonical(init_obj)).hexdigest()}
 return sign(obj,RESPONSE,private_key),responder_to_initiator,initiator_to_responder

def initiator_key(pending,response,expected_public_key):
 verify(response,RESPONSE,expected_public_key)
 if response.get("session_id")!=pending.session_id.hex(): raise ValueError("NLS session binding mismatch")
 if response.get("protocol_version") != 1: raise ValueError("unsupported NLS protocol version")
 _timestamp_ok(response.get("timestamp"))
 if response.get("vip") != pending.init_obj.get("vip"): raise ValueError("NLS temporary vIP mismatch")
 if response.get("original_ip") != pending.init_obj.get("original_ip"): raise ValueError("NLS original IP mismatch")
 if response.get("init_digest")!=hashlib.sha256(canonical(pending.init_obj)).hexdigest(): raise ValueError("NLS handshake transcript mismatch")
 shared=pending.private_ephemeral.exchange(X25519PublicKey.from_public_bytes(unb64(response["ephemeral_public_key"])))
 if not any(shared): raise ValueError("invalid X25519 shared secret")
 return derive_session(shared,pending.session_id,unb64(pending.initiator_public),unb64(expected_public_key))

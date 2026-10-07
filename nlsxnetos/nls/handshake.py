import hashlib,json,secrets,time
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .identity import b64,unb64,decode_public_key
from . import vip

MAGIC=b"NLSH"; VERSION=1; INIT=1; RESPONSE=2; CONFIRM=3; MAX_HANDSHAKE=8192; INFO=b"NlsxNetOS-NLS-v1-session"
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
 session_id:bytes
 private_ephemeral:X25519PrivateKey
 initiator_public:str
 peer_id:str
 created_at:int
 init_obj:dict
 vip_token:str|None=None
 vip_address:str|None=None
 original_ip:str|None=None

def new_init(router_id,identity_public,private_key,peer_id,certificate=None,ca_timestamp=None,
             destination_encryption_public_key=None,original_ip=None):
 eph=X25519PrivateKey.generate(); sid=secrets.token_bytes(16)
 timestamp=int(time.time()); nonce=b64(secrets.token_bytes(16))
 obj={"router_id":router_id,"peer_id":peer_id,"identity_public_key":identity_public,
      "ephemeral_public_key":b64(eph.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)),
      "session_id":sid.hex(),"timestamp":timestamp,"nonce":nonce,"protocol_version":1}
 token,address=vip.generate_vip(router_id,peer_id,nonce)
 obj["vip_token"]=token; obj["vip_address"]=address
 if destination_encryption_public_key:
  obj["vip_identity_envelope"]=vip.encrypt(destination_encryption_public_key,{"vip_token":token,"vip_address":address,"public_key":identity_public,"timestamp":timestamp})
 if certificate or ca_timestamp is not None:
  obj.update({"certificate":certificate,"ca_timestamp":ca_timestamp})
 return PendingHandshake(sid,eph,identity_public,peer_id,int(time.time()),sign(obj,INIT,private_key),
                         token,address,original_ip)

def derive_session(shared,sid,initiator_public,responder_public):
 salt=hashlib.sha256(b"NLS1-TRANSCRIPT|"+sid+initiator_public+responder_public).digest()
 material=HKDF(algorithm=hashes.SHA256(),length=64,salt=salt,info=INFO).derive(shared)
 return material[:32],material[32:]

def responder_key(init_obj,private_key,identity_public,router_id,expected_peer_id,expected_public_key,certificate=None,ca_timestamp=None,
                  local_encryption_private_key=None,peer_encryption_public_key=None,local_original_ip=None):
 verify(init_obj,INIT,expected_public_key)
 if expected_peer_id not in (None,"*") and init_obj.get("router_id") != expected_peer_id: raise ValueError("peer-id mismatch")
 if int(init_obj.get("protocol_version",0)) != 1: raise ValueError("unsupported NLS protocol version")
 _timestamp_ok(init_obj.get("timestamp"))
 if certificate is not None and init_obj.get("certificate") != certificate: raise ValueError("Router-CA certificate mismatch")
 if ca_timestamp is not None and init_obj.get("ca_timestamp") != ca_timestamp: raise ValueError("Router-CA timestamp mismatch")
 if local_encryption_private_key and init_obj.get("vip_identity_envelope"):
  record=vip.decrypt(local_encryption_private_key,init_obj["vip_identity_envelope"])
  if record.get("public_key")!=expected_public_key or record.get("vip_token")!=init_obj.get("vip_token") or record.get("vip_address")!=init_obj.get("vip_address"):
   raise ValueError("vIP Router-CA identity mismatch")
 sid=bytes.fromhex(init_obj["session_id"])
 if len(sid)!=16: raise ValueError("invalid NLS session id")
 eph_peer=X25519PublicKey.from_public_bytes(unb64(init_obj["ephemeral_public_key"])); eph=X25519PrivateKey.generate(); shared=eph.exchange(eph_peer)
 if not any(shared): raise ValueError("invalid X25519 shared secret")
 initiator_to_responder,responder_to_initiator=derive_session(shared,sid,unb64(expected_public_key),unb64(identity_public))
 obj={"router_id":router_id,"peer_id":init_obj["router_id"],"identity_public_key":identity_public,
      "ephemeral_public_key":b64(eph.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)),
      "session_id":init_obj["session_id"],"timestamp":int(time.time()),"protocol_version":1,
      "init_digest":hashlib.sha256(canonical(init_obj)).hexdigest(),"vip_token":init_obj.get("vip_token"),"vip_address":init_obj.get("vip_address")}
 if local_encryption_private_key and peer_encryption_public_key:
  if not local_original_ip: raise ValueError("local original IP is required for vIP trust")
  trust=vip.trust_record(vip_token=init_obj["vip_token"],original_ip=local_original_ip,public_key=identity_public,
                         certificate=certificate,timestamp=obj["timestamp"],trust=True)
  obj["vip_trust_envelope"]=vip.encrypt(peer_encryption_public_key,trust)
 if certificate or ca_timestamp is not None:
  obj.update({"certificate":certificate,"ca_timestamp":ca_timestamp})
 return sign(obj,RESPONSE,private_key),responder_to_initiator,initiator_to_responder

def initiator_key(pending,response,expected_public_key,expected_certificate=None,expected_ca_timestamp=None,
                  local_encryption_private_key=None,expected_original_ip=None):
 verify(response,RESPONSE,expected_public_key)
 if response.get("session_id")!=pending.session_id.hex(): raise ValueError("NLS session binding mismatch")
 if response.get("protocol_version") != 1: raise ValueError("unsupported NLS protocol version")
 _timestamp_ok(response.get("timestamp"))
 if expected_certificate is not None and response.get("certificate") != expected_certificate: raise ValueError("Router-CA certificate mismatch")
 if expected_ca_timestamp is not None and response.get("ca_timestamp") != expected_ca_timestamp: raise ValueError("Router-CA timestamp mismatch")
 if response.get("init_digest")!=hashlib.sha256(canonical(pending.init_obj)).hexdigest(): raise ValueError("NLS handshake transcript mismatch")
 if local_encryption_private_key and response.get("vip_trust_envelope"):
  record=vip.decrypt(local_encryption_private_key,response["vip_trust_envelope"])
  if record.get("vip_token")!=pending.vip_token or record.get("trust") is not True or record.get("public_key")!=expected_public_key:
   raise ValueError("destination vIP trust rejected")
  if expected_original_ip is not None and record.get("original_ip")!=expected_original_ip:
   raise ValueError("destination original IP does not match Router-CA")
 shared=pending.private_ephemeral.exchange(X25519PublicKey.from_public_bytes(unb64(response["ephemeral_public_key"])))
 if not any(shared): raise ValueError("invalid X25519 shared secret")
 return derive_session(shared,pending.session_id,unb64(pending.initiator_public),unb64(expected_public_key))

def build_confirm(pending,response,private_key,source_original_ip,certificate,ca_timestamp,destination_encryption_public_key):
 record=vip.trust_record(vip_token=pending.vip_token,original_ip=source_original_ip,public_key=pending.initiator_public,
                        certificate=certificate,timestamp=int(time.time()),trust=True)
 obj={"router_id":pending.init_obj["router_id"],"peer_id":pending.peer_id,"identity_public_key":pending.initiator_public,
      "session_id":pending.session_id.hex(),"vip_token":pending.vip_token,"vip_address":pending.vip_address,
      "vip_trust_envelope":vip.encrypt(destination_encryption_public_key,record),"timestamp":int(time.time()),
      "protocol_version":1}
 if certificate or ca_timestamp is not None: obj.update({"certificate":certificate,"ca_timestamp":ca_timestamp})
 return sign(obj,CONFIRM,private_key)

def verify_confirm(confirm,expected_public_key,expected_session_id,expected_vip_token,expected_certificate=None,expected_ca_timestamp=None,
                   local_encryption_private_key=None,expected_original_ip=None):
 verify(confirm,CONFIRM,expected_public_key)
 if confirm.get("session_id")!=expected_session_id.hex(): raise ValueError("NLS confirmation session mismatch")
 if confirm.get("vip_token")!=expected_vip_token: raise ValueError("NLS vIP token mismatch")
 _timestamp_ok(confirm.get("timestamp"))
 if expected_certificate is not None and confirm.get("certificate")!=expected_certificate: raise ValueError("Router-CA certificate mismatch")
 if expected_ca_timestamp is not None and confirm.get("ca_timestamp")!=expected_ca_timestamp: raise ValueError("Router-CA timestamp mismatch")
 if not local_encryption_private_key or not confirm.get("vip_trust_envelope"): raise ValueError("NLS vIP confirmation is missing")
 record=vip.decrypt(local_encryption_private_key,confirm["vip_trust_envelope"])
 if record.get("vip_token")!=expected_vip_token or record.get("trust") is not True or record.get("public_key")!=expected_public_key:
  raise ValueError("source vIP trust rejected")
 if expected_original_ip is not None and record.get("original_ip")!=expected_original_ip:
  raise ValueError("source original IP does not match Router-CA")
 return True

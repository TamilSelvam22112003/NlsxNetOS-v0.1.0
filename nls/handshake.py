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
 vip="fd00:4e4c:53:"+secrets.token_hex(2)+"::"+secrets.token_hex(2)
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


# ---- NLS v2 / NLH2 implementation (Prompt 3) --------------------------------
# Legacy v1 helpers above remain only to keep the pre-v2 test fixtures readable
# during this migration commit. The daemon must use the v2 functions below.
import hmac as _hmac
import ipaddress as _ipaddress
import cbor2 as _cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from .seal import seal as _seal, open_seal as _open_seal
from .key_schedule import transcript_hash as _transcript_hash, confirmation_mac as _confirmation_mac

V2_MAGIC = b"NLH2"
V2_VERSION = 1
M1, M2, M3, M4 = 1, 2, 3, 4
V2_HEADER = __import__("struct").Struct("!4sBB16sH")
V2_MAX_DATAGRAM = 20 * 1024 + V2_HEADER.size
V2_MAX_CBOR = 16 * 1024
V2_MAX_STRING = 4096
V2_MAX_ARRAY = 64
V2_MAX_CLOCK_SKEW = 120
V2_LOOKUP_VALIDITY = 30

# Exact schemas: fields not listed here are rejected, including extension keys.
_V2_SCHEMAS = {
    M1: {
        "session_id": bytes, "router_id": str, "ed25519_public_key": bytes,
        "rsa_encryption_public_key": bytes, "nonce_s": bytes, "timestamp": int,
        "vip": str, "padding": bytes, "sig_S": bytes,
    },
    M2: {
        "session_id": bytes, "router_id": str, "certificate": bytes, "RDR": dict,
        "gateway_ips": list, "sa_proposals": list, "dh_pub_D": bytes,
        "nonce_d": bytes, "ike_meta": dict, "H1": bytes, "sig_D": bytes,
    },
    M3: {
        "session_id": bytes, "certificate": bytes, "RDR": dict,
        "dh_pub_S": bytes, "chosen_sa": str, "S.wan_endpoint": str,
        "H2": bytes, "sig_S": bytes,
    },
    M4: {
        "session_id": bytes, "trust": bool, "H3": bytes,
        "confirm": bytes, "sig_D": bytes,
    },
}


def _v2_schema(kind, obj):
    if kind not in _V2_SCHEMAS or not isinstance(obj, dict):
        raise ValueError("NLS_HS_SCHEMA_INVALID")
    schema = _V2_SCHEMAS[kind]
    if set(obj) != set(schema):
        raise ValueError("NLS_HS_SCHEMA_FIELDS")
    for key, expected in schema.items():
        value = obj[key]
        if expected is int:
            valid = type(value) is int
        elif expected is bool:
            valid = type(value) is bool
        else:
            valid = isinstance(value, expected)
        if not valid:
            raise ValueError("NLS_HS_SCHEMA_TYPE")
        if isinstance(value, str) and (not value or len(value.encode("utf-8")) > V2_MAX_STRING):
            raise ValueError("NLS_HS_SCHEMA_STRING_BOUND")
        if isinstance(value, bytes):
            maximum = 16 * 1024 if key in ("certificate", "padding") else 4096
            if len(value) > maximum:
                raise ValueError("NLS_HS_SCHEMA_BYTES_BOUND")
        if isinstance(value, list) and len(value) > V2_MAX_ARRAY:
            raise ValueError("NLS_HS_SCHEMA_ARRAY_BOUND")
        if isinstance(value, dict) and len(value) > 64:
            raise ValueError("NLS_HS_SCHEMA_MAP_BOUND")
    if len(obj["session_id"]) != 16:
        raise ValueError("NLS_HS_SESSION_ID_LENGTH")
    if kind == M1:
        if len(obj["ed25519_public_key"]) != 32 or len(obj["nonce_s"]) != 32:
            raise ValueError("NLS_HS_M1_KEY_OR_NONCE_LENGTH")
        if not obj["rsa_encryption_public_key"] or len(obj["rsa_encryption_public_key"]) > 4096:
            raise ValueError("NLS_HS_M1_RSA_KEY_LENGTH")
        if len(obj["sig_S"]) != 64:
            raise ValueError("NLS_HS_SIGNATURE_LENGTH")
        if type(obj["timestamp"]) is not int or obj["timestamp"] < 0:
            raise ValueError("NLS_HS_TIMESTAMP_INVALID")
        vip = _ipaddress.ip_address(obj["vip"])
        if vip.version != 6 or not vip.is_private:
            raise ValueError("NLS_HS_VIP_INVALID")
    elif kind == M2:
        if len(obj["dh_pub_D"]) != 32 or len(obj["nonce_d"]) != 32 or len(obj["H1"]) != 32 or len(obj["sig_D"]) != 64:
            raise ValueError("NLS_HS_M2_LENGTH")
    elif kind == M3:
        if len(obj["dh_pub_S"]) != 32 or len(obj["H2"]) != 32 or len(obj["sig_S"]) != 64:
            raise ValueError("NLS_HS_M3_LENGTH")
    elif kind == M4:
        if obj["trust"] is not True or len(obj["H3"]) != 32 or len(obj["confirm"]) != 32 or len(obj["sig_D"]) != 64:
            raise ValueError("NLS_HS_M4_LENGTH_OR_TRUST")


def encode_v2_message(kind: int, session_id: bytes, recipient_rsa_public_key, obj: dict) -> bytes:
    """Validate, deterministic-CBOR encode, then SEAL a typed NLH2 datagram."""
    if kind not in _V2_SCHEMAS or not isinstance(session_id, bytes) or len(session_id) != 16:
        raise ValueError("NLS_HS_HEADER_INVALID")
    if obj.get("session_id") != session_id:
        raise ValueError("NLS_HS_SESSION_BINDING")
    _v2_schema(kind, obj)
    plaintext = _cbor2.dumps(obj, canonical=True)
    if len(plaintext) > V2_MAX_CBOR:
        raise ValueError("NLS_HS_CBOR_TOO_LARGE")
    aad = V2_MAGIC + bytes((V2_VERSION, kind)) + session_id
    envelope = _seal(recipient_rsa_public_key, plaintext, aad)
    if len(envelope) > 65535:
        raise ValueError("NLS_HS_ENVELOPE_TOO_LARGE")
    packet = V2_HEADER.pack(V2_MAGIC, V2_VERSION, kind, session_id, len(envelope)) + envelope
    if len(packet) > V2_MAX_DATAGRAM:
        raise ValueError("NLS_HS_DATAGRAM_TOO_LARGE")
    return packet


def decode_v2_envelope(packet: bytes):
    """Strictly parse only the untrusted NLH2 framing; return (kind, sid, envelope, aad)."""
    import struct as _struct
    try:
        if not isinstance(packet, bytes) or len(packet) < V2_HEADER.size + 2 + 384 + 12 + 16 or len(packet) > V2_MAX_DATAGRAM:
            raise ValueError("NLS_HS_DATAGRAM_LENGTH")
        magic, version, kind, sid, length = V2_HEADER.unpack(packet[:V2_HEADER.size])
        if magic != V2_MAGIC or version != V2_VERSION or kind not in _V2_SCHEMAS:
            raise ValueError("NLS_HS_HEADER_INVALID")
        if length != len(packet) - V2_HEADER.size:
            raise ValueError("NLS_HS_ENVELOPE_LENGTH")
        aad = V2_MAGIC + bytes((V2_VERSION, kind)) + sid
        return kind, sid, packet[V2_HEADER.size:], aad
    except (ValueError, TypeError, _struct.error) as exc:
        raise ValueError("NLS_HS_DATAGRAM_INVALID") from exc


def open_v2_message(packet: bytes, recipient_rsa_private_key):
    """Open and validate an NLH2 message; malformed CBOR never escapes as raw parser errors."""
    kind, sid, envelope, aad = decode_v2_envelope(packet)
    try:
        plaintext = _open_seal(recipient_rsa_private_key, envelope, aad)
        if len(plaintext) > V2_MAX_CBOR:
            raise ValueError("NLS_HS_CBOR_TOO_LARGE")
        obj = _cbor2.loads(plaintext)
        if _cbor2.dumps(obj, canonical=True) != plaintext:
            raise ValueError("NLS_HS_CBOR_NON_CANONICAL")
        _v2_schema(kind, obj)
        if obj["session_id"] != sid:
            raise ValueError("NLS_HS_SESSION_BINDING")
        return kind, sid, obj, plaintext
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("NLS_HS_"):
            raise
        raise ValueError("NLS_HS_OPEN_OR_PARSE_FAILED") from exc


def _v2_signing_bytes(kind: int, obj: dict) -> bytes:
    unsigned = dict(obj)
    sig_name = {M1: "sig_S", M2: "sig_D", M3: "sig_S", M4: "sig_D"}[kind]
    unsigned.pop(sig_name, None)
    return b"NLS-HS2-SIGN|" + bytes((kind,)) + _cbor2.dumps(unsigned, canonical=True)


def sign_v2(kind: int, obj: dict, private_key) -> dict:
    if kind not in _V2_SCHEMAS:
        raise ValueError("NLS_HS_TYPE_INVALID")
    sig_name = {M1: "sig_S", M2: "sig_D", M3: "sig_S", M4: "sig_D"}[kind]
    out = dict(obj)
    out.pop(sig_name, None)
    out[sig_name] = private_key.sign(_v2_signing_bytes(kind, out))
    _v2_schema(kind, out)
    return out


def verify_v2_signature(kind: int, obj: dict, public_key: bytes) -> None:
    _v2_schema(kind, obj)
    sig_name = {M1: "sig_S", M2: "sig_D", M3: "sig_S", M4: "sig_D"}[kind]
    try:
        _ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            obj[sig_name], _v2_signing_bytes(kind, obj)
        )
    except Exception as exc:
        raise ValueError("NLS_HS_SIGNATURE_INVALID") from exc


def transcript_h1(m1_plaintext: bytes) -> bytes:
    return _transcript_hash(m1_plaintext)


def transcript_h2(m1_plaintext: bytes, m2_plaintext: bytes) -> bytes:
    return _transcript_hash(m1_plaintext, m2_plaintext)


def transcript_h3(m1_plaintext: bytes, m2_plaintext: bytes, m3_plaintext: bytes) -> bytes:
    return _transcript_hash(m1_plaintext, m2_plaintext, m3_plaintext)


def verify_timestamp(timestamp: int, now: int | None = None, max_skew: int = V2_MAX_CLOCK_SKEW) -> None:
    current = int(time.time()) if now is None else int(now)
    if type(timestamp) is not int or timestamp < 0 or abs(current - timestamp) > max_skew:
        raise ValueError("NLS_HS_TIMESTAMP_INVALID")


def verify_confirmation(k_confirm: bytes, h3: bytes, received: bytes) -> None:
    expected = _confirmation_mac(k_confirm, h3)
    if not _hmac.compare_digest(expected, received):
        raise ValueError("NLS_HS_CONFIRMATION_INVALID")

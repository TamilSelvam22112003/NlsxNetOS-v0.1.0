import secrets,struct,time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .replay import ReplayWindow
MAGIC=b"NLS1"; VERSION=1; HEADER=struct.Struct("!4sB16sQQ12s")
class NLSProtocol:
 def __init__(self,key,replay_window=64,max_clock_skew=120,session_id=b""):
  if len(key)!=32: raise ValueError("NLS key must be 32 bytes")
  if session_id and len(session_id)!=16: raise ValueError("session_id must be 16 bytes")
  self.key=key; self.session_id=session_id or bytes(16); self.replay=ReplayWindow(replay_window); self.max_clock_skew=max_clock_skew
 def seal(self,sequence,plaintext,timestamp=None):
  timestamp=int(time.time()) if timestamp is None else int(timestamp); nonce=secrets.token_bytes(12)
  header=HEADER.pack(MAGIC,VERSION,self.session_id,sequence,timestamp,nonce)
  aad=header[:-12]
  return header+AESGCM(self.key).encrypt(nonce,plaintext,aad)
 def open(self,packet):
  if len(packet)<HEADER.size+16: raise ValueError("NLS packet is too short")
  magic,version,sid,sequence,timestamp,nonce=HEADER.unpack(packet[:HEADER.size])
  if magic!=MAGIC or version!=VERSION or sid!=self.session_id: raise ValueError("invalid NLS session/header")
  if abs(int(time.time())-timestamp)>self.max_clock_skew: raise ValueError("NLS timestamp outside allowed clock skew")
  if not self.replay.can_accept(sequence): raise ValueError("NLS replay detected")
  plaintext=AESGCM(self.key).decrypt(nonce,packet[HEADER.size:],packet[:HEADER.size-12])
  if not self.replay.mark(sequence): raise ValueError("NLS replay detected")
  return plaintext

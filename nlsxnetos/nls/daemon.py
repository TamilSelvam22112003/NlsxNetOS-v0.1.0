import logging,select,socket,time
from dataclasses import dataclass
from .config import load,endpoint
from .handshake import INIT,RESPONSE,decode_message,encode_message,new_init,responder_key,initiator_key
from .identity import load_or_create,public_key_b64
from .protocol import NLSProtocol,HEADER
from .tun import TunDevice
from nlsxnetos.router_ca import store as ca_store
LOG=logging.getLogger("nlsxnetos.nls")
MAX_DATAGRAM=65535
@dataclass
class Session:
 peer_id:str; endpoint:tuple; session_id:bytes; send_key:bytes; recv_protocol:NLSProtocol; last_seen:float; last_tx:float; tx_sequence:int=0
class NLSDaemon:
 def __init__(self,cfg):
  self.cfg=cfg; self.identity=load_or_create(cfg.identity_key); self.identity_public=public_key_b64(self.identity)
  self.sock=None; self.tun=None; self.peers={p.id:p for p in cfg.peers}; self.sessions={}; self.pending={}; self.blocked={}
  self.stats={"handshakes":0,"established":0,"rx":0,"tx":0,"drops":0}
 def _blocked(self,peer_id):
  until=self.blocked.get(peer_id,0)
  if until and until<=time.time(): self.blocked.pop(peer_id,None); return False
  return until>time.time()
 def _block(self,peer_id,reason):
  self.blocked[peer_id]=time.time()+self.cfg.peer_block_seconds
  LOG.warning("NLS peer %s temporarily blocked for %ss: %s",peer_id,self.cfg.peer_block_seconds,reason)
 def _peer_trusted(self,peer):
  if self._blocked(peer.id): return False
  if peer.router_ca_id is None: return True
  entry=next((e for e in ca_store.load() if e.id==peer.router_ca_id),None)
  ok=bool(entry and entry.public_key and entry.public_key==peer.public_key)
  if not ok: LOG.warning("peer %s rejected: Router-CA identity mismatch",peer.id)
  return ok
 def _bind(self):
  family=socket.AF_INET6 if ":" in self.cfg.listen_address else socket.AF_INET
  self.sock=socket.socket(family,socket.SOCK_DGRAM); self.sock.setblocking(False); self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  self.sock.bind((self.cfg.listen_address,self.cfg.listen_port)); LOG.info("NLS UDP listening on %s:%d",self.cfg.listen_address,self.cfg.listen_port)
 def _send_init(self,peer):
  if self._blocked(peer.id) or not self._peer_trusted(peer): return
  pending=new_init(self.cfg.router_id,self.identity_public,self.identity,peer.id); self.pending[pending.session_id]=(pending,peer)
  host,port=endpoint(peer.endpoint); self.sock.sendto(encode_message(INIT,pending.init_obj),(host,port)); self.stats["handshakes"]+=1
 def _peer_for_obj(self,obj,addr):
  for peer in self.peers.values():
   if peer.public_key!=obj.get("identity_public_key"): continue
   host,port=endpoint(peer.endpoint)
   if addr[0]==host and addr[1]==port: return peer
  return None
 def _handle_init(self,packet,addr):
  try:
   kind,obj=decode_message(packet)
   if kind!=INIT: return
   peer=self._peer_for_obj(obj,addr)
   if peer is None: raise ValueError("unknown or untrusted peer")
   if self._blocked(peer.id): return
   if not self._peer_trusted(peer):
    self._block(peer.id,"Router-CA trust validation failed")
    raise ValueError("untrusted peer")
   response,send_key,recv_key=responder_key(obj,self.identity,self.identity_public,self.cfg.router_id,self.cfg.router_id,peer.public_key)
   sid=bytes.fromhex(obj["session_id"])
   self.sessions[sid]=Session(peer.id,addr,sid,send_key,NLSProtocol(recv_key,self.cfg.replay_window,self.cfg.max_clock_skew_seconds,sid),time.time(),time.time())
   self.sock.sendto(encode_message(RESPONSE,response),addr); self.stats["established"]+=1; LOG.info("NLS session established with %s",peer.id)
  except Exception as exc:
   self.stats["drops"]+=1
   peer=self._peer_for_obj(locals().get("obj",{}),addr) if "obj" in locals() else None
   if peer is not None: self._block(peer.id,str(exc))
   LOG.warning("NLS INIT rejected from %s: %s",addr,exc)
 def _handle_response(self,packet):
  try:
   kind,obj=decode_message(packet)
   if kind!=RESPONSE: return
   sid=bytes.fromhex(obj["session_id"]); pending=self.pending.get(sid)
   if pending is None: return
   handshake,peer=pending
   if self._blocked(peer.id): return
   send_key,recv_key=initiator_key(handshake,obj,peer.public_key); host,port=endpoint(peer.endpoint)
   self.sessions[sid]=Session(peer.id,(host,port),sid,send_key,NLSProtocol(recv_key,self.cfg.replay_window,self.cfg.max_clock_skew_seconds,sid),time.time(),time.time())
   del self.pending[sid]; self.stats["established"]+=1; LOG.info("NLS session established with %s",peer.id)
  except Exception as exc:
   self.stats["drops"]+=1
   if "pending" in locals(): self._block(pending[1].id,str(exc))
   LOG.warning("NLS response rejected: %s",exc)
 def _handle_data(self,packet,addr):
  try:
   if len(packet)<HEADER.size+16: raise ValueError("NLS DATA packet too short")
   sid=HEADER.unpack(packet[:HEADER.size])[2]; session=self.sessions.get(sid)
   if session is None or session.endpoint[0]!=addr[0] or session.endpoint[1]!=addr[1]: raise ValueError("unknown NLS session")
   plaintext=session.recv_protocol.open(packet)
   if self.tun is not None: self.tun.write(plaintext)
   self.stats["rx"]+=1; session.last_seen=time.time()
  except Exception as exc:
   self.stats["drops"]+=1; LOG.warning("NLS DATA dropped from %s: %s",addr,exc)
 def _send_payload(self,payload):
  sessions=list(self.sessions.values())
  if not sessions: return False
  session=max(sessions,key=lambda s:s.last_seen); packet=NLSProtocol(session.send_key,self.cfg.replay_window,self.cfg.max_clock_skew_seconds,session.session_id).seal(session.tx_sequence,payload)
  session.tx_sequence+=1; self.sock.sendto(packet,session.endpoint); session.last_tx=time.time(); self.stats["tx"]+=1; return True
 def run(self):
  if not self.cfg.enabled: LOG.warning("NLS is disabled in configuration; exiting"); return
  self._bind()
  if self.cfg.tun.enabled: self.tun=TunDevice(self.cfg.tun.name).open(); LOG.info("NLS TUN device ready: %s",self.tun.name)
  last_attempt=0.0
  while True:
   now=time.time()
   for sid,s in list(self.sessions.items()):
    if now-s.last_seen>self.cfg.session_timeout_seconds: del self.sessions[sid]
   if self.peers and now-last_attempt>=5:
    for peer in self.peers.values():
     if not any(s.peer_id==peer.id for s in self.sessions.values()): self._send_init(peer)
    last_attempt=now
   ready,_,_=select.select([self.sock]+([self.tun] if self.tun else []),[],[],1.0)
   for item in ready:
    if item is self.sock:
     packet,addr=self.sock.recvfrom(MAX_DATAGRAM)
     if packet.startswith(b"NLSH"):
      kind,_=decode_message(packet)
      if kind==INIT: self._handle_init(packet,addr)
      elif kind==RESPONSE: self._handle_response(packet)
     elif packet.startswith(b"NLS1"): self._handle_data(packet,addr)
    else:
     try: payload=self.tun.read()
     except BlockingIOError: continue
     if payload: self._send_payload(payload)
def run(): NLSDaemon(load()).run()

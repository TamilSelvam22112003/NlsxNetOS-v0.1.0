import argparse,json,shutil
from nlsxnetos import __version__
from nlsxnetos.core.config import ensure_layout
from nlsxnetos.core.platform import supported,ubuntu_release
from nlsxnetos.networking.forwarding import forwarding_state
from nlsxnetos.networking.validation import frr_validate,service_state
from nlsxnetos.router_ca import cli as ca

def doctor(as_json=False):
 ok,detail=frr_validate()
 data={"ubuntu":ubuntu_release(),"supported_platform":supported(),"vtysh":shutil.which("vtysh") is not None,"frr":ok,"frr_service":service_state("frr"),"forwarding":forwarding_state()}
 print(json.dumps(data,indent=2) if as_json else "\n".join(f"{k}: {v}" for k,v in data.items()))
 return 0 if data["supported_platform"] and ok else 1

def nls_identity():
 from nlsxnetos.nls.config import load
 from nlsxnetos.nls.identity import load_or_create,public_key_b64
 cfg=load(); key=load_or_create(cfg.identity_key)
 print("Router ID:",cfg.router_id); print("Ed25519 public key:",public_key_b64(key)); print("Identity key:",cfg.identity_key)

def nls_status():
 from nlsxnetos.nls.config import load
 cfg=load()
 print("NLS enabled:",cfg.enabled); print("Protocol version:",cfg.protocol_version); print("Listen:",cfg.listen_address,cfg.listen_port)
 print("Router ID:",cfg.router_id); print("Peers:",len(cfg.peers)); print("TUN:",cfg.tun.enabled,cfg.tun.name)
 for p in cfg.peers: print(f"Peer {p.id}: {p.endpoint} CA={p.router_ca_id}")

def nls_self_test():
 from nlsxnetos.nls.crypto import generate_keypair,derive_key
 from nlsxnetos.nls.protocol import NLSProtocol
 ap,au=generate_keypair(); bp,bu=generate_keypair(); key=derive_key(ap,bu)
 packet=NLSProtocol(key,session_id=bytes(16)).seal(1,b"NlsxNetOS NLS self-test")
 assert NLSProtocol(key,session_id=bytes(16)).open(packet)==b"NlsxNetOS NLS self-test"
 print("NLS crypto/data-plane self-test: PASS")

def main():
 p=argparse.ArgumentParser(prog="nlsxnetos"); p.add_argument("--version",action="version",version=f"nlsxnetos {__version__}")
 s=p.add_subparsers(dest="cmd")
 s.add_parser("init")
 d=s.add_parser("doctor"); d.add_argument("--json",action="store_true")
 s.add_parser("status")
 f=s.add_parser("frr"); f.add_argument("action",choices=["validate"])
 n=s.add_parser("nls"); n.add_argument("action",choices=["self-test","run","identity","status"])
 c=s.add_parser("router-ca"); cs=c.add_subparsers(dest="action",required=True); cs.add_parser("list")
 a=cs.add_parser("add"); a.add_argument("id",type=int); a.add_argument("prefix"); a.add_argument("label"); a.add_argument("--public-key")
 r=cs.add_parser("remove"); r.add_argument("id",type=int); cs.add_parser("validate")
 x=p.parse_args()
 if x.cmd=="init": ensure_layout(); print("NlsxNetOS initialized"); return
 if x.cmd in ("doctor","status"): raise SystemExit(doctor(getattr(x,"json",False)))
 if x.cmd=="frr":
  ok,detail=frr_validate(); print(detail); raise SystemExit(0 if ok else 1)
 if x.cmd=="router-ca":
  if x.action=="list": ca.list_entries()
  elif x.action=="add": ca.add_entry(x.id,x.prefix,x.label,x.public_key)
  elif x.action=="remove": ca.remove_entry(x.id)
  else: ca.validate()
  return
 if x.cmd=="nls":
  if x.action=="run":
   from nlsxnetos.nls.daemon import run; run()
  elif x.action=="identity": nls_identity()
  elif x.action=="status": nls_status()
  else: nls_self_test(); return
 p.print_help()

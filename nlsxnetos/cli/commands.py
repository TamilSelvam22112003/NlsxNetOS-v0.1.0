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
def main():
    p=argparse.ArgumentParser(prog="nlsxnetos"); p.add_argument("--version",action="version",version=f"nlsxnetos {__version__}")
    s=p.add_subparsers(dest="cmd"); s.add_parser("init"); d=s.add_parser("doctor"); d.add_argument("--json",action="store_true"); s.add_parser("status")
    f=s.add_parser("frr"); f.add_argument("action",choices=["validate"]); n=s.add_parser("nls"); n.add_argument("action",choices=["self-test","run"])
    c=s.add_parser("router-ca"); cs=c.add_subparsers(dest="action",required=True); cs.add_parser("list")
    a=cs.add_parser("add"); a.add_argument("id",type=int); a.add_argument("prefix"); a.add_argument("label"); a.add_argument("--public-key")
    r=cs.add_parser("remove"); r.add_argument("id",type=int); cs.add_parser("validate"); x=p.parse_args()
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
        else:
            from nlsxnetos.nls.crypto import generate_keypair,derive_key
            from nlsxnetos.nls.protocol import NLSProtocol
            ap,au=generate_keypair(); bp,bu=generate_keypair(); ak,bk=derive_key(ap,bu),derive_key(bp,au)
            packet=NLSProtocol(ak).seal(1,b"NlsxNetOS NLS self-test"); assert NLSProtocol(bk).open(packet)==b"NlsxNetOS NLS self-test"
            print("NLS self-test: PASS"); return
    p.print_help()

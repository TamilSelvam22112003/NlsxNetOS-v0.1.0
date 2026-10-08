from pathlib import Path
def forwarding_state():
    out={}
    for k,p in {"ipv4":"/proc/sys/net/ipv4/ip_forward","ipv6":"/proc/sys/net/ipv6/conf/all/forwarding"}.items():
        try: out[k]=Path(p).read_text(encoding="utf-8").strip()
        except OSError: out[k]="unavailable"
    return out

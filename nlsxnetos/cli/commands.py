import argparse
import json
import re
import shutil
import shlex
import subprocess
import sys

from nlsxnetos import __version__
from nlsxnetos.core.config import ensure_layout
from nlsxnetos.core.platform import supported, ubuntu_release
from nlsxnetos.networking.forwarding import forwarding_state
from nlsxnetos.networking.validation import frr_validate, service_state
from nlsxnetos.router_ca import cli as ca
from nlsxnetos import router_config


PROMPT = "NlsxNetOS"
_MODES = ("exec", "config", "interface", "router-ca")


def doctor(as_json=False):
    ok, detail = frr_validate()
    data = {
        "ubuntu": ubuntu_release(),
        "supported_platform": supported(),
        "vtysh": shutil.which("vtysh") is not None,
        "frr": ok,
        "frr_service": service_state("frr"),
        "forwarding": forwarding_state(),
    }
    print(json.dumps(data, indent=2) if as_json else "\n".join(f"{k}: {v}" for k, v in data.items()))
    return 0 if data["supported_platform"] and ok else 1


def nls_identity():
    from nlsxnetos.nls.config import load
    from nlsxnetos.nls.identity import load_or_create, public_key_b64

    cfg = load()
    key = load_or_create(cfg.identity_key)
    print("Router ID:", cfg.router_id)
    print("Ed25519 public key:", public_key_b64(key))
    print("Identity key:", cfg.identity_key)


def nls_status():
    from nlsxnetos.nls.config import load

    cfg = load()
    print("NLS enabled:", cfg.enabled)
    print("Protocol version:", cfg.protocol_version)
    print("Listen:", cfg.listen_address, cfg.listen_port)
    print("Router ID:", cfg.router_id)
    print("Peers:", len(cfg.peers))
    print("TUN:", cfg.tun.enabled, cfg.tun.name)
    for peer in cfg.peers:
        print(f"Peer {peer.id}: {peer.endpoint} CA={peer.router_ca_id}")


def nls_self_test():
    from nlsxnetos.nls.crypto import generate_keypair, derive_key
    from nlsxnetos.nls.protocol import NLSProtocol

    ap, au = generate_keypair()
    bp, bu = generate_keypair()
    key = derive_key(ap, bu)
    packet = NLSProtocol(key, session_id=bytes(16)).seal(1, b"NlsxNetOS NLS self-test")
    assert NLSProtocol(key, session_id=bytes(16)).open(packet) == b"NlsxNetOS NLS self-test"
    print("NLS crypto/data-plane self-test: PASS")


def _require_root():
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        raise PermissionError("configuration changes require root; use sudo nlsxnetos")


def _iface_prompt(name):
    return f"{PROMPT}(config-if)# "


def _prompt(mode, interface=None):
    if mode == "exec":
        return f"{PROMPT}# "
    if mode == "config":
        return f"{PROMPT}(config)# "
    if mode == "interface":
        return _iface_prompt(interface)
    return f"{PROMPT}(config-router-ca)# "


def router_status():
    from nlsxnetos.router_runtime import status

    data = status()
    print(json.dumps(data, indent=2))


def router_apply():
    from nlsxnetos.router_runtime import apply

    apply()
    print("NlsxNetOS router runtime applied.")


def _show_interfaces():
    data = router_config.load()["router"]["interfaces"]
    if not data:
        print("No NlsxNetOS interface configuration.")
        return
    for name, cfg in data.items():
        state = "up" if cfg.get("enabled") else "down"
        role = cfg.get("nls_role") or "unset"
        print(f"{name}: {state}, NLS role={role}")
        for addr in cfg.get("addresses", []):
            print(f"  {addr}")


def _show_running_config():
    data = router_config.load()
    print("!")
    print("router")
    if data["router"].get("enabled"):
        print(" router enable")
    for name, cfg in data["router"].get("interfaces", {}).items():
        print(f" interface {name}")
        for addr in cfg.get("addresses", []):
            print(f"  ip address {addr}")
        if cfg.get("nls_role"):
            print(f"  nls role {cfg['nls_role']}")
        print("  " + ("no shutdown" if cfg.get("enabled") else "shutdown"))
        print(" exit")
    print("!")


def _interface_command(tokens, interface, data):
    if not tokens:
        return True, None
    command = tokens[0].lower()
    if command == "exit":
        return True, "config"
    if command == "end":
        return True, "exec"
    if command == "ip" and len(tokens) == 3 and tokens[1].lower() == "address":
        address = tokens[2]
        router_config.set_address(interface, address)
        router_config.record_interface(data, interface, address=address)
        print(f"Added {address} to {interface}")
        return True, None
    if command == "no" and len(tokens) == 3 and tokens[1].lower() == "ip" and tokens[2].lower() == "address":
        raise ValueError("use: no ip address <address>")
    if command == "no" and len(tokens) == 4 and tokens[1].lower() == "ip" and tokens[2].lower() == "address":
        address = tokens[3]
        router_config.remove_address(interface, address)
        entry = data["router"]["interfaces"].get(interface, {})
        entry["addresses"] = [x for x in entry.get("addresses", []) if x != address]
        print(f"Removed {address} from {interface}")
        return True, None
    if command == "nls" and len(tokens) == 3 and tokens[1].lower() == "role":
        role = tokens[2].lower()
        if role not in ("lan", "wan", "none"):
            raise ValueError("NLS role must be lan, wan, or none")
        router_config.record_interface(data, interface, role=None if role == "none" else role)
        if role == "none":
            data["router"]["interfaces"][interface]["nls_role"] = None
        print(f"{interface}: NLS role {role}")
        return True, None
    if command == "no" and len(tokens) == 2 and tokens[1].lower() == "shutdown":
        router_config.set_link(interface, True)
        router_config.record_interface(data, interface, enabled=True)
        print(f"{interface} is up")
        return True, None
    if command == "shutdown":
        router_config.set_link(interface, False)
        router_config.record_interface(data, interface, enabled=False)
        print(f"{interface} is down")
        return True, None
    if command == "show" and len(tokens) == 2 and tokens[1].lower() == "running-config":
        _show_running_config()
        return True, None
    raise ValueError("unknown interface command")


def _router_ca_command(tokens, data):
    if not tokens:
        return True, None
    command = tokens[0].lower()
    if command == "exit":
        return True, "config"
    if command == "end":
        return True, "exec"
    if command == "router-ca" and len(tokens) >= 4:
        identifier = int(tokens[1])
        prefix = tokens[2]
        label = tokens[3]
        public_key = tokens[4] if len(tokens) == 5 else None
        ca.add_entry(identifier, prefix, label, public_key)
        print(f"Router-CA {identifier} configured")
        return True, None
    if command == "no" and len(tokens) == 3 and tokens[1].lower() == "router-ca":
        ca.remove_entry(int(tokens[2]))
        print(f"Router-CA {tokens[2]} removed")
        return True, None
    raise ValueError("use: router-ca <id> <prefix> <label> [public-key]")


def _config_command(tokens, data):
    if not tokens:
        return True, None
    command = tokens[0].lower()
    if command == "exit":
        return True, "exec"
    if command == "end":
        return True, "exec"
    if command == "interface" and len(tokens) == 2:
        router_config.validate_interface(tokens[1])
        router_config.record_interface(data, tokens[1])
        return True, ("interface", tokens[1])
    if command == "router-ca" and len(tokens) == 1:
        return True, "router-ca"
    if command == "router-ca" and len(tokens) >= 4:
        identifier = int(tokens[1])
        ca.add_entry(identifier, tokens[2], tokens[3], tokens[4] if len(tokens) == 5 else None)
        print(f"Router-CA {identifier} configured")
        return True, None
    raise ValueError("unknown configuration command")


def interactive_cli():
    _require_root()
    ensure_layout()
    data = router_config.load()
    mode = "exec"
    interface = None
    print(f"{PROMPT} v{__version__}")
    print("Type 'enable', 'configure terminal', 'show running-config', or 'help'.")
    while True:
        try:
            raw = input(_prompt(mode, interface))
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        raw = raw.strip()
        if not raw:
            continue
        try:
            tokens = shlex.split(raw)
            cmd = tokens[0].lower()
            if cmd == "quit":
                return 0
            if cmd == "help":
                print("enable | configure terminal | router enable | interface <if> | router-ca | end | exit")
                print("write memory | show running-config | show interfaces | show router-ca")
                continue
            if mode == "exec":
                if cmd == "enable":
                    continue
                if cmd in ("configure", "conf") and len(tokens) == 2 and tokens[1].lower() == "terminal":
                    mode = "config"
                    continue
                if cmd == "write" and len(tokens) == 2 and tokens[1].lower() == "memory":
                    router_config.save(data)
                    print("Building configuration...")
                    print("[OK] Configuration saved to /etc/nlsxnetos/router.yaml")
                    continue
                if cmd == "show" and len(tokens) == 2:
                    what = tokens[1].lower()
                    if what == "running-config":
                        _show_running_config()
                    elif what == "interfaces":
                        _show_interfaces()
                    elif what == "router-ca":
                        ca.list_entries()
                    else:
                        raise ValueError("unknown show target")
                    continue
                if cmd == "end":
                    continue
                raise ValueError("unknown command")
            if mode == "config":
                _, next_mode = _config_command(tokens, data)
                if next_mode:
                    if isinstance(next_mode, tuple):
                        mode, interface = next_mode
                    else:
                        mode, interface = next_mode, None
                continue
            if mode == "interface":
                _, next_mode = _interface_command(tokens, interface, data)
                if next_mode:
                    if next_mode == "config":
                        mode, interface = "config", None
                    else:
                        mode, interface = next_mode, None
                continue
            if mode == "router-ca":
                _, next_mode = _router_ca_command(tokens, data)
                if next_mode:
                    mode, interface = next_mode, None
                continue
        except (ValueError, PermissionError, OSError, subprocess.CalledProcessError) as exc:
            print(f"% Error: {exc}")


def main():
    p = argparse.ArgumentParser(prog="nlsxnetos")
    p.add_argument("--version", action="version", version=f"nlsxnetos {__version__}")
    s = p.add_subparsers(dest="cmd")
    s.add_parser("init")
    d = s.add_parser("doctor")
    d.add_argument("--json", action="store_true")
    s.add_parser("status")
    s.add_parser("cli", help="interactive NlsxNetOS configuration CLI")\n    rtr = s.add_parser("router", help="Ubuntu router runtime")\n    rtr.add_argument("action", choices=["enable", "disable", "apply", "status"])
    f = s.add_parser("frr")
    f.add_argument("action", choices=["validate"])
    n = s.add_parser("nls")
    n.add_argument("action", choices=["self-test", "run", "identity", "status"])
    c = s.add_parser("router-ca")
    cs = c.add_subparsers(dest="action", required=True)
    cs.add_parser("list")
    a = cs.add_parser("add")
    a.add_argument("id", type=int)
    a.add_argument("prefix")
    a.add_argument("label")
    a.add_argument("--public-key")
    r = cs.add_parser("remove")
    r.add_argument("id", type=int)
    cs.add_parser("validate")
    import sys\n    if len(sys.argv) >= 5 and sys.argv[1].lower() == "router-ca" and sys.argv[2].isdigit():\n        _require_root()\n        identifier = int(sys.argv[2])\n        prefix = sys.argv[3]\n        label = sys.argv[4]\n        public_key = sys.argv[5] if len(sys.argv) == 6 else None\n        ca.add_entry(identifier, prefix, label, public_key)\n        print(f"Router-CA {identifier} configured")\n        return 0\n    x = p.parse_args()
    if x.cmd is None:
        return interactive_cli()
    if x.cmd == "cli":
        return interactive_cli()
    if x.cmd == "init":
        ensure_layout()
        print("NlsxNetOS initialized")
        return 0
    if x.cmd in ("doctor", "status"):
        raise SystemExit(doctor(getattr(x, "json", False)))
    if x.cmd == "router":\n        if x.action == "enable":\n            _require_root()\n            data = router_config.load()\n            data["router"]["enabled"] = True\n            data["router"]["ipv4_forwarding"] = True\n            data["router"]["ipv6_forwarding"] = True\n            router_config.save(data)\n            from nlsxnetos.router_runtime import apply\n            apply()\n            print("NlsxNetOS router mode enabled.")\n        elif x.action == "disable":\n            _require_root()\n            data = router_config.load()\n            data["router"]["enabled"] = False\n            data["router"]["ipv4_forwarding"] = False\n            data["router"]["ipv6_forwarding"] = False\n            router_config.save(data)\n            from nlsxnetos.router_runtime import apply\n            apply(start_frr=False)\n            print("NlsxNetOS router mode disabled.")\n        elif x.action == "apply":\n            _require_root()\n            router_apply()\n        else:\n            router_status()\n        return 0\n    if x.cmd == "frr":
        ok, detail = frr_validate()
        print(detail)
        raise SystemExit(0 if ok else 1)
    if x.cmd == "router-ca":
        if x.action == "list":
            ca.list_entries()
        elif x.action == "add":
            ca.add_entry(x.id, x.prefix, x.label, x.public_key)
        elif x.action == "remove":
            ca.remove_entry(x.id)
        else:
            ca.validate()
        return 0
    if x.cmd == "nls":
        if x.action == "run":
            from nlsxnetos.nls.daemon import run
            run()
        elif x.action == "identity":
            nls_identity()
        elif x.action == "status":
            nls_status()
        else:
            nls_self_test()
        return 0
    p.print_help()
    return 0

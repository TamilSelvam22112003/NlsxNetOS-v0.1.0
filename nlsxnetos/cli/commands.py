import argparse
import ipaddress
import json
import shutil
import shlex
import subprocess

from nlsxnetos import __version__
from nlsxnetos.core.config import ensure_layout
from nlsxnetos.core.platform import supported, ubuntu_release
from nlsxnetos.networking.forwarding import forwarding_state
from nlsxnetos.networking.validation import frr_validate, service_state
from nlsxnetos.router_ca import cli as ca
from nlsxnetos import router_config
from nlsxnetos import router_runtime

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
    print("Bind interface:", cfg.bind_interface or "kernel routing")
    print("Router ID:", cfg.router_id)
    print("Peers:", len(cfg.peers))
    print("TUN:", cfg.tun.enabled, cfg.tun.name)
    for peer in cfg.peers:
        print(f"Peer {peer.id}: {peer.endpoint} CA={peer.router_ca_id}")
        if peer.allowed_prefixes:
            print(f"  Allowed destination prefixes: {', '.join(peer.allowed_prefixes)}")


def nls_self_test():
    import ipaddress

    from nlsxnetos.nls.crypto import generate_keypair, derive_key
    from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
    from nlsxnetos.nls.protocol import NLSProtocol

    ap, au = generate_keypair()
    bp, bu = generate_keypair()
    key = derive_key(ap, bu)
    packet = NLSProtocol(key, session_id=bytes(16)).seal(1, b"NlsxNetOS NLS self-test")
    assert NLSProtocol(key, session_id=bytes(16)).open(packet) == b"NlsxNetOS NLS self-test"

    original = bytearray(20)
    original[0] = 0x45
    original[2:4] = (20).to_bytes(2, "big")
    original[8] = 64
    original[9] = 6
    original[12:16] = ipaddress.IPv4Address("10.0.0.10").packed
    original[16:20] = ipaddress.IPv4Address("203.0.113.10").packed
    original = bytes(original) + b"nls-data-plane"
    identity = bytes(range(32))
    wrapped = seal_ip_packet(key, bytes(16), 1, "203.0.113.10", identity, original)
    decoded = open_ip_packet(key, wrapped, bytes(16), identity)
    assert decoded["payload"] == original
    assert ipaddress.IPv4Address("10.0.0.10").packed not in wrapped[:HEADER.size]
    print("NLS crypto/data-plane self-test: PASS")


def _require_root():
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        raise PermissionError("configuration changes require root; use sudo nlsxnetos")


def _prompt(mode, interface=None):
    if mode == "exec":
        return f"{PROMPT}# "
    if mode == "config":
        return f"{PROMPT}(config)# "
    if mode == "interface":
        return f"{PROMPT}(config-if:{interface})# "
    return f"{PROMPT}(config-router-ca)# "


def _show_interfaces():
    data = router_config.load()["router"]
    if not data.get("interfaces"):
        print("No NlsxNetOS interface configuration.")
        return
    for logical, cfg in data["interfaces"].items():
        linux_name = cfg.get("linux_name", logical)
        state = "up" if cfg.get("enabled") else "down"
        role = cfg.get("nls_role") or "unset"
        print(f"{logical} ({linux_name}): {state}, NLS role={role}")
        for addr in cfg.get("addresses", []):
            print(f"  {addr}")


def _show_running_config():
    data = router_config.load()
    cfg = data["router"]
    print("!")
    print("version 1")
    print("!")
    for logical, entry in cfg.get("interfaces", {}).items():
        print(f"interface {logical}")
        for addr in entry.get("addresses", []):
            print(f" ip address {addr}")
        if entry.get("nls_role"):
            print(f" nls {entry['nls_role']}")
        print(" no shutdown" if entry.get("enabled") else " shutdown")
        print(" exit")
    print("!")
    print("ipv6 unicast-routing" if cfg.get("ipv6_forwarding") else "no ipv6 unicast-routing")
    print("!")


def _normalize_ip_address(value):
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
        default_prefix = 64 if address.version == 6 else 32
        normalized = f"{address}/{default_prefix}"
        print(f"% Notice: no prefix length supplied; using {normalized}")
        return normalized


def _interface_command(tokens, interface, data):
    if not tokens:
        return True, None
    command = tokens[0].lower()

    if command == "exit":
        return True, "config"
    if command == "end":
        return True, "exec"

    if command == "ip" and len(tokens) == 3 and tokens[1].lower() == "address":
        address = _normalize_ip_address(tokens[2])
        router_config.set_address(interface, address, data)
        router_config.record_interface(data, interface, address=address)
        print(f"Added {address} to {interface}")
        return True, None

    if command == "no" and len(tokens) == 4 and tokens[1].lower() == "ip" and tokens[2].lower() == "address":
        address = _normalize_ip_address(tokens[3])
        router_config.remove_address(interface, address, data)
        entry = data["router"]["interfaces"].get(router_config.normalize_interface_name(interface), {})
        entry["addresses"] = [x for x in entry.get("addresses", []) if x != address]
        print(f"Removed {address} from {interface}")
        return True, None

    if command == "nls" and len(tokens) == 2:
        role = tokens[1].lower()
        if role not in ("lan", "wan", "none"):
            raise ValueError("use: nls lan | nls wan | nls none")
        router_config.record_interface(
            data, interface, role=None if role == "none" else role
        )
        if role == "none":
            data["router"]["interfaces"][router_config.normalize_interface_name(interface)]["nls_role"] = None
        print(f"{interface}: NLS role {role}")
        return True, None

    if command == "nls" and len(tokens) == 3 and tokens[1].lower() == "role":
        return _interface_command(["nls", tokens[2]], interface, data)

    if command == "no" and len(tokens) == 2 and tokens[1].lower() == "shutdown":
        router_config.set_link(interface, True, data)
        router_config.record_interface(data, interface, enabled=True)
        print(f"{interface} is up")
        return True, None

    if command == "shutdown":
        router_config.set_link(interface, False, data)
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

    if command in ("exit", "end"):
        return True, "exec"

    if command == "interface" and len(tokens) == 2:
        logical = router_config.normalize_interface_name(tokens[1])
        router_config.validate_interface(logical, data)
        router_config.record_interface(data, logical)
        return True, ("interface", logical)

    if command == "router-ca" and len(tokens) == 1:
        return True, "router-ca"

    if command == "router-ca" and len(tokens) >= 4:
        identifier = int(tokens[1])
        ca.add_entry(identifier, tokens[2], tokens[3], tokens[4] if len(tokens) == 5 else None)
        print(f"Router-CA {identifier} configured")
        return True, None

    raise ValueError("unknown configuration command")


def _exec_router_ca_command(tokens):
    # Cisco-like NlsxNetOS extension requested by the project:
    # nlsnetos router-ca <id> ip addr <address-or-prefix> [label]
    if len(tokens) < 5 or tokens[0].lower() != "nlsnetos" or tokens[1].lower() != "router-ca":
        raise ValueError("use: nlsnetos router-ca <id> ip addr <address-or-prefix> [label]")
    identifier = int(tokens[2])
    if tokens[3].lower() != "ip" or tokens[4].lower() != "addr":
        raise ValueError("use: nlsnetos router-ca <id> ip addr <address-or-prefix> [label]")
    raw = tokens[5] if len(tokens) >= 6 else ""
    if not raw:
        raise ValueError("Router-CA IP address is required")
    try:
        if "/" in raw:
            prefix = str(ipaddress.ip_network(raw, strict=False))
        else:
            prefix = str(ipaddress.ip_interface(f"{raw}/128").network)
    except ValueError as exc:
        raise ValueError("invalid Router-CA IP address/prefix") from exc
    label = tokens[6] if len(tokens) >= 7 else f"ca-{identifier}"
    ca.add_entry(identifier, prefix, label)
    print(f"Router-CA {identifier} configured: {prefix} ({label})")


def interactive_cli():
    _require_root()
    ensure_layout()
    data = router_config.load()
    mode = "exec"
    interface = None

    print(f"{PROMPT} v{__version__}")
    print("IOS-compatible configuration style; FRR vtysh remains unchanged.")
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

            if cmd in ("quit", "logout"):
                return 0

            if cmd == "help":
                print("enable | enable nlsxnetos | configure terminal | interface g0/0")
                print("ip address <address[/prefix]> | nls lan | nls wan | no shutdown")
                print("write memory | show running-config | show interfaces | show router-ca")
                print("nlsnetos router-ca <id> ip addr <address/prefix> [label]")
                continue

            if mode == "exec":
                if cmd == "enable":
                    # 'enable nlsxnetos' is accepted as an explicit NlsxNetOS
                    # privilege-selection command; NlsxNetOS is already active.
                    if len(tokens) == 1 or (
                        len(tokens) == 2 and tokens[1].lower() == "nlsxnetos"
                    ):
                        continue
                    raise ValueError("use: enable or enable nlsxnetos")

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

                if cmd == "router" and len(tokens) == 2:
                    action = tokens[1].lower()
                    if action == "enable":
                        router_runtime.enable()
                        print("NlsxNetOS router enabled.")
                        continue
                    if action == "disable":
                        router_runtime.disable()
                        print("NlsxNetOS router disabled.")
                        continue

                if cmd == "nlsnetos" and len(tokens) >= 6 and tokens[1].lower() == "router-ca":
                    _exec_router_ca_command(tokens)
                    continue

                if cmd == "reboot" and len(tokens) == 1:
                    print("Restarting system...")
                    subprocess.run(["systemctl", "reboot"], check=False)
                    return 0

                if cmd == "exit":
                    return 0

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
                    mode, interface = ("config", None) if next_mode == "config" else (next_mode, None)
                continue

            if mode == "router-ca":
                _, next_mode = _router_ca_command(tokens, data)
                if next_mode:
                    mode, interface = next_mode, None

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
    s.add_parser("cli", help="interactive NlsxNetOS configuration CLI")
    f = s.add_parser("frr")
    f.add_argument("action", choices=["validate"])
    n = s.add_parser("nls")
    n.add_argument("action", choices=["self-test", "run", "identity", "status"])
    rr = s.add_parser("router")
    rr.add_argument("action", choices=["enable", "disable", "status"])
    c = s.add_parser("router-ca")
    cs = c.add_subparsers(dest="action", required=True)
    cs.add_parser("list")
    a = cs.add_parser("add")
    a.add_argument("id", type=int)
    a.add_argument("prefix")
    a.add_argument("label")
    a.add_argument("endpoint", nargs="?")
    a.add_argument("--public-key")
    r = cs.add_parser("remove")
    r.add_argument("id", type=int)
    cs.add_parser("validate")

    x = p.parse_args()
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
    if x.cmd == "frr":
        ok, detail = frr_validate()
        print(detail)
        raise SystemExit(0 if ok else 1)
    if x.cmd == "router":
        if x.action == "enable":
            router_runtime.enable()
        elif x.action == "disable":
            router_runtime.disable()
        else:
            print(json.dumps(router_runtime.status(), indent=2))
        return 0
    if x.cmd == "router-ca":
        if x.action == "list":
            ca.list_entries()
        elif x.action == "add":
            ca.add_entry(x.id, x.prefix, x.label, x.public_key, x.endpoint)
        else:
            ca.remove_entry(x.id) if x.action == "remove" else ca.validate()
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

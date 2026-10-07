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
from nlsxnetos import router_config
from nlsxnetos import router_runtime
from nlsxnetos.nls import cli as nls_cli


PROMPT = "NlsxNetOS"
_MODES = ("exec", "config", "interface")


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
    from nlsxnetos.nls.rsa import load_or_create as load_rsa_private_key, public_key_b64 as rsa_public_key_b64
    from nlsxnetos.nls.rsa_signing import load_or_create as load_rsa_signing_private_key, public_key_b64 as rsa_signing_public_key_b64

    cfg = load()
    key = load_or_create(cfg.identity_key)
    print("Router ID:", cfg.router_id)
    print("Ed25519 public key:", public_key_b64(key))
    print("Identity key:", cfg.identity_key)
    rsa_key = load_rsa_private_key(cfg.encryption_private_key)
    print("RSA encryption public key:", rsa_public_key_b64(rsa_key))
    print("RSA encryption key:", cfg.encryption_private_key)
    signing_key = load_rsa_signing_private_key(cfg.signing_private_key)
    print("RSA signing public key:", rsa_signing_public_key_b64(signing_key))
    print("RSA signing key:", cfg.signing_private_key)


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

    from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
    from nlsxnetos.nls.rsa import load_or_create as load_rsa_private_key
    from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
    from nlsxnetos.nls.rsa_signing import load_or_create as load_rsa_signing_private_key, public_key_b64 as rsa_signing_public_key_b64

    original = bytearray(20)
    original[0] = 0x45
    original[2:4] = (20).to_bytes(2, "big")
    original[8] = 64
    original[9] = 6
    original[12:16] = ipaddress.IPv4Address("10.0.0.10").packed
    original[16:20] = ipaddress.IPv4Address("203.0.113.10").packed
    original = bytes(original) + b"nls-rsa-data-plane"
    identity = bytes(range(32))
    rsa_private = load_rsa_private_key("/tmp/nlsxnetos-self-test-rsa.pem")
    rsa_public = rsa_public_key_b64(rsa_private)
    signing_private = load_rsa_signing_private_key("/tmp/nlsxnetos-self-test-signing.pem")
    signing_public = rsa_signing_public_key_b64(signing_private)
    wrapped = seal_ip_packet(
        rsa_public,
        rsa_private,
        signing_private,
        bytes(16),
        1,
        "203.0.113.10",
        identity,
        original,
    )
    decoded = open_ip_packet(
        rsa_private,
        wrapped,
        bytes(16),
        identity,
        signing_public,
    )
    assert decoded["payload"] == original
    assert ipaddress.IPv4Address("10.0.0.10").packed not in wrapped[:HEADER.size]
    assert b"nls-rsa-data-plane" not in wrapped
    print("NLS RSA data-plane self-test: PASS")

def _require_root():
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        raise PermissionError("configuration changes require root; use sudo nlsxnetos")


def _iface_prompt(name):
    return f"{PROMPT}(config-if:{name})# "


def _prompt(mode, interface=None):
    if mode == "exec":
        return f"{PROMPT}# "
    if mode == "config":
        return f"{PROMPT}(config)# "
    if mode == "interface":
        return _iface_prompt(interface)
    return f"{PROMPT}(config)# "


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
                print("enable | configure terminal | interface <if> | router enable | router disable | end | exit")
                print("write memory | show running-config | show interfaces | nls status")
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
                    elif what == "nls":
                        nls_cli.status()
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
    rc = s.add_parser("router-ca")
    rc.add_argument("action", choices=["validate", "list"])
    n = s.add_parser("nls")
    n.add_argument("action", choices=["self-test", "run", "identity", "status", "enable", "disable", "erase", "configure"])
    n.add_argument("--router-id")
    n.add_argument("--advertised-endpoint")
    n.add_argument("--ca-server")
    n.add_argument("--ca-file")
    n.add_argument("--bind-interface")
    n.add_argument("--listen-port", type=int)
    n.add_argument("--tun-mtu", type=int)
    rr = s.add_parser("router")
    rr.add_argument("action", choices=["enable", "disable", "status"])
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
        from nlsxnetos.router_ca import cli as router_ca_cli
        if x.action == "validate":
            router_ca_cli.validate()
        else:
            router_ca_cli.list_entries()
        return 0
    if x.cmd == "nls":
        if x.action == "run":
            from nlsxnetos.nls.daemon import run
            run()
        elif x.action == "identity":
            nls_identity()
        elif x.action == "status":
            nls_status()
        elif x.action == "enable":
            _require_root()
            nls_cli.enable()
        elif x.action == "disable":
            _require_root()
            nls_cli.disable()
        elif x.action == "erase":
            _require_root()
            nls_cli.erase()
        elif x.action == "configure":
            _require_root()
            values = {}
            if x.router_id is not None:
                values["router_id"] = x.router_id
            if x.bind_interface is not None:
                values["bind_interface"] = x.bind_interface
            if x.advertised_endpoint is not None:
                values["advertised_endpoint"] = x.advertised_endpoint
            if x.listen_port is not None:
                values["listen_port"] = x.listen_port
            if x.tun_mtu is not None:
                values["tun"] = {"enabled": True, "name": "nls0", "mtu": x.tun_mtu}
            if x.ca_server is not None or x.ca_file is not None:
                current = nls_cli.management.status().get("router_ca", {}) or {}
                if x.ca_server is not None:
                    current["server_url"] = x.ca_server
                if x.ca_file is not None:
                    current["ca_file"] = x.ca_file
                values["router_ca"] = current
            nls_cli.configure(**values)
            print("NLS configuration updated.")
        else:
            nls_self_test()
        return 0
    p.print_help()
    return 0

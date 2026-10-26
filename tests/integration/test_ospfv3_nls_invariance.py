"""Real FRR/OSPFv3 regression for NLS daemon startup/shutdown invariance.

This test validates real OSPFv3 adjacencies, LSDB state and kernel routes.
It covers NLS daemon startup/shutdown only. Handshake, rekey, vIP expiry and
trust-loss lifecycle invariance remain separate required coverage.
Run as root on Linux with FRR, iproute2 and NLS Python dependencies installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.integration

ROUTERS = ("nlsospf1", "nlsospf2", "nlsospf3")
LINKS = (
    ("nlsospf1", "veth12a", "nlsospf2", "veth12b"),
    ("nlsospf2", "veth23b", "nlsospf3", "veth23c"),
)
ROUTER_IDS = {"nlsospf1": "10.0.0.1", "nlsospf2": "10.0.0.2", "nlsospf3": "10.0.0.3"}


def run(*args, ns=None, check=True, timeout=15, env=None):
    command = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    try:
        return subprocess.run(command, check=check, text=True, capture_output=True,
                              timeout=timeout, env=env)
    except subprocess.CalledProcessError as exc:
        print("OSPFV3_TEST_COMMAND_FAILURE " + json.dumps({
            "argv": command, "returncode": exc.returncode,
            "stdout": exc.stdout, "stderr": exc.stderr,
        }, sort_keys=True), flush=True)
        raise


def _vty(ns, *commands):
    args = ["vtysh", "-N", ns]
    for command in commands:
        args.extend(["-c", command])
    return run(*args, ns=ns)


def _add_link(ns_a, if_a, ns_b, if_b):
    host_a, host_b = f"{if_a}h", f"{if_b}h"
    run("ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b)
    run("ip", "link", "set", host_a, "netns", ns_a)
    run("ip", "link", "set", host_b, "netns", ns_b)
    run("ip", "link", "set", host_a, "name", if_a, ns=ns_a)
    run("ip", "link", "set", host_b, "name", if_b, ns=ns_b)
    run("ip", "link", "set", if_a, "up", ns=ns_a)
    run("ip", "link", "set", if_b, "up", ns=ns_b)


def _wait_until(predicate, description, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (subprocess.SubprocessError, OSError):
            pass
        time.sleep(1)
    raise AssertionError(f"Timed out waiting for {description}; last={last!r}")


def _neighbors(ns):
    output = _vty(ns, "show ipv6 ospf6 neighbor").stdout
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].count(".") == 3:
            result[fields[0]] = fields[3]
    return result


def _lsdb(ns):
    output = _vty(ns, "show ipv6 ospf6 database").stdout
    normalized = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Age is dynamic and should not make a stable LSDB look changed.
        line = re.sub(r"(?i)(?:LS )?age:\\s*\\d+", "age:<dynamic>", line)
        if line.lower().startswith(("uptime:", "duration:")):
            continue
        normalized.append(line)
    return tuple(normalized)


def _routes(ns):
    output = run("ip", "-6", "route", "show", "table", "main", ns=ns).stdout
    return tuple(sorted(
        line.strip() for line in output.splitlines()
        if line.strip() and not line.strip().startswith("fe80:")
    ))


def _snapshot(ns):
    return {"neighbors": _neighbors(ns), "lsdb": _lsdb(ns), "routes": _routes(ns)}


def _start_frr(ns):
    config_dir = Path("/etc/frr") / ns
    runtime_dir = Path("/var/run/frr") / ns
    config_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    for daemon in ("zebra", "ospf6d"):
        config = config_dir / f"{daemon}.conf"
        config.write_text(f"hostname {ns}-{daemon}\n", encoding="utf-8")
        config.chmod(0o640)
    zebra = shutil.which("zebra") or "/usr/lib/frr/zebra"
    ospf6d = shutil.which("ospf6d") or "/usr/lib/frr/ospf6d"
    run(zebra, "-d", "-N", ns, "-S", ns=ns, timeout=20)
    run(ospf6d, "-d", "-N", ns, "-S", ns=ns, timeout=20)
    _wait_until(lambda: _vty(ns, "show version").returncode == 0,
                f"FRR VTY for {ns}", timeout=20)


def _stop_frr(ns):
    runtime_dir = Path("/var/run/frr") / ns
    for daemon in ("ospf6d", "zebra"):
        try:
            pid = int((runtime_dir / f"{daemon}.pid").read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
        except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
            pass
    time.sleep(0.5)
    shutil.rmtree(runtime_dir, ignore_errors=True)
    shutil.rmtree(Path("/etc/frr") / ns, ignore_errors=True)


def _configure_ospf6(ns, interfaces):
    commands = ["configure terminal", f"hostname {ns}", "router ospf6",
                f"router-id {ROUTER_IDS[ns]}", "exit"]
    for interface in ("lo", *interfaces):
        commands.extend([f"interface {interface}", "ipv6 ospf6 area 0.0.0.0", "exit"])
    commands.append("end")
    _vty(ns, *commands)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root for namespaces, FRR and TUN")
def test_real_ospfv3_routing_is_invariant_to_nls_startup_and_shutdown(tmp_path):
    for binary in ("ip", "vtysh"):
        assert shutil.which(binary), f"required integration binary missing: {binary}"
    assert shutil.which("zebra") or Path("/usr/lib/frr/zebra").exists(), "FRR zebra is required"
    assert shutil.which("ospf6d") or Path("/usr/lib/frr/ospf6d").exists(), "FRR ospf6d is required"

    created = []
    frr_started = []
    nls_proc = None
    try:
        for ns in ROUTERS:
            run("ip", "netns", "add", ns)
            created.append(ns)
            run("ip", "link", "set", "lo", "up", ns=ns)
            run("sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1", ns=ns)

        for link in LINKS:
            _add_link(*link)

        addresses = (
            ("nlsospf1", "veth12a", "fd00:12::1/64"),
            ("nlsospf2", "veth12b", "fd00:12::2/64"),
            ("nlsospf2", "veth23b", "fd00:23::2/64"),
            ("nlsospf3", "veth23c", "fd00:23::3/64"),
            ("nlsospf1", "lo", "2001:db8:100::1/128"),
            ("nlsospf2", "lo", "2001:db8:200::1/128"),
            ("nlsospf3", "lo", "2001:db8:300::1/128"),
        )
        for ns, interface, address in addresses:
            run("ip", "-6", "addr", "add", address, "dev", interface, ns=ns)

        for ns, interfaces in (
            ("nlsospf1", ("veth12a",)),
            ("nlsospf2", ("veth12b", "veth23b")),
            ("nlsospf3", ("veth23c",)),
        ):
            _start_frr(ns)
            frr_started.append(ns)
            _configure_ospf6(ns, interfaces)

        expected_neighbors = {
            "nlsospf1": {"10.0.0.2"},
            "nlsospf2": {"10.0.0.1", "10.0.0.3"},
            "nlsospf3": {"10.0.0.2"},
        }
        for ns, expected in expected_neighbors.items():
            _wait_until(lambda ns=ns, expected=expected: set(_neighbors(ns)) == expected,
                        f"real OSPFv3 adjacencies on {ns}", timeout=75)
        baseline = {ns: _snapshot(ns) for ns in ROUTERS}
        assert all(baseline[ns]["neighbors"] for ns in ROUTERS)
        assert all(baseline[ns]["lsdb"] for ns in ROUTERS)

        # Start the actual NLS daemon on the middle router with no peers. This
        # creates its real TUN device but does not invent a handshake/session.
        config_dir = tmp_path / "nls-config"
        config_dir.mkdir()
        identity_dir = tmp_path / "identity"
        identity_dir.mkdir()
        nls_config = {
            "nls": {
                "enabled": True, "deployment_mode": "lab", "protocol_version": 2,
                "router_id": "ospf-invariance-router", "listen_address": "::",
                "listen_port": 4789, "identity_key": str(identity_dir / "ed25519.key"),
                "encryption_private_key": str(identity_dir / "rsa-encryption.pem"),
                "peers": [], "tun": {"enabled": True, "name": "nls0", "mtu": 1280},
            }
        }
        (config_dir / "nls.yaml").write_text(yaml.safe_dump(nls_config), encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "PYTHONPATH": os.getcwd(),
            "NLSXNETOS_CONFIG_DIR": str(config_dir),
            "NLSXNETOS_NLS_STATUS_PATH": str(tmp_path / "nls-status.json"),
            "NLSXNETOS_VIP_STATE": str(tmp_path / "vip-state.json"),
            "NLSXNETOS_TRUST_TABLE": str(tmp_path / "trust-table.json"),
            "NLSXNETOS_VIP_POOL": "fd42:4e4c:53::/64",
        })
        nls_proc = subprocess.Popen(
            ["ip", "netns", "exec", "nlsospf2", sys.executable, "-c",
             "from nls.daemon import run; run()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )
        _wait_until(
            lambda: run("ip", "link", "show", "nls0", ns="nlsospf2", check=False).returncode == 0
            if nls_proc.poll() is None else False,
            "actual NLS daemon TUN startup", timeout=30,
        )
        during_nls = {ns: _snapshot(ns) for ns in ROUTERS}
        assert during_nls == baseline, "NLS startup changed OSPFv3 neighbors, LSDB or kernel routes"

        nls_proc.terminate()
        try:
            nls_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            nls_proc.kill()
            nls_proc.wait(timeout=5)
            raise AssertionError("NLS daemon did not stop cleanly")
        nls_proc = None
        _wait_until(
            lambda: run("ip", "link", "show", "nls0", ns="nlsospf2", check=False).returncode != 0,
            "NLS TUN teardown", timeout=15,
        )
        after_shutdown = {ns: _snapshot(ns) for ns in ROUTERS}
        assert after_shutdown == baseline, "NLS shutdown changed OSPFv3 neighbors, LSDB or kernel routes"

        # Positive control: an intentional new OSPFv3-advertised prefix must
        # change the observed LSDB and propagate into the first router's FIB.
        run("ip", "link", "add", "control0", "type", "dummy", ns="nlsospf3")
        run("ip", "link", "set", "control0", "up", ns="nlsospf3")
        run("ip", "-6", "addr", "add", "2001:db8:999::1/128", "dev", "control0", ns="nlsospf3")
        _vty("nlsospf3", "configure terminal", "interface control0",
             "ipv6 ospf6 area 0.0.0.0", "end")
        _wait_until(
            lambda: any("2001:db8:999::/128" in route or "2001:db8:999::1" in route
                        for route in _routes("nlsospf1")),
            "positive-control OSPFv3 route propagation", timeout=45,
        )
        assert _lsdb("nlsospf1") != baseline["nlsospf1"]["lsdb"], (
            "positive control failed: intentional OSPFv3 prefix change did not alter LSDB"
        )
    finally:
        if nls_proc is not None:
            nls_proc.terminate()
            try:
                nls_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                nls_proc.kill()
                nls_proc.wait(timeout=5)
        for ns in reversed(frr_started):
            _stop_frr(ns)
        for ns in reversed(created):
            run("ip", "netns", "del", ns, check=False)

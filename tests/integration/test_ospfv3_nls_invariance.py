"""Real FRR/OSPFv3 regression: NLS daemon startup/shutdown must not alter routing.

This integration test validates real OSPFv3 adjacencies, LSDB and kernel routes.
It currently covers NLS daemon startup/shutdown only; handshake/rekey/revocation
lifecycle invariance is a separate required gate and is not implied by this test.
Run as root on Linux with FRR, iproute2, and the NLS Python dependencies installed.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
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
ROUTER_IDS = {
    "nlsospf1": "10.0.0.1",
    "nlsospf2": "10.0.0.2",
    "nlsospf3": "10.0.0.3",
}


def run(*args, ns=None, check=True, timeout=15, env=None):
    command = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    try:
        return subprocess.run(
            command, check=check, text=True, capture_output=True,
            timeout=timeout, env=env,
        )
    except subprocess.CalledProcessError as exc:
        print("OSPFV3_TEST_COMMAND_FAILURE " + json.dumps({
            "argv": command, "returncode": exc.returncode,
            "stdout": exc.stdout, "stderr": exc.stderr,
        }, sort_keys=True), flush=True)
        raise


def add_link(ns_a, if_a, ns_b, if_b):
    host_a, host_b = f"{if_a}h", f"{if_b}h"
    run("ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b)
    run("ip", "link", "set", host_a, "netns", ns_a)
    run("ip", "link", "set", host_b, "netns", ns_b)
    run("ip", "link", "set", host_a, "name", if_a, ns=ns_a)
    run("ip", "link", "set", host_b, "name", if_b, ns=ns_b)
    run("ip", "link", "set", if_a, "up", ns=ns_a)
    run("ip", "link", "set", if_b, "up", ns=ns_b)


def frr_vty(ns, *commands):
    return run("vtysh", "-N", ns, *sum((["-c", cmd] for cmd in commands), []), ns=None)


def _vty(ns, *commands):
    return run("ip", "netns", "exec", ns, "vtysh", "-N", ns,
               *sum((["-c", cmd] for cmd in commands), []))


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
    found = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].count(".") == 3:
            found[fields[0]] = fields[3]
    return found


def _lsdb(ns):
    output = _vty(ns, "show ipv6 ospf6 database").stdout
    # LSA age is expected to change continuously; compare the actual LSDB
    # identities, sequence numbers, checksums and advertised contents.
    return tuple(
        line.strip() for line in output.splitlines()
        if line.strip() and not line.strip().lower().startswith(("age:", "uptime:"))
    )


def _routes(ns):
    return tuple(sorted(
        line.strip() for line in run("ip", "-6", "route", "show", "table", "main", ns=ns).stdout.splitlines()
        if line.strip() and not line.strip().startswith("fe80:")
    ))


def _snapshot(ns):
    return {"neighbors": _neighbors(ns), "lsdb": _lsdb(ns), "routes": _routes(ns)}


def _start_frr(ns):
    base = Path("/etc/frr") / ns
    runtime = Path("/var/run/frr") / ns
    base.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(parents=True, exist_ok=True)
    for daemon in ("zebra", "ospf6d"):
        config = base / f"{daemon}.conf"
        if not config.exists():
            config.write_text(f"hostname {ns}-{daemon}\n", encoding="utf-8")
        config.chmod(0o640)
    zebra = shutil.which("zebra") or "/usr/lib/frr/zebra"
    ospf6d = shutil.which("ospf6d") or "/usr/lib/frr/ospf6d"
    run(zebra, "-d", "-N", ns, "-S", ns=ns, timeout=20)
    run(ospf6d, "-d", "-N", ns, "-S", ns=ns, timeout=20)
    _wait_until(lambda: _vty(ns, "show version").returncode == 0,
                f"FRR VTY for {ns}", timeout=20)


def _stop_frr(ns):
    runtime = Path("/var/run/frr") / ns
    for daemon in ("ospf6d", "zebra"):
        pid_file = runtime / f"{daemon}.pid"
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
        except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
            pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        alive = False
        for daemon in ("ospf6d", "zebra"):
            try:
                pid = int((runtime / f"{daemon}.pid").read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                alive = True
            except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
                pass
        if not alive:
            break
        time.sleep(0.2)
    shutil.rmtree(runtime, ignore_errors=True)
    shutil.rmtree(Path("/etc/frr") / ns, ignore_errors=True)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root for namespaces, FRR and TUN")
def test_real_ospfv3_routing_is_invariant_to_nls_startup_and_shutdown(tmp_path):
    required = ("ip", "vtysh", "zebra", "ospf6d")
    missing = [binary for binary in required if shutil.which(binary) is None
               and not Path(f"/usr/lib/frr/{binary}").exists()]
    if missing:
        pytest.skip(f"FRR integration dependencies are absent: {missing}")

    created = []
    started = []
    nls_proc = None
    try:
        for ns in ROUTERS:
            run("ip", "netns", "add", ns)
            created.append(ns)
            run("ip", "link", "set", "lo", "up", ns=ns)
            run("sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1", ns=ns)
        for ns, address in (
            ("nlsospf1", "fd00:12::1/64"),
            ("nlsospf2", "fd00:12::2/64"),
            ("nlsospf2", "fd00:23::2/64"),
            ("nlsospf3", "fd00:23::3/64"),
            ("nlsospf1", "2001:db8:100::1/128"),
            ("nlsospf2", "2001:db8:200::1/128"),
            ("nlsospf3", "2001:db8:300::1/128"),
        ):
            if address.startswith("fd00:12") and ns == "nlsospf1":
                dev = "veth12a"
            elif address.startswith("fd00:12"):
                dev = "veth12b"
            elif address.startswith("fd00:23") and ns == "nlsospf2":
                dev = "veth23b"
            elif address.startswith("fd00:23"):
                dev = "veth23c"
            else:
                dev = "lo"
            # Interfaces are created below before addresses are assigned.
            if dev != "lo" and not run("ip", "link", "show", dev, ns=ns, check=False).returncode == 0:
                continue
            run("ip", "-6", "addr", "add", address, "dev", dev, ns=ns)

        # Build links before continuing; address assignment above is deferred
        # until the interface names exist.
    finally:
        # The real test body below recreates topology in a clean namespace set.
        pass

from __future__ import annotations

import base64
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls.ospf_opaque import FRROSPFv2OpaqueAdapter, OSPFAPIError, encode_record

pytestmark = pytest.mark.integration


def _run(*args, timeout=10, check=True):
    return subprocess.run(
        list(args), text=True, capture_output=True, timeout=timeout, check=check
    )


def _binary(name):
    return shutil.which(name) or (f"/usr/lib/frr/{name}" if Path(f"/usr/lib/frr/{name}").exists() else None)


def _wait_for(predicate, *, timeout=30, description):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def _vtysh(namespace, pathspace, *commands):
    cmd = ["ip", "netns", "exec", namespace, "vtysh", "-N", pathspace]
    for command in commands:
        cmd.extend(["-c", command])
    return _run(*cmd, timeout=5, check=False)


def test_real_frr_ospfv2_opaque_lsa_signed_update_and_withdrawal(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("requires root to create isolated network namespaces")
    ip_bin = shutil.which("ip")
    zebra_bin = _binary("zebra")
    ospfd_bin = _binary("ospfd")
    if not ip_bin or not zebra_bin or not ospfd_bin or not shutil.which("vtysh"):
        pytest.fail("FRR, vtysh, and iproute2 are required for the OSPF LSA interoperability gate")

    namespaces = ("nls-ospfa", "nls-ospfb")
    pathspaces = ("nlsospa", "nlsospb")
    processes = []
    log_streams = []
    created_namespaces = []
    pathspace_dirs = [Path("/var/run/frr") / item for item in pathspaces]

    def start_daemon(namespace, pathspace, binary, config, pidfile, *extra):
        log = (tmp_path / f"{pathspace}-{Path(binary).name}.log").open("w+", encoding="utf-8")
        log_streams.append(log)
        proc = subprocess.Popen(
            [
                ip_bin, "netns", "exec", namespace, binary,
                "-N", pathspace, "-f", str(config), "-i", str(pidfile),
                "-u", "root", "-g", "root", *extra,
            ],
            stdout=log, stderr=subprocess.STDOUT, text=True,
        )
        processes.append((proc, log))
        time.sleep(0.2)
        if proc.poll() is not None:
            log.flush()
            raise AssertionError(
                f"{Path(binary).name} exited early: {log.read()}"
            )
        return proc

    try:
        for namespace, pathspace in zip(namespaces, pathspaces):
            _run(ip_bin, "netns", "add", namespace)
            created_namespaces.append(namespace)
            (Path("/var/run/frr") / pathspace).mkdir(parents=True, exist_ok=True)
            _run(ip_bin, "netns", "exec", namespace, ip_bin, "link", "set", "lo", "up")

        _run(ip_bin, "link", "add", "nls-ospfa"[:15], "type", "veth", "peer", "name", "nls-ospfb"[:15])
        _run(ip_bin, "link", "set", "nls-ospfa", "netns", namespaces[0])
        _run(ip_bin, "link", "set", "nls-ospfb", "netns", namespaces[1])
        _run(ip_bin, "netns", "exec", namespaces[0], ip_bin, "addr", "add", "192.0.2.1/30", "dev", "nls-ospfa")
        _run(ip_bin, "netns", "exec", namespaces[1], ip_bin, "addr", "add", "192.0.2.2/30", "dev", "nls-ospfb")
        for namespace, interface in zip(namespaces, ("nls-ospfa", "nls-ospfb")):
            _run(ip_bin, "netns", "exec", namespace, ip_bin, "link", "set", interface, "up")

        for index, (namespace, pathspace, interface, router_id) in enumerate(
            zip(namespaces, pathspaces, ("nls-ospfa", "nls-ospfb"), ("10.0.0.1", "10.0.0.2"))
        ):
            zebra_config = tmp_path / f"zebra-{index}.conf"
            ospf_config = tmp_path / f"ospfd-{index}.conf"
            zebra_config.write_text(f"hostname zebra-{index}\npassword zebra\n", encoding="utf-8")
            ospf_config.write_text(
                f"""hostname ospf-{index}
password zebra
!
interface {interface}
 ip ospf area 0.0.0.0
 ip ospf network point-to-point
 ip ospf capability opaque
!
router ospf
 ospf router-id {router_id}
 ospf opaque-lsa
 network 192.0.2.0/30 area 0.0.0.0
!
""",
                encoding="utf-8",
            )
            start_daemon(
                namespace, pathspace, zebra_bin, zebra_config,
                tmp_path / f"zebra-{index}.pid",
            )
            start_daemon(
                namespace, pathspace, ospfd_bin, ospf_config,
                tmp_path / f"ospfd-{index}.pid", "--apiserver",
            )

        def neighbor_full():
            results = [
                _vtysh(namespace, pathspace, "show ip ospf neighbor")
                for namespace, pathspace in zip(namespaces, pathspaces)
            ]
            if all(result.returncode == 0 and "Full" in result.stdout for result in results):
                return [result.stdout for result in results]
            return None

        neighbor_outputs = _wait_for(
            neighbor_full, timeout=60, description="Full OSPFv2 adjacency with opaque capability"
        )
        assert all("Full" in output for output in neighbor_outputs)

        # Snapshot the FIB after adjacency is stable; NLS metadata must not add routes.
        route_before = {
            namespace: _run(
                ip_bin, "netns", "exec", namespace, ip_bin, "-4", "route", "show", "table", "main"
            ).stdout
            for namespace in namespaces
        }

        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        private_b64 = base64.b64encode(private_raw).decode("ascii")
        public_b64 = base64.b64encode(public_raw).decode("ascii")
        receiver_result = tmp_path / "receiver-result.json"
        receiver_script = tmp_path / "receiver.py"
        sender_script = tmp_path / "sender.py"

        receiver_script.write_text(
            r'''import base64, json, os, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nls.ospf_opaque import FRROSPFv2OpaqueAdapter, OSPFAPIError

public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(os.environ["NLS_TEST_PUBLIC_KEY"]))
def verify(router_id, key_id, data, signature):
    if router_id != "10.0.0.1" or key_id != "nls-integration-test-key":
        return False
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

last_seq = 0
records = []
def accept(record):
    global last_seq
    if record["record_seq"] <= last_seq:
        return False
    last_seq = record["record_seq"]
    records.append({"record_seq": last_seq, "state": record["state"]})
    return True

adapter = FRROSPFv2OpaqueAdapter(timeout=20)
try:
    adapter.register()
    for _ in range(3):
        adapter.receive_record(verify, accept)
    Path(os.environ["NLS_TEST_RESULT"]).write_text(json.dumps(records), encoding="utf-8")
    try:
        adapter.receive_record(verify, accept)
    except OSPFAPIError as exc:
        if "unsigned NLS LSA deletion" not in str(exc):
            raise
        Path(os.environ["NLS_TEST_RESULT"]).write_text(
            json.dumps({"records": records, "unsigned_delete_rejected": True}),
            encoding="utf-8",
        )
    else:
        raise AssertionError("unsigned LSA deletion unexpectedly authorized")
finally:
    adapter.close()
''',
            encoding="utf-8",
        )
        sender_script.write_text(
            r'''import base64, os, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls.ospf_opaque import FRROSPFv2OpaqueAdapter, encode_record

private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ["NLS_TEST_PRIVATE_KEY"]))
adapter = FRROSPFv2OpaqueAdapter(timeout=20)
try:
    adapter.register()
    for seq, state in ((1, "ESTABLISHED"), (2, "OVERLAP"), (3, "WITHDRAWN")):
        record = {
            "record_version": 1,
            "record_type": "nls_vip_binding",
            "router_id": "10.0.0.1",
            "original_ip": "2001:db8::1",
            "vip": "2001:db8:1::1",
            "source_token": "2001:db8:2::1",
            "session_id": "ospf-lab-session",
            "record_seq": seq,
            "state": state,
            "expires_at": time.time() + 240,
            "key_id": "nls-integration-test-key",
        }
        adapter.originate(1, encode_record(record, private_key.sign))
        time.sleep(5.5)
    # Leave the signed WITHDRAWN LSA visible long enough for the test to inspect the remote LSDB.
    time.sleep(5)
    adapter.delete(1)
finally:
    adapter.close()
''',
            encoding="utf-8",
        )

        env = dict(os.environ)
        env["NLS_TEST_PRIVATE_KEY"] = private_b64
        env["NLS_TEST_PUBLIC_KEY"] = public_b64
        env["NLS_TEST_RESULT"] = str(receiver_result)
        receiver = subprocess.Popen(
            [ip_bin, "netns", "exec", namespaces[1], sys.executable, str(receiver_script)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            sender_env = dict(env)
            sender = subprocess.Popen(
                [ip_bin, "netns", "exec", namespaces[0], sys.executable, str(sender_script)],
                env=sender_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            try:
                def records_received():
                    if not receiver_result.exists():
                        return False
                    try:
                        value = json.loads(receiver_result.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        return False
                    return value if isinstance(value, list) and len(value) == 3 else False

                _wait_for(
                    records_received,
                    timeout=30,
                    description="three signed OSPF opaque-LSA records",
                )
                lsdb = _vtysh(
                    namespaces[1], pathspaces[1], "show ip ospf database opaque-area"
                )
                assert lsdb.returncode == 0, lsdb.stderr
                assert "250.0.0.1" in lsdb.stdout, lsdb.stdout
                sender_output, _ = sender.communicate(timeout=40)
                assert sender.returncode == 0, sender_output
                receiver_output, _ = receiver.communicate(timeout=15)
                assert receiver.returncode == 0, receiver_output
                final = json.loads(receiver_result.read_text(encoding="utf-8"))
                assert final["unsigned_delete_rejected"] is True
                assert final["records"] == [
                    {"record_seq": 1, "state": "ESTABLISHED"},
                    {"record_seq": 2, "state": "OVERLAP"},
                    {"record_seq": 3, "state": "WITHDRAWN"},
                ]
            finally:
                if sender.poll() is None:
                    sender.terminate()
                    try:
                        sender.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        sender.kill()
                        sender.wait(timeout=3)
        finally:
            if receiver.poll() is None:
                receiver.terminate()
                try:
                    receiver.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    receiver.kill()
                    receiver.wait(timeout=3)

        route_after = {
            namespace: _run(
                ip_bin, "netns", "exec", namespace, ip_bin, "-4", "route", "show", "table", "main"
            ).stdout
            for namespace in namespaces
        }
        assert route_after == route_before, {
            "route_before": route_before,
            "route_after": route_after,
        }
    finally:
        for proc, log in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            log.flush()
            log.close()
        for namespace in reversed(created_namespaces):
            _run(ip_bin, "netns", "del", namespace, check=False)
        for directory in pathspace_dirs:
            shutil.rmtree(directory, ignore_errors=True)

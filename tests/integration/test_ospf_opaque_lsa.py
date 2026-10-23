from __future__ import annotations

import base64
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
        receiver_progress = tmp_path / "receiver-progress.json"
        receiver_ready = tmp_path / "receiver-ready"
        receiver_script = tmp_path / "receiver.py"
        sender_script = tmp_path / "sender.py"

        receiver_script.write_text(
            r'''import base64, json, os, subprocess, time
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
    Path(os.environ["NLS_TEST_PROGRESS"]).write_text(json.dumps(records), encoding="utf-8")
    return True

adapter = FRROSPFv2OpaqueAdapter(timeout=60)
try:
    adapter.register()
    original_read_frame = adapter._read_frame
    def trace_read_frame(sock):
        message_type, sequence, body = original_read_frame(sock)
        if sock is adapter._async:
            with open(os.environ["NLS_TEST_TRACE"], "a", encoding="utf-8") as trace:
                trace.write(json.dumps({
                    "message_type": message_type,
                    "sequence": sequence,
                    "body_length": len(body),
                    "prefix_hex": body[:12].hex(),
                }) + "\\n")
        return message_type, sequence, body
    adapter._read_frame = trace_read_frame
    Path(os.environ["NLS_TEST_READY"]).write_text("ready", encoding="utf-8")
    def next_signed_record():
        while True:
            try:
                return adapter.receive_record(verify, accept)
            except OSPFAPIError as exc:
                message = str(exc)
                if "unsigned NLS LSA deletion" in message:
                    if len(records) == 3 and records[-1]["state"] == "WITHDRAWN":
                        return None
                    continue
                if "stale or unauthorized" in message:
                    continue
                raise

    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        record = next_signed_record()
        if record is not None and record["record_seq"] == 3 and record["state"] == "WITHDRAWN":
            break
    else:
        raise AssertionError(f"did not receive signed WITHDRAWN sequence 3; records={records!r}")
    Path(os.environ["NLS_TEST_PROGRESS"]).write_text(json.dumps(records), encoding="utf-8")
    while next_signed_record() is not None:
        pass
    Path(os.environ["NLS_TEST_RESULT"]).write_text(
        json.dumps({"records": records, "unsigned_delete_rejected": True}),
        encoding="utf-8",
    )
finally:
    adapter.close()
''',
            encoding="utf-8",
        )
        sender_script.write_text(
            r'''import base64, json, os, subprocess, time
from pathlib import Path
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
        adapter.originate(seq, encode_record(record, private_key.sign))
        time.sleep(1)
        local_lsdb = subprocess.run(
            ["vtysh", "-N", os.environ["NLS_TEST_PATHSPACE"],
             "-c", "show ip ospf database opaque-area"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        with open(os.environ["NLS_TEST_SENDER_PROGRESS"], "a", encoding="utf-8") as progress:
            progress.write(json.dumps({
                "record_seq": seq, "state": state,
                "local_lsdb": local_lsdb.stdout,
                "local_lsdb_error": local_lsdb.stderr,
            }) + "\\n")
        time.sleep(8)
    # Leave the signed WITHDRAWN LSA visible long enough for the test to inspect the remote LSDB.
    time.sleep(20)
    adapter.delete(3)
finally:
    adapter.close()
''',
            encoding="utf-8",
        )

        env = dict(os.environ)
        env["NLS_TEST_PRIVATE_KEY"] = private_b64
        env["NLS_TEST_PUBLIC_KEY"] = public_b64
        env["NLS_TEST_RESULT"] = str(receiver_result)
        env["NLS_TEST_PROGRESS"] = str(receiver_progress)
        env["NLS_TEST_READY"] = str(receiver_ready)
        receiver_trace = tmp_path / "receiver-trace.jsonl"
        env["NLS_TEST_TRACE"] = str(receiver_trace)
        sender_progress = tmp_path / "sender-progress.json"
        env["NLS_TEST_SENDER_PROGRESS"] = str(sender_progress)
        env["NLS_TEST_PATHSPACE"] = pathspaces[0]
        receiver = subprocess.Popen(
            [ip_bin, "netns", "exec", namespaces[1], sys.executable, str(receiver_script)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            def receiver_ready_check():
                if receiver.poll() is not None:
                    output, _ = receiver.communicate()
                    raise AssertionError(
                        f"receiver exited before registering rc={receiver.returncode}: {output}"
                    )
                return receiver_ready.exists()

            _wait_for(
                receiver_ready_check,
                timeout=30,
                description="receiver OSPF API event subscription",
            )
            sender_env = dict(env)
            sender = subprocess.Popen(
                [ip_bin, "netns", "exec", namespaces[0], sys.executable, str(sender_script)],
                env=sender_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            try:
                def records_received():
                    if receiver.poll() is not None:
                        output, _ = receiver.communicate()
                        raise AssertionError(
                            f"receiver exited early rc={receiver.returncode}: {output}"
                        )
                    if sender.poll() is not None and sender.returncode != 0:
                        output, _ = sender.communicate()
                        raise AssertionError(
                            f"sender failed rc={sender.returncode}: {output}"
                        )
                    if not receiver_progress.exists():
                        return False
                    try:
                        value = json.loads(receiver_progress.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        return False
                    return value if isinstance(value, list) and value and value[-1] == {"record_seq": 3, "state": "WITHDRAWN"} else False

                try:
                    _wait_for(
                        records_received,
                        timeout=45,
                        description="three signed OSPF opaque-LSA records",
                    )
                except AssertionError as exc:
                    progress = (
                        receiver_progress.read_text(encoding="utf-8")
                        if receiver_progress.exists()
                        else "none"
                    )
                    trace = (
                        receiver_trace.read_text(encoding="utf-8")
                        if receiver_trace.exists()
                        else "none"
                    )
                    sender_state = (
                        sender_progress.read_text(encoding="utf-8")
                        if sender_progress.exists()
                        else "none"
                    )
                    remote_lsdb = _vtysh(
                        namespaces[1], pathspaces[1], "show ip ospf database opaque-area"
                    ).stdout
                    raise AssertionError(
                        f"{exc}; receiver progress={progress}; sender progress={sender_state}; trace={trace}; remote LSDB={remote_lsdb}"
                    ) from exc
                lsdb = _vtysh(
                    namespaces[1], pathspaces[1], "show ip ospf database opaque-area"
                )
                assert lsdb.returncode == 0, lsdb.stderr
                assert "250.0.0.3" in lsdb.stdout, lsdb.stdout
                assert "Opaque-ID   0x3" in lsdb.stdout, lsdb.stdout
                sender_output, _ = sender.communicate(timeout=50)
                assert sender.returncode == 0, sender_output
                receiver_output, _ = receiver.communicate(timeout=40)
                assert receiver.returncode == 0, receiver_output
                final = json.loads(receiver_result.read_text(encoding="utf-8"))
                assert final["unsigned_delete_rejected"] is True
                assert final["records"]
                assert final["records"][-1] == {
                    "record_seq": 3, "state": "WITHDRAWN"
                }
                assert all(
                    earlier["record_seq"] < later["record_seq"]
                    for earlier, later in zip(
                        final["records"], final["records"][1:]
                    )
                )
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

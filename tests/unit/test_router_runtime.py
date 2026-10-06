from pathlib import Path


def test_router_runtime_has_sysctl_targets():
    source = Path(__file__).resolve().parents[2] / "nlsxnetos" / "router_runtime.py"
    text = source.read_text(encoding="utf-8")
    assert "/proc/sys/net/ipv4/ip_forward" in text
    assert "/proc/sys/net/ipv6/conf/all/forwarding" in text

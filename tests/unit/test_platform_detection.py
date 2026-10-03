from collections import namedtuple
from pathlib import Path

from nlsxnetos.platform.detection import (
    UbuntuSupport,
    detect_platform,
    format_platform_report,
    parse_os_release,
)
from nlsxnetos.platform.ubuntu import is_deployment_candidate

Uname = namedtuple("Uname", "release machine")


def _detect(os_release: str):
    return detect_platform(
        Path("/test/os-release"),
        read_text=lambda _: os_release,
        uname=Uname(release="6.8.0-test", machine="x86_64"),
        python_version="3.12.3",
    )


def test_parse_os_release_handles_quotes_comments_and_bad_lines() -> None:
    parsed = parse_os_release('ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04 LTS"\n# comment\nbad\n')

    assert parsed == {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"}


def test_ubuntu_2004_is_reported_as_legacy() -> None:
    info = _detect('ID=ubuntu\nVERSION_ID="20.04"\n')

    assert info.is_ubuntu is True
    assert info.ubuntu_support is UbuntuSupport.LEGACY
    assert is_deployment_candidate(info) is True
    assert "legacy" in info.support_message.lower()


def test_recognized_ubuntu_is_not_claimed_as_validated() -> None:
    info = _detect('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')

    assert info.ubuntu_support is UbuntuSupport.PREPARED_UNVALIDATED
    assert "not yet been validated" in info.support_message


def test_non_ubuntu_is_rejected() -> None:
    info = _detect('ID=debian\nVERSION_ID="12"\n')

    assert info.is_ubuntu is False
    assert info.ubuntu_support is UbuntuSupport.NOT_UBUNTU
    assert is_deployment_candidate(info) is False


def test_missing_os_release_is_reported_without_raising() -> None:
    info = detect_platform(
        Path("/missing"),
        read_text=lambda _: (_ for _ in ()).throw(FileNotFoundError()),
        uname=Uname(release="6.8.0-test", machine="arm64"),
        python_version="3.12.3",
    )

    assert info.ubuntu_support is UbuntuSupport.UNKNOWN
    assert "Unable to determine" in info.support_message


def test_platform_report_contains_observed_facts() -> None:
    report = format_platform_report(_detect('ID=ubuntu\nVERSION_ID="22.04"\n'))

    assert "Kernel: 6.8.0-test" in report
    assert "Ubuntu support: prepared-unvalidated" in report

"""Read-only operating-system detection for supported deployment targets.

This module deliberately does not run package managers, change networking, or
require elevated privileges.  It gives later commands a trustworthy basis for
deciding whether it is safe to continue on the host.
"""

from __future__ import annotations

import platform
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class UbuntuSupport(str, Enum):
    """The project's validation state for a detected Ubuntu release."""

    LEGACY = "legacy"
    PREPARED_UNVALIDATED = "prepared-unvalidated"
    UNSUPPORTED = "unsupported"
    NOT_UBUNTU = "not-ubuntu"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlatformInfo:
    """Facts discovered from the host without changing it."""

    distribution_id: str | None
    version_id: str | None
    version_codename: str | None
    pretty_name: str | None
    kernel: str
    architecture: str
    python_version: str
    is_ubuntu: bool
    ubuntu_support: UbuntuSupport
    support_message: str


def parse_os_release(contents: str) -> dict[str, str]:
    """Parse the key/value subset of the freedesktop ``os-release`` format.

    Shell variable expansion is intentionally not performed.  Malformed lines
    are ignored because a detector should report incomplete information rather
    than fail merely because an optional field is malformed.
    """

    values: dict[str, str] = {}
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        try:
            parsed = shlex.split(raw_value, posix=True)
        except ValueError:
            continue
        if len(parsed) == 1:
            values[key] = parsed[0]
        elif not parsed:
            values[key] = ""
    return values


def _ubuntu_support(
    distribution_id: str | None, version_id: str | None
) -> tuple[bool, UbuntuSupport, str]:
    """Return the support posture without claiming unperformed validation."""

    if not distribution_id:
        return False, UbuntuSupport.UNKNOWN, "Unable to determine the operating system distribution."
    if distribution_id.casefold() != "ubuntu":
        return False, UbuntuSupport.NOT_UBUNTU, "NlsxNetOS currently targets Ubuntu only."
    if version_id == "20.04":
        return (
            True,
            UbuntuSupport.LEGACY,
            "Ubuntu 20.04 is detected as a legacy target; standard support has ended.",
        )
    if version_id in {"22.04", "24.04"}:
        return (
            True,
            UbuntuSupport.PREPARED_UNVALIDATED,
            f"Ubuntu {version_id} is recognized, but this release has not yet been validated by CI or a test VM.",
        )
    return (
        True,
        UbuntuSupport.UNSUPPORTED,
        f"Ubuntu {version_id or 'with an unknown version'} is not a validated NlsxNetOS target.",
    )


def detect_platform(
    os_release_path: Path = Path("/etc/os-release"),
    *,
    read_text: Callable[[Path], str] | None = None,
    uname: platform.uname_result | None = None,
    python_version: str | None = None,
) -> PlatformInfo:
    """Return platform facts using only read-only host information.

    ``read_text`` and ``uname`` are injectable to make the behavior testable
    without depending on the platform running the test suite.
    """

    if read_text is None:
        read_text = lambda path: path.read_text(encoding="utf-8")
    try:
        os_release = parse_os_release(read_text(os_release_path))
    except (OSError, UnicodeError):
        os_release = {}

    system = uname or platform.uname()
    distribution_id = os_release.get("ID")
    version_id = os_release.get("VERSION_ID")
    is_ubuntu, ubuntu_support, support_message = _ubuntu_support(distribution_id, version_id)
    return PlatformInfo(
        distribution_id=distribution_id,
        version_id=version_id,
        version_codename=os_release.get("VERSION_CODENAME"),
        pretty_name=os_release.get("PRETTY_NAME"),
        kernel=system.release,
        architecture=system.machine,
        python_version=python_version or platform.python_version(),
        is_ubuntu=is_ubuntu,
        ubuntu_support=ubuntu_support,
        support_message=support_message,
    )


def format_platform_report(info: PlatformInfo) -> str:
    """Format detection results for a future read-only diagnostic command."""

    distribution = info.pretty_name or info.distribution_id or "unknown"
    version = info.version_id or "unknown"
    return "\n".join(
        (
            f"Distribution: {distribution}",
            f"Version: {version}",
            f"Kernel: {info.kernel}",
            f"Architecture: {info.architecture}",
            f"Python: {info.python_version}",
            f"Ubuntu support: {info.ubuntu_support.value}",
            f"Status: {info.support_message}",
        )
    )

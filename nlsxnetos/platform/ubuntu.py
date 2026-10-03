"""Ubuntu-specific platform helpers.

All mutating Ubuntu implementation belongs here in later milestones.  This
milestone only exposes the read-only support assessment from platform
detection.
"""

from .detection import PlatformInfo, UbuntuSupport


def is_deployment_candidate(info: PlatformInfo) -> bool:
    """Return whether the host is Ubuntu, without claiming it is validated."""

    return info.is_ubuntu and info.ubuntu_support in {
        UbuntuSupport.LEGACY,
        UbuntuSupport.PREPARED_UNVALIDATED,
    }

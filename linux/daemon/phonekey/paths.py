"""Default locations.

Development: state in ~/.local/state/phonekey-dev, socket in $XDG_RUNTIME_DIR/phonekey.
System service (installed by scripts/install.sh): state in /var/lib/phonekey,
socket in /run/phonekey. Environment variables override both.
"""

import os
from pathlib import Path

SYSTEM_STATE = Path("/var/lib/phonekey")
SYSTEM_SOCKET = Path("/run/phonekey/phonekey.sock")


def dev_state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "phonekey-dev"


def default_state_dir(system: bool | None = None) -> Path:
    """`system=None` picks the system registry when running as root on an installed system."""
    if "PHONEKEY_STATE_DIR" in os.environ:
        return Path(os.environ["PHONEKEY_STATE_DIR"])
    if system is None:
        system = os.geteuid() == 0 and SYSTEM_STATE.is_dir()
    return SYSTEM_STATE if system else dev_state_dir()


def dev_socket_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "phonekey" / "phonekey.sock"


def default_socket_path(system: bool = False) -> Path:
    if "PHONEKEY_SOCKET" in os.environ:
        return Path(os.environ["PHONEKEY_SOCKET"])
    return SYSTEM_SOCKET if system else dev_socket_path()

"""Default locations (development mode; the system service uses --system paths in Phase 5)."""

import os
from pathlib import Path

SYSTEM_SOCKET = Path("/run/phonekey/phonekey.sock")


def default_state_dir() -> Path:
    if "PHONEKEY_STATE_DIR" in os.environ:
        return Path(os.environ["PHONEKEY_STATE_DIR"])
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "phonekey-dev"


def default_socket_path() -> Path:
    if "PHONEKEY_SOCKET" in os.environ:
        return Path(os.environ["PHONEKEY_SOCKET"])
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "phonekey" / "phonekey.sock"

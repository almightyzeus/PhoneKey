"""Adds and removes PhoneKey's line in one PAM service file (SECURITY.md D-8).

Only `phonekey enable` / `phonekey disable` call the writers, as root, after
showing the diff. The edit is one `auth sufficient` line placed right before
`@include common-auth`, so the password prompt (pam_unix) always follows.
`common-auth` itself is never edited. Removal needs neither the phone nor the
daemon.
"""

from __future__ import annotations

import datetime
import difflib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

PAM_DIR = Path("/etc/pam.d")
BACKUP_DIR = Path("/var/backups/phonekey")
MODULE_NAME = "pam_phonekey.so"
MODULE_DIRS = (Path("/usr/lib/x86_64-linux-gnu/security"), Path("/lib/x86_64-linux-gnu/security"),
               Path("/usr/lib/security"), Path("/lib/security"))
MARKER = "# PhoneKey (pre-alpha): added by 'phonekey enable'; remove with 'sudo phonekey disable'."
_INCLUDE_COMMON_AUTH = re.compile(r"^\s*@include\s+common-auth\s*$")


@dataclass(frozen=True)
class Service:
    name: str      # file in /etc/pam.d
    action: str    # daemon action (daemon.ACTIONS)


# Phase 5: sudo only. Later phases add the lock screen and login, one at a time.
SERVICES = {"sudo": Service("sudo", "sudo")}


class PamConfigError(Exception):
    pass


def module_line(service: Service) -> str:
    return f"auth    sufficient    {MODULE_NAME} action={service.action}"


def is_enabled(text: str) -> bool:
    return any(MODULE_NAME in line and not line.lstrip().startswith("#") for line in text.splitlines())


def add(text: str, service: Service) -> str:
    """Inserts the PhoneKey line before `@include common-auth`. Refuses anything unexpected."""
    if MODULE_NAME in text:
        raise PamConfigError(f"{service.name} already mentions {MODULE_NAME}")
    lines = text.splitlines(keepends=True)
    includes = [i for i, line in enumerate(lines) if _INCLUDE_COMMON_AUTH.match(line)]
    if len(includes) != 1:
        raise PamConfigError(f"expected exactly one '@include common-auth' line in {service.name}, "
                             f"found {len(includes)}; not editing an unfamiliar file")
    i = includes[0]
    if any(re.match(r"^\s*-?auth\s", line) for line in lines[:i]):
        raise PamConfigError(f"{service.name} already has auth rules before common-auth; not editing it")
    return "".join(lines[:i] + [MARKER + "\n", module_line(service) + "\n"] + lines[i:])


def remove(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True)
                   if MODULE_NAME not in line and line.rstrip("\n") != MARKER)


def diff(path: Path, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"{path} (current)", tofile=f"{path} (new)"))


def installed_module() -> Path | None:
    for d in MODULE_DIRS:
        if (d / MODULE_NAME).is_file():
            return d / MODULE_NAME
    return None


def read_service_file(path: Path) -> str:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise PamConfigError(f"{path} is not a regular root-owned file that only root can write; not editing it")
    return path.read_text()


def backup(path: Path, text: str, backup_dir: Path = BACKUP_DIR) -> Path:
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = backup_dir / f"{path.name}.{stamp}"
    n = 1
    while target.exists():
        target = backup_dir / f"{path.name}.{stamp}.{n}"
        n += 1
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return target


def write_atomic(path: Path, text: str) -> None:
    """Replaces `path` in one rename, keeping its mode and owner."""
    st = os.stat(path)
    tmp = path.with_name(f".{path.name}.phonekey-new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IMODE(st.st_mode))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    if path.read_text() != text:
        raise PamConfigError(f"{path} does not contain what was written")


def enabled_files(pam_dir: Path = PAM_DIR) -> list[Path]:
    out = []
    for p in sorted(pam_dir.iterdir()):
        try:
            if p.is_file() and not p.is_symlink() and is_enabled(p.read_text()):
                out.append(p)
        except (OSError, UnicodeDecodeError):
            continue
    return out

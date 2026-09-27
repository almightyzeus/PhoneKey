#!/usr/bin/env bash
# Installs the PhoneKey daemon and CLI as a system service.
#
# Does NOT touch PAM, sudo, the lock screen, login, or Bluetooth configuration.
# Every change is listed first; nothing happens without typing "install".
# Undo with scripts/uninstall.sh.
#
#   sudo scripts/install.sh --dry-run   # show what would change, change nothing
#   sudo scripts/install.sh             # show, ask, then install
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIB=/usr/lib/phonekey
BIN=/usr/bin/phonekey
UNIT=/etc/systemd/system/phonekeyd.service
USER_NAME=phonekey

plan() {
    cat <<PLAN
PhoneKey install plan
=====================
Creates:
  system user   $USER_NAME (no login shell, no password, no home directory)
  $LIB/phonekey/          daemon + CLI Python package (from linux/daemon/phonekey)
  $LIB/phonekeyd          daemon launcher
  $BIN                    CLI launcher
  $UNIT   hardened systemd unit, runs as '$USER_NAME'
  /var/lib/phonekey/            state (created by systemd, owner $USER_NAME, 0700)
  /run/phonekey/                socket directory (created by systemd at runtime)
Runs:
  systemctl daemon-reload
  systemctl enable --now phonekeyd

Does NOT change: PAM (/etc/pam.d), sudo, lock screen, login, /etc/bluetooth,
D-Bus configuration, or installed packages.
Your development pairing (~/.local/state/phonekey-dev) is not copied; pair
again with 'sudo phonekey pair' after installing.
Undo: sudo "$REPO/scripts/uninstall.sh"
PLAN
}

run() {
    if (( DRY_RUN )); then echo "  [dry-run] $*"; else echo "  + $*"; "$@"; fi
}

plan
echo
if (( ! DRY_RUN )); then
    [[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
    read -r -p "Type 'install' to proceed: " answer
    [[ "$answer" == "install" ]] || { echo "Nothing changed."; exit 1; }
fi

echo "Steps:"
if ! getent passwd "$USER_NAME" >/dev/null; then
    run useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "PhoneKey daemon" "$USER_NAME"
fi
run install -d -m 0755 "$LIB/phonekey"
for f in "$REPO"/linux/daemon/phonekey/*.py; do
    run install -m 0644 "$f" "$LIB/phonekey/"
done
run install -m 0644 "$REPO/linux/README.md" "$LIB/README.md"

launcher() {  # launcher <path> <python module entry>
    local tmp
    tmp="$(mktemp)"
    printf '#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "%s")\nfrom %s import main\nsys.exit(main())\n' \
        "$LIB" "$2" > "$tmp"
    run install -m 0755 "$tmp" "$1"
    rm -f "$tmp"
}
launcher "$LIB/phonekeyd" phonekey.daemon
launcher "$BIN" phonekey.cli
run install -m 0644 "$REPO/linux/systemd/phonekeyd.service" "$UNIT"
run systemctl daemon-reload
run systemctl enable --now phonekeyd

echo
if (( DRY_RUN )); then
    echo "Dry run: nothing was changed."
else
    echo "Installed. Check with: phonekey status   and   phonekey logs"
fi

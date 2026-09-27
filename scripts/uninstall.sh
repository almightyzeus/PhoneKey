#!/usr/bin/env bash
# Removes everything scripts/install.sh created. Works without the phone.
#
#   sudo scripts/uninstall.sh --dry-run   # show what would be removed
#   sudo scripts/uninstall.sh             # remove program + service, keep pairings
#   sudo scripts/uninstall.sh --purge     # also remove pairings and the 'phonekey' user
set -euo pipefail

DRY_RUN=0 PURGE=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --purge) PURGE=1 ;;
        *) echo "unknown option $arg" >&2; exit 2 ;;
    esac
done

run() {
    if (( DRY_RUN )); then echo "  [dry-run] $*"; else echo "  + $*"; "$@" || true; fi
}

if grep -qs pam_phonekey /etc/pam.d/*; then
    echo "PhoneKey is still enabled in PAM. Run 'sudo phonekey disable' first:" >&2
    grep -ls pam_phonekey /etc/pam.d/* >&2
    exit 1
fi
(( DRY_RUN )) || [[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

echo "Removing PhoneKey:"
run systemctl disable --now phonekeyd
run rm -f /etc/systemd/system/phonekeyd.service
run systemctl daemon-reload
run rm -rf /usr/lib/phonekey
run rm -f /usr/lib/x86_64-linux-gnu/security/pam_phonekey.so
run rm -f /usr/bin/phonekey
if (( PURGE )); then
    run rm -rf /var/lib/phonekey
    run userdel phonekey
else
    echo "  (keeping /var/lib/phonekey and user 'phonekey'; use --purge to remove them)"
fi
echo "Also forget the laptop/phone pairing in Bluetooth settings if you no longer need it."
(( DRY_RUN )) && echo "Dry run: nothing was changed." || echo "Done."

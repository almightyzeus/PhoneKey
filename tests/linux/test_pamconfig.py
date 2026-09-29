"""PAM file editing (SECURITY.md D-8). Works on copies; never touches /etc/pam.d."""

import os
import tempfile
import unittest
from pathlib import Path

from phonekey import pamconfig
from phonekey.pamconfig import PamConfigError

SUDO = pamconfig.SERVICES["sudo"]
# /etc/pam.d/sudo as shipped by Linux Mint 22 / Ubuntu 24.04.
MINT_SUDO = """#%PAM-1.0

# Set up user limits from /etc/security/limits.conf.
session    required   pam_limits.so

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0

@include common-auth
@include common-account
@include common-session-noninteractive
"""


class EditTest(unittest.TestCase):
    def test_adds_one_sufficient_line_before_common_auth(self):
        new = pamconfig.add(MINT_SUDO, SUDO)
        lines = new.splitlines()
        i = lines.index("@include common-auth")
        self.assertEqual(lines[i - 1], "auth    sufficient    pam_phonekey.so action=sudo")
        self.assertEqual(lines[i - 2], pamconfig.MARKER)
        self.assertEqual(len(lines), len(MINT_SUDO.splitlines()) + 2)
        self.assertTrue(pamconfig.is_enabled(new))
        self.assertFalse(pamconfig.is_enabled(MINT_SUDO))

    def test_never_required_or_requisite(self):
        new = pamconfig.add(MINT_SUDO, SUDO)
        phonekey_lines = [l for l in new.splitlines() if "pam_phonekey" in l and not l.startswith("#")]
        self.assertEqual(len(phonekey_lines), 1)
        self.assertEqual(phonekey_lines[0].split()[1], "sufficient")

    def test_remove_restores_original_exactly(self):
        self.assertEqual(pamconfig.remove(pamconfig.add(MINT_SUDO, SUDO)), MINT_SUDO)

    def test_remove_is_idempotent_and_leaves_other_lines(self):
        self.assertEqual(pamconfig.remove(MINT_SUDO), MINT_SUDO)

    def test_refuses_twice(self):
        with self.assertRaises(PamConfigError):
            pamconfig.add(pamconfig.add(MINT_SUDO, SUDO), SUDO)

    def test_refuses_unfamiliar_files(self):
        for text in (MINT_SUDO.replace("@include common-auth\n", ""),
                     MINT_SUDO + "@include common-auth\n",
                     MINT_SUDO.replace("@include common-auth", "auth required pam_unix.so\n@include common-auth"),
                     MINT_SUDO.replace("@include common-auth", "-auth optional pam_x.so\n@include common-auth")):
            with self.assertRaises(PamConfigError):
                pamconfig.add(text, SUDO)

    def test_diff_shows_only_additions(self):
        d = pamconfig.diff(Path("/etc/pam.d/sudo"), MINT_SUDO, pamconfig.add(MINT_SUDO, SUDO))
        changed = [l for l in d.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
        self.assertEqual(len(changed), 2)
        self.assertTrue(all(l.startswith("+") for l in changed))

# /etc/pam.d/cinnamon-screensaver as shipped by Linux Mint 22.3 (cinnamon-screensaver 6.6).
MINT_SCREENSAVER = """@include common-auth
auth optional pam_gnome_keyring.so
"""
UNLOCK = pamconfig.SERVICES["unlock"]


class UnlockEditTest(unittest.TestCase):
    def test_service_file_and_timeout(self):
        self.assertEqual(("cinnamon-screensaver", "unlock", 20), (UNLOCK.name, UNLOCK.action, UNLOCK.timeout))

    def test_line_goes_first_with_timeout(self):
        lines = pamconfig.add(MINT_SCREENSAVER, UNLOCK).splitlines()
        self.assertEqual([pamconfig.MARKER, "auth    sufficient    pam_phonekey.so action=unlock timeout=20",
                          "@include common-auth", "auth optional pam_gnome_keyring.so"], lines)

    def test_remove_restores_original_exactly(self):
        self.assertEqual(MINT_SCREENSAVER, pamconfig.remove(pamconfig.add(MINT_SCREENSAVER, UNLOCK)))

    def test_real_screensaver_file_is_accepted_if_present(self):
        real = Path("/etc/pam.d/cinnamon-screensaver")
        if not real.exists():
            self.skipTest("no cinnamon-screensaver")
        text = pamconfig.read_service_file(real)  # read only
        if not pamconfig.is_enabled(text):
            self.assertEqual(pamconfig.remove(pamconfig.add(text, UNLOCK)), text)

    def test_sudo_line_unchanged(self):
        self.assertEqual("auth    sufficient    pam_phonekey.so action=sudo", pamconfig.module_line(SUDO))


class FileTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.file = self.dir / "sudo"
        self.file.write_text(MINT_SUDO)
        os.chmod(self.file, 0o644)

    def test_write_atomic_keeps_mode_and_leaves_no_temp(self):
        pamconfig.write_atomic(self.file, "new\n")
        self.assertEqual(self.file.read_text(), "new\n")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["sudo"])

    def test_backup_is_private_and_unique(self):
        backups = self.dir / "backups"
        a = pamconfig.backup(self.file, MINT_SUDO, backups)
        b = pamconfig.backup(self.file, MINT_SUDO, backups)
        self.assertNotEqual(a, b)
        self.assertEqual(a.read_text(), MINT_SUDO)
        self.assertEqual(a.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backups.stat().st_mode & 0o777, 0o700)

    def test_read_refuses_files_not_owned_by_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        with self.assertRaises(PamConfigError):
            pamconfig.read_service_file(self.file)

    def test_enabled_files(self):
        (self.dir / "other").write_text(pamconfig.add(MINT_SUDO, SUDO))
        self.assertEqual([p.name for p in pamconfig.enabled_files(self.dir)], ["other"])

    def test_real_sudo_file_is_accepted_if_present(self):
        real = Path("/etc/pam.d/sudo")
        if not real.exists():
            self.skipTest("no /etc/pam.d/sudo")
        text = pamconfig.read_service_file(real)  # read only
        if not pamconfig.is_enabled(text):
            self.assertEqual(pamconfig.remove(pamconfig.add(text, SUDO)), text)


if __name__ == "__main__":
    unittest.main()

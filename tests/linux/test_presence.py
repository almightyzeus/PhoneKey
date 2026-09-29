"""Local-presence rules for sudo approvals (SECURITY.md R-8, D-15)."""

import tempfile
import unittest
from pathlib import Path

from phonekey import presence
from phonekey.presence import Session, decide, decide_unlock

ME = "alice"
LOCAL = Session(ME, remote=False, active=True, seat="seat0")
SSH = Session(ME, remote=True, active=True, seat="")


class DecideTest(unittest.TestCase):
    # Process inside a logind session
    def test_local_active_session_allowed(self):
        self.assertIsNone(decide(ME, LOCAL, has_tty=False, local_sessions=[]))

    def test_ssh_session_refused(self):
        self.assertIn("remote", decide(ME, SSH, has_tty=True, local_sessions=[LOCAL]))

    def test_other_users_session_refused(self):
        self.assertIsNotNone(decide(ME, Session("bob", False, True, "seat0"), True, [LOCAL]))

    def test_background_session_refused(self):
        self.assertIsNotNone(decide(ME, Session(ME, False, False, "seat0"), True, [LOCAL]))

    # Process outside any session (desktop terminals run under user@UID.service)
    def test_terminal_while_logged_in_locally_allowed(self):
        self.assertIsNone(decide(ME, None, has_tty=True, local_sessions=[LOCAL]))

    def test_no_terminal_refused(self):  # cron, systemd services, scripts without a tty
        self.assertIn("no terminal", decide(ME, None, has_tty=False, local_sessions=[LOCAL]))

    def test_terminal_without_local_login_refused(self):
        for sessions in ([], [SSH], [Session(ME, False, False, "seat0")], [Session(ME, False, True, "")],
                         [Session("bob", False, True, "seat0")]):
            with self.subTest(sessions=sessions):
                self.assertIsNotNone(decide(ME, None, has_tty=True, local_sessions=sessions))


class UnlockTest(unittest.TestCase):
    """D-16: Cinnamon's PAM helper has no session and no terminal; the account must be at the seat."""

    def test_active_local_session_allowed(self):
        self.assertIsNone(decide_unlock(ME, [SSH, LOCAL]))

    def test_refused_without_a_local_active_seat_session(self):
        for sessions in ([], [SSH], [Session(ME, False, False, "seat0")], [Session(ME, False, True, "")],
                         [Session("bob", False, True, "seat0")]):
            with self.subTest(sessions=sessions):
                self.assertIsNotNone(decide_unlock(ME, sessions))

    def test_checker_uses_unlock_rule_without_tty_or_session(self):
        proc = Path(tempfile.mkdtemp())  # no /proc entry at all: tty and session are irrelevant
        check = presence.checker(FakeLogind(sessions=[LOCAL]), proc)
        self.assertIsNone(check(4242, ME, "linux.unlock"))
        self.assertIsNotNone(check(4242, ME, "linux.sudo"))  # sudo still needs a terminal
        self.assertIsNotNone(presence.checker(FakeLogind(sessions=[SSH]), proc)(4242, ME, "linux.unlock"))

    def test_unlock_lookup_failure_refuses(self):
        class Broken(FakeLogind):
            def sessions(self):
                raise RuntimeError("bus down")
        self.assertIn("cannot determine", presence.checker(Broken())(1, ME, "linux.unlock"))


class TtyTest(unittest.TestCase):
    def setUp(self):
        self.proc = Path(tempfile.mkdtemp())

    def stat(self, pid, comm, tty_nr):
        (self.proc / str(pid)).mkdir()
        (self.proc / str(pid) / "stat").write_text(f"{pid} ({comm}) S 1 {pid} {pid} {tty_nr} -1 4194560 0 0\n")

    def test_tty(self):
        self.stat(10, "sudo", 34817)
        self.stat(11, "sudo", 0)
        self.assertTrue(presence.has_tty(10, self.proc))
        self.assertFalse(presence.has_tty(11, self.proc))

    def test_tricky_command_names(self):
        self.stat(12, "a) S 1 2 3 99 (b", 0)  # a name that looks like more fields
        self.assertFalse(presence.has_tty(12, self.proc))

    def test_missing_or_garbage(self):
        self.assertFalse(presence.has_tty(99, self.proc))
        (self.proc / "13").mkdir()
        (self.proc / "13" / "stat").write_text("garbage")
        self.assertFalse(presence.has_tty(13, self.proc))


class FakeLogind:
    def __init__(self, session=None, sessions=(), error=None):
        self.session, self._sessions, self.error = session, list(sessions), error

    def session_of(self, pid):
        if self.error:
            raise self.error
        return self.session

    def sessions(self):
        return self._sessions


class CheckerTest(unittest.TestCase):
    def test_logind_failure_refuses(self):
        check = presence.checker(FakeLogind(error=RuntimeError("bus down")))
        self.assertIn("cannot determine", check(1, ME))

    def test_combines_facts(self):
        proc = Path(tempfile.mkdtemp())
        (proc / "5").mkdir()
        (proc / "5" / "stat").write_text("5 (sudo) S 1 5 5 34817 -1\n")
        self.assertIsNone(presence.checker(FakeLogind(sessions=[LOCAL]), proc)(5, ME))
        self.assertIsNotNone(presence.checker(FakeLogind(sessions=[SSH]), proc)(5, ME))
        self.assertIsNotNone(presence.checker(FakeLogind(session=SSH, sessions=[LOCAL]), proc)(5, ME))


if __name__ == "__main__":
    unittest.main()

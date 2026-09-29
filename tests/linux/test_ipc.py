"""Local IPC authorization (SECURITY.md T-7: unprivileged local attackers)."""

import os
import pwd
import unittest

from phonekey.daemon import ACTIONS, LOCAL_ONLY, authorize, pairable_account, parse_request

ME = os.getuid()
MY_NAME = pwd.getpwuid(ME).pw_name
OTHER_UID = 0 if ME != 0 else 1


def check(op, uid, account=None, *, system_mode):
    return authorize(op, uid, account, daemon_uid=ME, system_mode=system_mode)


class AuthorizeTest(unittest.TestCase):
    def test_status_is_open(self):
        self.assertIsNone(check("status", 12345, system_mode=True))

    def test_auth_only_for_own_account(self):
        for system_mode in (False, True):
            with self.subTest(system_mode=system_mode):
                self.assertIsNone(check("auth", ME, MY_NAME, system_mode=system_mode))
                if ME != 0:
                    self.assertIsNotNone(check("auth", ME, "root", system_mode=system_mode))
                    self.assertIsNotNone(check("auth", ME, None, system_mode=system_mode))

    def test_sudo_action_only_from_root(self):
        if ME != 0:
            self.assertIsNotNone(authorize("auth", ME, MY_NAME, daemon_uid=ME, system_mode=True, action="sudo"))
            self.assertIsNone(authorize("auth", ME, MY_NAME, daemon_uid=ME, system_mode=True, action="test"))
        self.assertIsNone(authorize("auth", 0, "someone", daemon_uid=ME, system_mode=True, action="sudo"))

    def test_root_may_authenticate_any_account(self):
        self.assertIsNone(check("auth", 0, "someone", system_mode=True))

    def test_unknown_uid_refused(self):
        self.assertIsNotNone(check("auth", 2**31 - 7, "nobody-here", system_mode=True))

    def test_pairing_requires_root_in_system_mode(self):
        if ME != 0:
            self.assertIsNotNone(check("pair", ME, system_mode=True))
        self.assertIsNone(check("pair", 0, system_mode=True))

    def test_pairing_in_dev_mode_only_for_daemon_owner(self):
        self.assertIsNone(check("pair", ME, system_mode=False))
        self.assertIsNotNone(check("pair", ME + 1, system_mode=False))

    def test_pairing_in_dev_mode_only_for_own_account(self):
        self.assertIsNone(check("pair", ME, MY_NAME, system_mode=False))
        if ME != 0:
            self.assertIsNotNone(check("pair", ME, "root", system_mode=False))

    def test_pairable_accounts(self):
        self.assertIsNone(pairable_account(MY_NAME) if ME != 0 else None)
        self.assertIsNotNone(pairable_account("root"))
        self.assertIsNotNone(pairable_account("no-such-user-phonekey"))
        self.assertIsNotNone(pairable_account(["list"]))

    def test_unknown_operation_refused(self):
        self.assertIsNotNone(check("unpair", 0, system_mode=True))

    def test_sudo_and_unlock_need_local_presence(self):
        self.assertEqual({"linux.sudo", "linux.unlock"}, LOCAL_ONLY)

    def test_actions_are_a_fixed_set(self):
        self.assertEqual({"phonekey.test", "linux.sudo", "linux.unlock", "linux.login"}, set(ACTIONS.values()))


class ParseRequestTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_request(b'{"op": "auth", "action": "sudo", "account": "a"}')["op"], "auth")
        self.assertEqual(parse_request(b'{"op": "status"}'), {"op": "status"})

    def test_malformed_requests_are_rejected_not_crashing(self):
        for line in (b"", b"not json", b"\xff\xfe", b"[]", b'"op"', b"42", b"{}", b'{"op": 1}',
                     b'{"op": "auth", "action": []}', b'{"op": "auth", "action": {"a": 1}}',
                     b'{"op": "auth", "account": null}', b'{"op": "pair", "account": 5}'):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    parse_request(line)


if __name__ == "__main__":
    unittest.main()

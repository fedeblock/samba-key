import subprocess
import unittest
from unittest.mock import patch

from samba_key.auth import CredentialVerifier


class CredentialVerifierTests(unittest.TestCase):
    def _verifier(self, transport):
        return CredentialVerifier('samba', share='skverify', transport=transport)

    def test_password_goes_through_command_not_argv(self):
        # The command the transport builds must never contain the password.
        v = self._verifier(lambda u, p: 0)
        cmd = v._command('alice')
        self.assertNotIn('secret password 12', cmd)
        self.assertIn('//samba/skverify', cmd)
        self.assertIn('alice', cmd)
        self.assertIn('-U', cmd)

    def test_verify_true_only_on_clean_return(self):
        v = self._verifier(lambda u, p: 0)
        self.assertTrue(v.verify('alice', 'a-real-password-12'))
        v2 = self._verifier(lambda u, p: 1)
        self.assertFalse(v2.verify('alice', 'wrong-password-12'))

    def test_fails_closed_on_timeout_or_error(self):
        def boom(u, p):
            raise subprocess.TimeoutExpired('smbclient', 10)

        def oser(u, p):
            raise OSError('no smbclient installed')

        self.assertFalse(self._verifier(boom).verify('alice', 'a-real-password-12'))
        self.assertFalse(self._verifier(oser).verify('alice', 'a-real-password-12'))

    def test_rejects_malformed_username_and_password(self):
        called = []
        v = self._verifier(lambda u, p: called.append((u, p)) or 0)
        for user, pw in [('-admin', 'x'), ('alice%bad', 'x'), ('root', 'x'),
                         ('alice', ''), ('alice', 'has\nnewline'), ('alice', 'has\0null'),
                         ('alice', 'x' * 2000)]:
            self.assertFalse(v.verify(user, pw))
        self.assertEqual(called, [])

    def test_guest_empty_password_rejected_before_exec(self):
        called = []
        v = self._verifier(lambda u, p: called.append((u, p)) or 0)
        self.assertFalse(v.verify('alice', ''))
        self.assertEqual(called, [])

    def test_password_never_logged_on_failure(self):
        def transport(u, p):
            return 1
        v = self._verifier(transport)
        with self.assertLogs('samba_key.auth', level='WARNING') as records:
            self.assertFalse(v.verify('alice', 'secret password 12'))
        self.assertFalse(any('secret password 12' in line for line in records.output))

    # --- canary ---
    def test_canary_detects_guest_accepting_verifier(self):
        # A verifier that (mis)accepts everything must fail the canary.
        permissive = self._verifier(lambda u, p: 0)
        self.assertFalse(permissive.canary_ok())

    def test_canary_passes_when_unknown_user_fails(self):
        strict = self._verifier(lambda u, p: 1)
        self.assertTrue(strict.canary_ok())


if __name__ == '__main__':
    unittest.main()

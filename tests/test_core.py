import unittest
from unittest.mock import patch
import subprocess

from samba_key.core import PasswordChanger, AttemptLimiter


class PasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self.changer = PasswordChanger('samba')

    @patch('samba_key.core.subprocess.run')
    def test_passwords_are_sent_through_stdin(self, run):
        run.return_value.returncode = 0
        self.assertTrue(self.changer.change('alice', 'current-old-1', 'brand-new-12'))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['smbpasswd', '-s', '-r', 'samba', '-U', 'alice'])
        self.assertEqual(kwargs['input'], 'current-old-1\nbrand-new-12\nbrand-new-12\n')
        self.assertNotIn('current-old-1', str(args))

    @patch('samba_key.core.subprocess.run')
    def test_failed_or_timed_out_change_fails_closed(self, run):
        run.return_value.returncode = 1
        self.assertFalse(self.changer.change('alice', 'wrong-old-1', 'another-new-1'))
        run.side_effect = subprocess.TimeoutExpired('smbpasswd', 10)
        self.assertFalse(self.changer.change('alice', 'wrong-old-1', 'another-new-1'))

    @patch('samba_key.core.subprocess.run')
    def test_error_logging_records_only_safe_status(self, run):
        run.return_value.returncode = 1
        run.return_value.stderr = 'secret-user and secret-password: NT_STATUS_PASSWORD_RESTRICTION\n'
        with self.assertLogs('samba_key.core', level='WARNING') as records:
            self.assertFalse(self.changer.change('alice', 'valid-old-password', 'valid-new-password'))
        self.assertIn('NT_STATUS_PASSWORD_RESTRICTION', records.output[0])
        self.assertNotIn('secret-', records.output[0])

    @patch('samba_key.core.subprocess.run')
    def test_rejects_protocol_injection_and_option_username(self, run):
        for user, old, new in [('-admin', 'x' * 12, 'y' * 12), ('alice%bad', 'x' * 12, 'y' * 12), ('alice', 'bad\nother', 'x' * 12), ('alice', 'x' * 12, 'new\nsecond')]:
            self.assertFalse(self.changer.change(user, old, new))
        run.assert_not_called()

    def test_min_length_policy_rejects_short_passwords(self):
        short = PasswordChanger('samba', min_length=12)
        self.assertFalse(short.policy_ok('short', 'shorter'))
        self.assertTrue(short.policy_ok('old-enough-1', 'new-enough-12'))
        self.assertFalse(short.policy_ok('ok', 'new\nline'))

    @patch('samba_key.core.subprocess.run')
    def test_short_old_password_can_change_to_a_valid_new_password(self, run):
        # The minimum length applies to the NEW password only. A user whose
        # current Samba password is shorter than the minimum must still be able
        # to change it to a compliant one.
        run.return_value.returncode = 0
        self.assertTrue(self.changer.change('alice', 'short', 'a-valid-new-password'))
        args, kwargs = run.call_args
        self.assertEqual(kwargs['input'], 'short\na-valid-new-password\na-valid-new-password\n')

    def test_old_password_is_only_checked_for_protocol_safety(self):
        changer = PasswordChanger('samba', min_length=12)
        self.assertTrue(changer.policy_ok('short', 'a-valid-new-password'))
        self.assertFalse(changer.policy_ok('', 'a-valid-new-password'))
        self.assertFalse(changer.policy_ok('old\nline', 'a-valid-new-password'))
        self.assertFalse(changer.policy_ok('old\0line', 'a-valid-new-password'))
        self.assertFalse(changer.policy_ok('a-valid-old', 'short'))

    def test_long_current_password_can_change_to_a_short_compliant_new(self):
        # A current password longer than the new-password maximum (here 8 bytes)
        # is within the generous current-password cap, so the change is allowed
        # to a compliant new password. The new policy must not block it.
        changer = PasswordChanger('samba', min_length=6, max_length=8, max_current_length=64)
        old = 'A' * 40  # 40 bytes: > max_length (8), < max_current_length (64)
        self.assertTrue(changer.policy_ok(old, 'new-one'))

    def test_current_password_beyond_technical_cap_is_rejected(self):
        # Beyond the technical cap the current password cannot be processed
        # safely; it is rejected before contacting the server.
        changer = PasswordChanger('samba', min_length=6, max_length=8, max_current_length=8)
        old = 'A' * 64  # 64 bytes > max_current_length (8)
        self.assertFalse(changer.policy_ok(old, 'new-one'))

    @patch('samba_key.core.subprocess.run')
    def test_long_current_password_reaches_the_server(self, run):
        run.return_value.returncode = 0
        changer = PasswordChanger('samba', min_length=6, max_length=8, max_current_length=64)
        old = 'A' * 40
        self.assertTrue(changer.change('alice', old, 'new-one'))
        args, kwargs = run.call_args
        self.assertEqual(kwargs['input'], f'{old}\nnew-one\nnew-one\n')

    def test_limiter_limits_and_expires(self):
        limiter = AttemptLimiter(limit=2, window=60)
        self.assertTrue(limiter.allow('client', now=0))
        self.assertTrue(limiter.allow('client', now=1))
        self.assertFalse(limiter.allow('client', now=2))
        self.assertTrue(limiter.allow('client', now=61))


if __name__ == '__main__':
    unittest.main()

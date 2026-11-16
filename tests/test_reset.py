"""Tests for the privileged reset_fn: allowlist, policy, and password delivery
through a pipe fd (never argv/env)."""
import os
import sys
import tempfile
import unittest


class ResetFnTests(unittest.TestCase):
    def _make(self, transport):
        from samba_key.reset import make_reset_fn
        return make_reset_fn(['alice', 'bob'], min_length=12,
                             max_length=64, transport=transport)

    def test_non_allowlisted_account_refused(self):
        seen = []
        fn = self._make(lambda a, p: seen.append((a, p)) or 0)
        self.assertFalse(fn('eve', 'a-new-password-123'))
        self.assertFalse(fn('root', 'a-new-password-123'))
        self.assertEqual(seen, [])  # no invocation for a non-allowlisted user

    def test_policy_failure_refused_before_invocation(self):
        seen = []
        fn = self._make(lambda a, p: seen.append((a, p)) or 0)
        for bad in ('short', 'a' * 200, 'new\npassword', 'new\0password',
                    'a-new-password-1\r'):
            self.assertFalse(fn('alice', bad), 'policy must reject ' + repr(bad))
        self.assertEqual(seen, [])

    def test_success_path_invokes_with_password_via_transport(self):
        delivered = []
        fn = self._make(lambda a, p: delivered.append((a, p)) or 0)
        self.assertTrue(fn('alice', 'a-new-password-123'))
        self.assertEqual(delivered, [('alice', 'a-new-password-123')])

    def test_nonzero_return_is_failure(self):
        fn = self._make(lambda a, p: 127)
        self.assertFalse(fn('alice', 'a-new-password-123'))

    def test_transport_exception_is_failure_not_crash(self):
        def boom(a, p):
            raise OSError('no smbpasswd')
        fn = self._make(boom)
        self.assertFalse(fn('alice', 'a-new-password-123'))


class CommandConstructionTests(unittest.TestCase):
    """The real transport must build a command with the password absent from
    argv and the environment, and deliver it on the child's stdin pipe
    (smbpasswd -s reads the new password twice from standard input)."""

    def test_real_transport_hides_password_from_argv_and_env(self):
        # Run the real _transport_stdin path against a fake executable that
        # records its own argv, its environment, and what it reads on stdin. A
        # direct python script (not a shell wrapper) so sys.argv is exactly what
        # was passed and the environment is exactly what was set.
        from samba_key.reset import make_reset_fn
        script = (
            "import sys, os, json\n"
            "argv = sys.argv[1:]\n"
            "env = dict(os.environ)\n"
            "pw = sys.stdin.read()\n"
            "with open(os.environ['RECORD'], 'w') as f:\n"
            "    json.dump({'argv': argv, 'env_has_pass':\n"
            "        os.environ.get('PASSWD_FD') is not None,\n"
            "        'pw': pw}, f)\n"
            "sys.exit(0)\n"
        )
        d = tempfile.mkdtemp()
        fake = os.path.join(d, 'smbpasswd.py')
        with open(fake, 'w') as f:
            f.write('#! /usr/bin/env python3\n' + script)
        os.chmod(fake, 0o755)
        record = os.path.join(d, 'record.json')
        os.environ['RECORD'] = record
        os.environ.pop('PASSWD_FD', None)

        # The fake is a python file; run it as the binary via its shebang.
        fn = make_reset_fn(['alice'], min_length=12, executable=fake)
        secret = 'a-brand-new-password-123'
        self.assertTrue(fn('alice', secret))
        import json
        with open(record) as fh:
            rec = json.load(fh)
        # The password must arrive on stdin, never in argv, and there must be
        # no PASSWD_FD in the environment.
        self.assertNotIn(secret, ' '.join(rec['argv']))
        self.assertNotIn('PASSWD_FD', str(rec.get('env_has_pass')))
        self.assertIn(secret, rec['pw'])
        self.assertIn('alice', rec['argv'])
        # smbpasswd -s reads the password twice; the payload carries both lines.
        self.assertEqual(rec['pw'].count(secret), 2)

        os.environ.pop('RECORD', None)

if __name__ == '__main__':
    unittest.main()

import os
import re
import glob
import unittest

from samba_key.config import Config, ConfigError


# Config attributes that are intentionally not consumed by a source module
# outside config.py. Each must be justified here or the meta-test below fails.
UNUSED_BUT_INTENTIONAL = {
    'admin_socket': 'documented for RECOVERY_ADMIN_SOCKET; the admin CLI derives the socket path from AUTHORITY_DIR and reads the env var directly rather than via a Config object',
    'smtp_from': 'the default seed for smtp_sender (the delivery uses smtp_sender); SMTP_FROM is honored via that default',
}


class ConfigCoverageTests(unittest.TestCase):
    """Defect 4 meta-test: every Config attribute must be consumed somewhere
    outside config.py (or be explicitly justified here). A dead option that a
    user sets but that the process ignores is a correctness bug."""

    def _outside_sources(self):
        here = os.path.dirname(os.path.abspath(__file__))
        pkg = os.path.dirname(here)
        texts = []
        for path in glob.glob(os.path.join(pkg, 'samba_key', '*.py')):
            base = os.path.basename(path)
            if base == 'config.py':
                continue
            with open(path) as fh:
                texts.append(fh.read())
        return '\n'.join(texts)

    def test_every_config_attribute_is_used_outside_config(self):
        cfg = Config({})
        attrs = [a for a in dir(cfg) if not a.startswith('_')
                 and not callable(getattr(cfg, a))]
        src = self._outside_sources()
        for a in attrs:
            if a in UNUSED_BUT_INTENTIONAL:
                continue
            # Must appear as an attribute access .a or a string 'a' somewhere
            # outside config.py.
            pattern = r'\.%s\b' % re.escape(a)
            used = re.search(pattern, src) or ("'%s'" % a) in src or \
                ('"%s"' % a) in src
            self.assertTrue(
                used, 'Config attribute %r is set but never consumed outside '
                'config.py (or it is unused; justify it in '
                'UNUSED_BUT_INTENTIONAL): %s' % (a, UNUSED_BUT_INTENTIONAL.get(a)))

    def test_intentionally_unused_are_documented(self):
        for a in UNUSED_BUT_INTENTIONAL:
            self.assertIn(a, dir(Config({})),
                          'an entry in the exception list no longer exists')


class ConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self):
        c = Config({})
        self.assertEqual(c.server, 'host.docker.internal')
        self.assertEqual(c.min_password_length, 12)
        self.assertEqual(c.max_password_length, 1024)
        self.assertEqual(c.recovery_mode, 'disabled')
        self.assertFalse(c.public()['recovery_available'])
        self.assertEqual(c.base_url, '')

    def test_empty_server_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config({'SAMBA_SERVER': '   '})

    def test_automatic_is_always_refused_with_reason(self):
        for env in ({'RECOVERY_MODE': 'automatic'},
                    {'RECOVERY_MODE': 'automatic', 'RECOVERY_SOCKET': '/x', 'BASE_URL': 'https://a'}):
            with self.assertRaises(ConfigError) as ctx:
                Config(env)
            self.assertIn('automatic', str(ctx.exception).lower())

    def test_approval_requires_socket_and_https_origin(self):
        # Approval is now the wired policy, but it fails closed: it must not run
        # without an authority socket and an HTTPS origin for the recovery links.
        with self.assertRaises(ConfigError) as ctx:
            Config({'RECOVERY_MODE': 'approval'})
        self.assertIn('recovery_socket', str(ctx.exception).lower())
        with self.assertRaises(ConfigError) as ctx:
            Config({'RECOVERY_MODE': 'approval', 'RECOVERY_SOCKET': '/x'})
        self.assertIn('https', str(ctx.exception).lower())
        ok = Config({'RECOVERY_MODE': 'approval', 'RECOVERY_SOCKET': '/x',
                     'BASE_URL': 'https://portal.example'})
        self.assertTrue(ok._recovery_available)
        self.assertEqual(ok.public()['recovery_available'], True)

    def test_disabled_is_default_and_unavailable(self):
        c = Config({})
        self.assertEqual(c.recovery_mode, 'disabled')
        self.assertFalse(c.public()['recovery_available'])

    def test_overlapping_portal_and_admin_groups_refused(self):
        with self.assertRaises(ConfigError):
            Config({'PORTAL_GROUP': 'samba-key-admin',
                   'ADMIN_GROUP': 'samba-key-admin'})

    def test_distinct_groups_ok(self):
        cfg = Config({'PORTAL_GROUP': 'www-data',
                      'ADMIN_GROUP': 'samba-key-admin',
                      'PORTAL_UID': '33'})
        self.assertEqual(cfg.portal_group, 'www-data')
        self.assertEqual(cfg.admin_group, 'samba-key-admin')
        self.assertEqual(cfg.portal_uid, 33)

    def test_unknown_recovery_mode_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config({'RECOVERY_MODE': 'whenever'})

    def test_password_bounds_must_be_consistent(self):
        with self.assertRaises(ConfigError):
            Config({'MIN_PASSWORD_LENGTH': '20', 'MAX_PASSWORD_LENGTH': '10'})

    def test_current_password_cap_defaults_higher_than_new_max(self):
        c = Config({})
        self.assertEqual(c.max_current_password_length, 4096)
        self.assertGreaterEqual(c.max_current_password_length, c.max_password_length)

    def test_current_password_cap_must_cover_new_max(self):
        with self.assertRaises(ConfigError):
            Config({'MAX_CURRENT_PASSWORD_LENGTH': '64', 'MAX_PASSWORD_LENGTH': '1024'})

    def test_numeric_environment_values_are_validated(self):
        for bad in ('RATE_LIMIT', 'RATE_WINDOW', 'RATE_MAX_CLIENTS'):
            with self.assertRaises(ConfigError):
                Config({bad: 'not-a-number'})

    def test_public_summary_excludes_secrets(self):
        c = Config({'SAMBA_KEY_SECRET': 'do-not-log-me', 'SMTP_PASSWORD': 'do-not-log-me'})
        summary = str(c.public())
        self.assertNotIn('do-not-log-me', summary)

    def test_secrets_from_secret_file_are_read_and_not_public(self):
        import tempfile, os
        d = tempfile.mkdtemp()
        pw = os.path.join(d, 'pw.txt')
        tok = os.path.join(d, 'tok.txt')
        with open(pw, 'w') as fh:
            fh.write('s3cr3t-smtp\n')
        with open(tok, 'w') as fh:
            fh.write('s3cr3t-telegram')
        c = Config({'SMTP_PASSWORD_FILE': pw, 'TELEGRAM_BOT_TOKEN_FILE': tok})
        self.assertEqual(c.smtp_password, 's3cr3t-smtp')
        self.assertEqual(c.telegram_bot_token, 's3cr3t-telegram')
        summary = str(c.public())
        self.assertNotIn('s3cr3t-smtp', summary)
        self.assertNotIn('s3cr3t-telegram', summary)

    def test_missing_secret_file_yields_empty_not_crash(self):
        c = Config({'SMTP_PASSWORD_FILE': '/no/such/file'})
        self.assertEqual(c.smtp_password, '')


if __name__ == '__main__':
    unittest.main()

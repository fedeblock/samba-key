import io
import os
import tempfile
import unittest
from pathlib import Path

from samba_key.contacts import ContactError, load_contacts, run


class ContactsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'contacts.toml'
        self.path.write_text('''[[users]]
username = "alice"
name = "Alice Example"
email = "alice@example.test"
phone = "+44 20 1234 5678"
''')
        self.path.chmod(0o600)

    def test_loads_private_contact_record(self):
        contact = load_contacts(self.path)['alice']
        self.assertEqual(contact['email'], 'alice@example.test')
        self.assertEqual(contact['phone'], '+44 20 1234 5678')

    def test_rejects_world_readable_or_symlinked_file(self):
        self.path.chmod(0o644)
        with self.assertRaises(ContactError):
            load_contacts(self.path)
        self.path.chmod(0o600)
        link = self.path.parent / 'link.toml'
        link.symlink_to(self.path)
        with self.assertRaises(ContactError):
            load_contacts(link)

    def test_duplicate_or_invalid_username_is_rejected(self):
        self.path.write_text('[[users]]\nusername="../root"\n')
        with self.assertRaises(ContactError):
            load_contacts(self.path)
        self.path.write_text('[[users]]\nusername="alice"\n[[users]]\nusername="alice"\n')
        with self.assertRaises(ContactError):
            load_contacts(self.path)

    def test_email_enrollment_uses_saved_address_and_is_not_auto_verified(self):
        class FakeAdmin:
            def channel_add(inner, account, kind, value):
                inner.called = (account, kind, value)
                return 'one-time-code'
        admin = FakeAdmin()
        output = io.StringIO()
        rc = run(['enroll', 'alice', 'email'], self.path, admin, output)
        self.assertEqual(rc, 0)
        self.assertEqual(admin.called, ('alice', 'email', 'alice@example.test'))
        self.assertIn('one-time-code', output.getvalue())
        self.assertNotIn('verified', output.getvalue().lower())

    def test_phone_is_never_used_as_telegram_chat_id(self):
        class FakeAdmin:
            def channel_add(inner, account, kind, value):
                inner.called = (account, kind, value)
                return 'one-time-code'
        admin = FakeAdmin()
        self.assertEqual(run(['enroll', 'alice', 'telegram'], self.path,
                             admin, io.StringIO()), 0)
        self.assertEqual(admin.called, ('alice', 'telegram', ''))

    def test_email_verification_uses_private_prompt_and_saved_address(self):
        from unittest.mock import patch
        class FakeAdmin:
            def channel_verify(inner, *args):
                inner.called = args
                return True
        admin = FakeAdmin()
        with patch('samba_key.contacts.getpass.getpass', return_value='secret-code'):
            rc = run(['verify', 'alice', 'email'], self.path, admin, io.StringIO())
        self.assertEqual(rc, 0)
        self.assertEqual(admin.called, ('alice', 'email', 'alice@example.test', 'secret-code'))

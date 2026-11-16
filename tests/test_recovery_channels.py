"""The request selects only a registered channel type, never a destination."""
import unittest
import os
import sqlite3
import tempfile
from unittest.mock import patch

from samba_key.delivery_worker import DeliveryWorker
from samba_key.reset_auth import ResetAuthority, Role
from samba_key.store import Store


class RecoveryChannelTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.store.bind_channel('alice', 'email', 'alice@example.test')
        self.store.bind_channel('alice', 'telegram', '12345678')
        self.authority = ResetAuthority(self.store, {'alice'}, lambda *args: True,
                                        principals=lambda peer: Role.PORTAL)
        self.sent = []

    def _request(self, channel):
        return self.authority.dispatch(Role.PORTAL, 'MINT',
                                       {'account': 'alice', 'channel': channel})

    def test_telegram_choice_delivers_only_to_registered_telegram(self):
        result = self._request('telegram')
        self.assertTrue(result['ok'])
        self.assertTrue(self.store.approve(result['handle']))
        class Delivery:
            def send(inner, kind, target, subject, body):
                self.sent.append((kind, target, body.split('#t=')[1]))
        self.assertEqual(DeliveryWorker(self.store, Delivery(), 'https://example.test').deliver_pending(), 1)
        self.assertEqual(self.sent[0][:2], ('telegram', '12345678'))
        self.assertTrue(self.authority.dispatch(Role.PORTAL, 'CONSUME', {
            'token': self.sent[0][2], 'new_password': 'a-strong-password'})['ok'])

    def test_missing_selected_channel_is_never_substituted(self):
        self.store.revoke_channel('alice', 'telegram')
        result = self._request('telegram')
        self.assertTrue(result['ok'])
        self.assertTrue(self.store.approve(result['handle']))
        class Delivery:
            def send(inner, *args):
                self.fail('a missing Telegram channel must never send e-mail')
        self.assertEqual(DeliveryWorker(self.store, Delivery(), 'https://example.test').deliver_pending(), 0)

    def test_untrusted_portal_cannot_supply_an_address(self):
        result = self.authority.dispatch(Role.PORTAL, 'MINT', {
            'account': 'alice', 'channel': 'telegram', 'value': 'attacker@example.test'})
        self.assertFalse(result['ok'])

    def test_form_displays_channel_choice_when_enabled(self):
        from samba_key.app import create_app
        with patch.dict('os.environ', {'RECOVERY_MODE': 'disabled'}):
            body = create_app(recovery_service=object()).test_client().get(
                '/recovery?lang=es').get_data(as_text=True)
        self.assertIn('name="channel"', body)
        self.assertIn('value="email"', body)
        self.assertIn('value="telegram"', body)

    def test_web_form_passes_only_the_chosen_channel_type(self):
        import re
        from samba_key.app import create_app
        class Capture:
            def request(inner, username, client, channel):
                inner.result = (username, channel)
                return {'status': 'generic'}
        capture = Capture()
        with patch.dict('os.environ', {'RECOVERY_MODE': 'disabled'}):
            client = create_app(recovery_service=capture).test_client()
            page = client.get('/recovery?lang=es', base_url='https://portal.example')
            csrf = re.search(r'name="csrf" value="([^"]+)"',
                             page.get_data(as_text=True)).group(1)
            result = client.post('/recovery?lang=es', base_url='https://portal.example',
                                 data={'csrf': csrf, 'username': 'alice', 'channel': 'telegram'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(capture.result, ('alice', 'telegram'))

    def test_admin_sees_the_selected_masked_destination(self):
        result = self._request('telegram')
        listing = self.authority.dispatch(Role.ADMIN, 'LIST', {})['requests']
        self.assertEqual(listing[0]['channel'], 'telegram')
        self.assertEqual(listing[0]['destination'], '***5678')
        self.assertNotIn('12345678', str(listing))

    def test_existing_store_is_migrated_without_losing_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'old.db')
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE requests (handle TEXT PRIMARY KEY, account TEXT NOT NULL, '
                         'kind TEXT NOT NULL, binding_fingerprint TEXT NOT NULL DEFAULT "", '
                         'token_digest TEXT UNIQUE, status TEXT NOT NULL, issued INTEGER NOT NULL, '
                         'created_at REAL NOT NULL, expires_at REAL NOT NULL)')
            conn.execute('INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         ('old', 'alice', 'recovery', '', None, 'pending', 0, 1, 9999999999))
            conn.commit()
            conn.close()
            store = Store(path)
            self.addCleanup(store.close)
            request = store.pending_requests()[0]
            self.assertEqual((request.handle, request.channel), ('old', 'auto'))

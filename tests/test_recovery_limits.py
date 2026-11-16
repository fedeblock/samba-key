"""Recovery client-cap behaviour across requests and expiration."""
import unittest
import os
import tempfile
import threading

from samba_key.recovery import RecoveryService
from samba_key.reset_auth import ResetAuthority, ResetClient, Role, _serve_one
from samba_key.store import Store


class _Authority:
    def mint(self, username):
        return None


class RecoveryClientCapTests(unittest.TestCase):
    def test_short_password_reports_policy_without_consuming_token(self):
        class Authority:
            def consume(self, *args):
                raise AssertionError('short password must not consume token')
        store = Store(':memory:')
        self.addCleanup(store.close)
        service = RecoveryService(Authority(), store, 'https://example.test', policy_min=12)
        self.assertEqual(service.complete('token', 'short', 'client-a')['status'], 'short_password')

    def test_reset_form_displays_configured_minimum(self):
        from unittest.mock import patch
        from samba_key.app import create_app
        import re
        class Service:
            def complete(self, *args):
                return {'status': 'short_password'}
        with patch.dict(os.environ, {'RECOVERY_MODE': 'disabled', 'MIN_PASSWORD_LENGTH': '14'}):
            client = create_app(recovery_service=Service()).test_client()
            page = client.get('/reset?lang=es', base_url='https://portal.example')
            csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()
            response = client.post('/reset?lang=es', base_url='https://portal.example',
                                   data={'csrf': csrf, 'token': 'anything', 'new_password': 'short'})
        self.assertIn('al menos 14 caracteres', response.get_data(as_text=True))
        self.assertNotIn('enlace no es válido', response.get_data(as_text=True))
        self.assertIn('value="anything"', response.get_data(as_text=True))

    def test_details_endpoint_requires_csrf_and_only_returns_safe_fields(self):
        from unittest.mock import patch
        from samba_key.app import create_app
        import re
        class Service:
            def details(self, token, client):
                if token == 'valid':
                    return {'account': 'alice', 'channel': 'email',
                            'destination': 'a***e@example.test', 'internal': 'never expose'}
                return None
        with patch.dict(os.environ, {'RECOVERY_MODE': 'disabled'}):
            client = create_app(recovery_service=Service()).test_client()
            page = client.get('/reset?lang=es', base_url='https://portal.example')
            csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()
            rejected = client.post('/reset/details', base_url='https://portal.example',
                                   data={'token': 'valid'})
            self.assertEqual(rejected.status_code, 403)
            ok = client.post('/reset/details', base_url='https://portal.example',
                             data={'csrf': csrf, 'token': 'valid'})
            self.assertEqual(ok.json, {'account': 'alice', 'channel': 'email',
                                       'destination': 'a***e@example.test'})
            self.assertEqual(ok.headers['Cache-Control'], 'no-store')
            invalid = client.post('/reset/details', base_url='https://portal.example',
                                  data={'csrf': csrf, 'token': 'wrong'})
            self.assertEqual(invalid.json, {})

    def test_unhashable_opcode_is_refused(self):
        authority = ResetAuthority(None, [], None, principals=lambda peer: Role.PORTAL)
        self.assertFalse(authority.dispatch(Role.PORTAL, [], {}).get('ok'))

    def test_non_object_request_does_not_crash_authority(self):
        import struct
        from unittest.mock import MagicMock, patch
        conn = MagicMock()
        with patch('samba_key.reset_auth._recv_all',
                   side_effect=[struct.pack('>I', 2), b'[]']):
            _serve_one(conn, Role.PORTAL, MagicMock(), 1)

    def test_disconnected_client_does_not_kill_authority_socket(self):
        from unittest.mock import MagicMock, patch
        stop = threading.Event()
        conn = MagicMock()
        server = MagicMock()
        server.accept.return_value = (conn, None)
        authority = ResetAuthority(None, [], None, principals=lambda peer: Role.PORTAL,
                                   peer_credential=lambda connection: (123, 123))
        def disconnect(*args):
            stop.set()
            raise BrokenPipeError('client disconnected')
        with patch('samba_key.reset_auth.socket.socket', return_value=server), \
             patch('samba_key.reset_auth.os.path.exists', return_value=False), \
             patch('samba_key.reset_auth.os.chmod'), \
             patch('samba_key.reset_auth.os.unlink'), \
             patch('samba_key.reset_auth._serve_one', side_effect=disconnect):
            authority.serve('/fake.sock', stop_event=stop)
        conn.close.assert_called_once()
        server.close.assert_called_once()

    def test_recovery_link_only_appears_when_recovery_is_available(self):
        from unittest.mock import patch
        from samba_key.app import create_app
        with patch.dict(os.environ, {'RECOVERY_MODE': 'disabled'}):
            disabled = create_app().test_client().get('/?lang=es').get_data(as_text=True)
            enabled = create_app(recovery_service=object()).test_client().get(
                '/?lang=es').get_data(as_text=True)
        self.assertNotIn('href="/recovery?lang=es"', disabled)
        self.assertIn('href="/recovery?lang=es"', enabled)

    def test_enabled_recovery_form_is_not_labeled_unavailable(self):
        from unittest.mock import patch
        from samba_key.app import create_app
        with patch.dict(os.environ, {'RECOVERY_MODE': 'disabled'}):
            page = create_app(recovery_service=object()).test_client().get(
                '/recovery?lang=es').get_data(as_text=True)
        self.assertNotIn('La recuperación de contraseña no está disponible', page)
        self.assertIn('Solicitar recuperación', page)
    def test_capacity_is_atomic_across_multiple_store_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'portal.db')
            stores = [Store(path), Store(path)]
            self.addCleanup(stores[0].close)
            self.addCleanup(stores[1].close)
            barrier = threading.Barrier(2)
            outcomes = []
            def register(index):
                barrier.wait()
                outcomes.append(stores[index].register_recovery_client(
                    f'client-{index}', 1, 60, 60, 1000))
            threads = [threading.Thread(target=register, args=(i,)) for i in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertCountEqual(outcomes, [True, False])

    def test_attempt_limit_is_atomic_across_multiple_store_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'portal.db')
            stores = [Store(path), Store(path)]
            self.addCleanup(stores[0].close)
            self.addCleanup(stores[1].close)
            barrier = threading.Barrier(2)
            outcomes = []
            def attempt(index):
                barrier.wait()
                outcomes.append(stores[index].hit('same-client', 1, 60, 1000))
            threads = [threading.Thread(target=attempt, args=(i,)) for i in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertCountEqual(outcomes, [True, False])

    def test_capacity_is_enforced_and_expired_clients_free_slots(self):
        now = [1000.0]
        store = Store(':memory:', now=lambda: now[0])
        self.addCleanup(store.close)
        service = RecoveryService(_Authority(), store, 'https://example.test',
                                  clients_cap=1, client_window=60,
                                  now_func=lambda: now[0])
        self.assertEqual(service.request('alice', 'client-a')['status'], 'generic')
        self.assertEqual(service.request('alice', 'client-b')['status'], 'rate_limited')
        self.assertEqual(service.request('alice', 'client-a')['status'], 'generic')
        now[0] += 61
        self.assertEqual(service.request('alice', 'client-b')['status'], 'generic')

    def test_unique_usernames_do_not_leave_expired_rate_entries(self):
        now = [1000.0]
        store = Store(':memory:', now=lambda: now[0])
        self.addCleanup(store.close)
        service = RecoveryService(_Authority(), store, 'https://example.test',
                                  clients_cap=2, client_window=60,
                                  request_window=60, complete_window=60,
                                  now_func=lambda: now[0])
        service.request('alice', 'client-a')
        now[0] += 61
        service.request('bob', 'client-a')
        keys = [row[0] for row in store._conn.execute('SELECT DISTINCT key FROM ratelimit')]
        self.assertNotIn('account-client-a-alice', keys)

    def test_uncertain_reset_is_not_reported_as_an_invalid_link(self):
        class UncertainAuthority:
            def consume(self, *args):
                return None
        store = Store(':memory:')
        self.addCleanup(store.close)
        service = RecoveryService(UncertainAuthority(), store, 'https://example.test')
        self.assertEqual(service.complete('token', 'long-enough-password', 'client-a')['status'],
                         'uncertain')

    def test_reset_transport_failure_is_distinct_from_rejected_token(self):
        from unittest.mock import patch
        client = ResetClient('/missing.sock')
        with patch.object(client, '_call', return_value={'ok': False, 'transport_error': True}):
            self.assertIsNone(client.consume('token', 'long-enough-password'))
        with patch.object(client, '_call', return_value={'ok': False}):
            self.assertFalse(client.consume('token', 'long-enough-password'))

    def test_reset_has_time_for_smbpasswd_while_request_timeout_stays_short(self):
        import json
        import struct
        from unittest.mock import MagicMock, patch
        client = ResetClient('/fake.sock', recv_timeout=3)
        sock = MagicMock()
        body = json.dumps({'ok': True}).encode()
        with patch('samba_key.reset_auth.socket.socket', return_value=sock), \
             patch('samba_key.reset_auth._write_frame'), \
             patch('samba_key.reset_auth._recv_all', side_effect=[struct.pack('>I', len(body)), body]) as recv:
            self.assertTrue(client.consume('token', 'long-enough-password'))
        self.assertEqual(recv.call_args_list[0].args[2], 25)
        sock.settimeout.assert_called_with(25)

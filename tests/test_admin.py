import unittest
import io
import tempfile
import os
import threading
import time

from samba_key.store import Store
from samba_key.reset_auth import ResetAuthority, AdminClient, Role
from samba_key.admin import run, main


class FakeClient:
    def __init__(self):
        self.approved = []
        self.denied = []
        self.pending = [
            {'handle': 'h1', 'account': 'alice', 'kind': 'recovery',
             'status': 'pending', 'expires_at': 100},
        ]
        self.channels = []

    def list_pending(self):
        return [r for r in self.pending if r['status'] == 'pending']

    def approve(self, handle):
        self.approved.append(handle)
        for r in self.pending:
            if r['handle'] == handle:
                r['status'] = 'approved'
        return True

    def deny(self, handle):
        self.denied.append(handle)
        for r in self.pending:
            if r['handle'] == handle:
                r['status'] = 'denied'
        return True

    def channel_add(self, account, kind, value):
        return 'CODE-123'

    def channel_verify(self, account, kind, value, code):
        self.channels.append({'account': account, 'kind': kind, 'value': value})
        return True

    def channel_remove(self, account, kind):
        return True

    def channel_list(self, account=None):
        return self.channels


class AdminCliTests(unittest.TestCase):
    def test_list_and_approve(self):
        client = FakeClient()
        out = io.StringIO()
        rc = run(['list'], client, out)
        self.assertEqual(rc, 0)
        self.assertIn('alice', out.getvalue())
        rc = run(['approve', 'h1'], client, out)
        self.assertEqual(rc, 0)
        self.assertIn('approved', out.getvalue())
        self.assertEqual(client.approved, ['h1'])

    def test_deny(self):
        client = FakeClient()
        out = io.StringIO()
        rc = run(['deny', 'h1'], client, out)
        self.assertEqual(rc, 0)
        self.assertIn('denied', out.getvalue())

    def test_bad_usage(self):
        out = io.StringIO()
        self.assertEqual(run([], FakeClient(), out), 2)
        self.assertEqual(run(['approve'], FakeClient(), out), 2)
        self.assertEqual(run(['bogus'], FakeClient(), out), 2)
        self.assertEqual(run(['channel'], FakeClient(), out), 2)
        self.assertEqual(run(['channel', 'add', 'alice'], FakeClient(), out), 2)

    def test_channel_add_and_verify_and_remove_and_list(self):
        client = FakeClient()
        out = io.StringIO()
        self.assertEqual(run(['channel', 'add', 'alice', 'email',
                              'alice@example.org'], client, out), 0)
        self.assertIn('CODE-123', out.getvalue())
        self.assertEqual(run(['channel', 'verify', 'alice', 'email',
                              'alice@example.org', 'CODE-123'], client, out), 0)
        out2 = io.StringIO()
        self.assertEqual(run(['channel', 'list', 'alice'], client, out2), 0)
        self.assertIn('example.org', out2.getvalue())
        self.assertEqual(run(['channel', 'remove', 'alice', 'email'],
                             client, io.StringIO()), 0)

    def test_main_without_socket_env_refuses(self):
        old = os.environ.pop('RECOVERY_ADMIN_SOCKET', None)
        old_dir = os.environ.pop('AUTHORITY_DIR', None)
        try:
            self.assertEqual(main(['list']), 2)
        finally:
            if old is not None:
                os.environ['RECOVERY_ADMIN_SOCKET'] = old
            if old_dir is not None:
                os.environ['AUTHORITY_DIR'] = old_dir

    def test_main_falls_back_to_authority_dir(self):
        # With only AUTHORITY_DIR set (no separate RECOVERY_ADMIN_SOCKET), the
        # CLI must derive <dir>/admin.sock rather than refuse as 'unset'. A
        # missing socket fails fast (connect error), so the CLI reports no
        # requests instead of returning 2.
        old = os.environ.pop('RECOVERY_ADMIN_SOCKET', None)
        os.environ['AUTHORITY_DIR'] = tempfile.mkdtemp()
        try:
            self.assertNotEqual(main(['list']), 2,
                                'AUTHORITY_DIR must be used, not refused as unset')
        finally:
            if old is not None:
                os.environ['RECOVERY_ADMIN_SOCKET'] = old
            os.environ.pop('AUTHORITY_DIR', None)


class AdminCliRealSocketTests(unittest.TestCase):
    """The CLI must actually approve through the real admin socket, which the
    portal cannot reach."""

    def setUp(self):
        import socket as _s
        self.tmp = tempfile.mkdtemp()
        store = Store(os.path.join(self.tmp, 'auth.db'))
        self.admin_sock = os.path.join(self.tmp, 'admin.sock')
        calls = []
        self.server = ResetAuthority(
            store, eligible_accounts=frozenset({'alice'}),
            reset_fn=lambda a, p: calls.append((a, p)) or True,
            principals=lambda peer: Role.ADMIN,
            peer_credential=lambda c: (0, 5000))
        self._thread = threading.Thread(
            target=self.server.serve, args=(self.admin_sock,), daemon=True)
        self._thread.start()
        for _ in range(300):
            probe = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                probe.connect(self.admin_sock)
                break
            except OSError:
                time.sleep(0.01)
            finally:
                probe.close()
        self.store = store
        self.mint_sock = os.path.join(self.tmp, 'portal.sock')
        self.portal_server = ResetAuthority(
            store, eligible_accounts=frozenset({'alice'}),
            reset_fn=lambda a, p: calls.append((a, p)) or True,
            principals=lambda peer: Role.PORTAL,
            peer_credential=lambda c: (1000, 1000))
        self._pthread = threading.Thread(
            target=self.portal_server.serve, args=(self.mint_sock,), daemon=True)
        self._pthread.start()
        for _ in range(300):
            probe = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                probe.connect(self.mint_sock)
                break
            except OSError:
                time.sleep(0.01)
            finally:
                probe.close()

    def tearDown(self):
        self.store.close()

    def test_cli_approves_via_admin_socket(self):
        from samba_key.reset_auth import ResetClient, AdminClient
        handle = ResetClient(self.mint_sock).mint('alice')
        self.assertIsNotNone(handle)
        out = io.StringIO()
        client = AdminClient(self.admin_sock)
        self.assertEqual(run(['list'], client, out), 0)
        self.assertIn('alice', out.getvalue())
        self.assertEqual(run(['approve', handle], client, out), 0)
        # The portal can NEVER issue the token: delivery is authority-side.
        token = self.store.issue(handle, 900)
        self.assertIsNotNone(token)

    def test_cli_enrolls_a_channel_via_admin_socket(self):
        from samba_key.reset_auth import AdminClient
        client = AdminClient(self.admin_sock)
        out = io.StringIO()
        rc = run(['channel', 'add', 'alice', 'email', 'alice@example.org'],
                 client, out)
        self.assertEqual(rc, 0)
        code = out.getvalue().split('code: ')[1].split()[0]
        self.assertEqual(run(['channel', 'verify', 'alice', 'email',
                              'alice@example.org', code], client, io.StringIO()), 0)
        self.assertEqual(self.store.resolve_binding('alice').value,
                         'alice@example.org')

    def test_cli_telegram_add_takes_no_value(self):
        # Telegram's chat id is learned on /start, so 'channel add' must accept
        # the three-argument form the OPERATIONS procedure documents.
        from samba_key.reset_auth import AdminClient
        client = AdminClient(self.admin_sock)
        out = io.StringIO()
        rc = run(['channel', 'add', 'alice', 'telegram'], client, out)
        self.assertEqual(rc, 0)
        self.assertIn('code: ', out.getvalue())
        # And the email form still requires an address.
        out2 = io.StringIO()
        self.assertEqual(run(['channel', 'add', 'alice', 'email'],
                             client, out2), 2)


if __name__ == '__main__':
    unittest.main()

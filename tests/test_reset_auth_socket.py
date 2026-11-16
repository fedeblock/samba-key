import os
import tempfile
import threading
import time
import unittest

from samba_key.store import Store
from samba_key.reset_auth import (
    ResetAuthority, ResetClient, AdminClient, Role,
)


def _start(authority, path):
    t = threading.Thread(target=authority.serve, args=(path,), daemon=True)
    t.start()
    for _ in range(300):
        try:
            import socket as _s
            probe = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                probe.connect(path)
            finally:
                probe.close()
            break
        except OSError:
            time.sleep(0.01)
    return t


class SocketRoundTripTests(unittest.TestCase):
    def test_full_flow_over_socket(self):
        # The end-to-end path: portal mints (no channel, no token), a *separate*
        # admin principal approves, the authority-side worker issues + delivers
        # (here: store.issue simulates the worker, since the portal must never
        # issue), and the portal consumes the token it obtained from the link.
        dir_ = tempfile.mkdtemp()
        store = Store(os.path.join(dir_, 's.db'))
        calls = []
        reset_fn = lambda acct, pw: calls.append((acct, pw)) or True
        portal_sock = os.path.join(dir_, 'portal.sock')
        admin_sock = os.path.join(dir_, 'admin.sock')
        _start(ResetAuthority(store, eligible_accounts=frozenset({'alice'}),
                              reset_fn=reset_fn,
                              principals=lambda peer: Role.PORTAL,
                              peer_credential=lambda c: (1000, 1000)),
               portal_sock)
        _start(ResetAuthority(store, eligible_accounts=frozenset({'alice'}),
                              reset_fn=reset_fn,
                              principals=lambda peer: Role.ADMIN,
                              peer_credential=lambda c: (0, 5000)),
               admin_sock)
        pc = ResetClient(portal_sock)
        ac = AdminClient(admin_sock)

        handle = pc.mint('alice')
        self.assertTrue(handle)
        # The portal can never obtain a token through the socket: there is no
        # ISSUE/REVOKE on the portal client at all.
        self.assertFalse(hasattr(pc, 'issue'))
        self.assertFalse(hasattr(pc, 'revoke'))
        # The admin (a different principal, different socket) approves.
        pending = ac.list_pending()
        self.assertEqual(pending[0]['account'], 'alice')
        self.assertEqual(pending[0]['handle'], handle)
        self.assertTrue(ac.approve(handle))
        # Authority-side issue (the worker), then the portal consumes the token
        # that would have arrived in the delivered link.
        token = store.issue(handle, 900)
        self.assertTrue(token)
        self.assertIsNone(store.issue(handle, 900))  # single use
        self.assertTrue(pc.consume(token, 'a-new-password-1'))
        self.assertEqual(calls, [('alice', 'a-new-password-1')])
        self.assertFalse(pc.consume(token, 'another-password-2'))  # single use
        store.close()

    def test_portal_socket_cannot_approve_or_issue(self):
        dir_ = tempfile.mkdtemp()
        store = Store(os.path.join(dir_, 's.db'))
        calls = []
        portal_sock = os.path.join(dir_, 'portal.sock')
        _start(ResetAuthority(store, eligible_accounts=frozenset({'alice'}),
                              reset_fn=lambda a, p: calls.append((a, p)) or True,
                              principals=lambda peer: Role.PORTAL,
                              peer_credential=lambda c: (1000, 1000)),
               portal_sock)
        pc = ResetClient(portal_sock)
        handle = pc.mint('alice')
        self.assertTrue(handle)
        # Approving or issuing through the portal socket (wrong principal) must
        # fail; the portal has no code path to advance or deliver a request.
        self.assertFalse(AdminClient(portal_sock).approve(handle))
        self.assertEqual(calls, [])
        store.close()

    def test_unknown_account_over_socket_is_rejected(self):
        dir_ = tempfile.mkdtemp()
        store = Store(os.path.join(dir_, 's.db'))
        portal_sock = os.path.join(dir_, 'portal.sock')
        _start(ResetAuthority(store, eligible_accounts=frozenset({'alice'}),
                              reset_fn=lambda a, p: None,
                              principals=lambda peer: Role.PORTAL,
                              peer_credential=lambda c: (1000, 1000)),
               portal_sock)
        pc = ResetClient(portal_sock)
        self.assertIsNone(pc.mint('bob'))
        self.assertIsNone(pc.mint('root'))
        store.close()

    def test_channel_ops_refused_on_portal_socket(self):
        # Channel enrollment is admin-only: the portal socket must refuse every
        # channel operation, so a compromised portal cannot inject a binding.
        dir_ = tempfile.mkdtemp()
        store = Store(os.path.join(dir_, 's.db'))
        portal_sock = os.path.join(dir_, 'portal.sock')
        _start(ResetAuthority(store, eligible_accounts=frozenset({'alice'}),
                              reset_fn=lambda a, p: True,
                              principals=lambda peer: Role.PORTAL,
                              peer_credential=lambda c: (1000, 1000)),
               portal_sock)
        pc = ResetClient(portal_sock)  # portal client: no channel methods
        self.assertFalse(hasattr(pc, 'channel_add'))
        self.assertFalse(hasattr(pc, 'channel_verify'))
        store.close()


class RawPortalAdversarialTests(unittest.TestCase):
    """Drive the *raw* portal socket (not the friendly ResetClient wrapper) as a
    PORTAL-role peer and prove the dispatch role gate refuses every privileged
    operation -- approving, issuing a token, and injecting or altering a channel
    binding -- so a compromised portal cannot do any of these even with a raw
    socket connection. This makes the guarantee non-vacuous."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 's.db'))
        self.portal_sock = os.path.join(self.dir, 'portal.sock')
        self._stop = threading.Event()
        t = threading.Thread(
            target=ResetAuthority(
                self.store, eligible_accounts=frozenset({'alice'}),
                reset_fn=lambda a, p: True,
                principals=lambda peer: Role.PORTAL,
                peer_credential=lambda c: (1000, 1000)).serve,
            args=(self.portal_sock,),
            kwargs={'forced_role': Role.PORTAL, 'stop_event': self._stop},
            daemon=True)
        t.start()
        for _ in range(300):
            import socket as _s
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                s.connect(self.portal_sock)
            except OSError:
                s.close()
                time.sleep(0.01)
                continue
            s.close()
            break

    def tearDown(self):
        self._stop.set()
        self.store.close()

    def _raw_call(self, op, payload):
        import json, socket, struct
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.portal_sock)
            body = json.dumps({'op': op, 'payload': payload}).encode()
            s.sendall(struct.pack('>I', len(body)) + body)
            s.settimeout(5)
            header = b''
            while len(header) < 4:
                chunk = s.recv(4 - len(header))
                if not chunk:
                    return {}
                header += chunk
            (length,) = struct.unpack('>I', header)
            data = b''
            while len(data) < length:
                chunk = s.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            return json.loads(data.decode())
        finally:
            s.close()

    def test_portal_socket_cannot_approve_issue_or_inject_binding(self):
        handle = self.store.create_request('alice', 1800)
        self.assertIsNotNone(handle)
        # A raw PORTAL-role connection must be refused for every privileged op.
        self.assertFalse(self._raw_call('APPROVE', {'handle': handle}).get('ok'))
        self.assertFalse(self._raw_call('ISSUE', {'handle': handle}).get('ok'))
        self.assertFalse(self._raw_call('CHANNEL_ADD',
                         {'account': 'alice', 'kind': 'email',
                          'value': 'attacker@example.net'}).get('ok'))
        self.assertFalse(self._raw_call('CHANNEL_VERIFY',
                         {'account': 'alice', 'kind': 'email',
                          'value': 'attacker@example.net', 'code': 'x'}).get('ok'))
        # The request is still pending and unapproved; nothing was injected.
        self.assertEqual(self.store.approved_requests(), [])
        self.assertEqual(self.store.channel_rows('alice'), [])

    def test_portal_socket_mint_is_allowed_but_carries_no_channel(self):
        # MINT is the one portal op that is allowed, and it accepts no channel.
        resp = self._raw_call('MINT', {'account': 'alice', 'kind': 'recovery'})
        self.assertTrue(resp.get('ok'))
        self.assertIn('handle', resp)
        self.assertNotIn('token', resp)
        self.assertNotIn('value', resp)


if __name__ == '__main__':
    unittest.main()


class SilentAuthorityTests(unittest.TestCase):
    """A hung or silent authority (a socket that accepts but never answers) must
    not block the portal: the client's receive timeout bounds the call and the
    request fails closed to the uniform generic message."""

    def test_silent_authority_is_bounded_and_fails_closed(self):
        import json, socket, struct, threading, time
        d = tempfile.mkdtemp()
        sock_path = os.path.join(d, 'silent.sock')
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(4)
        stop = threading.Event()

        def _drain():
            srv.settimeout(0.5)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    break
                try:
                    conn.settimeout(0.5)
                    conn.recv(4)  # read the frame header, then stay silent
                except OSError:
                    pass
                finally:
                    conn.close()

        t = threading.Thread(target=_drain, daemon=True)
        t.start()
        client = ResetClient(sock_path, recv_timeout=0.3)
        start = time.time()
        handle = client.mint('alice')
        elapsed = time.time() - start
        self.assertIsNone(handle)
        self.assertLess(elapsed, 3.0, 'a silent authority must not hang')
        stop.set()
        srv.close()

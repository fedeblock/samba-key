"""End-to-end integration test for the recovery flow with REAL components.

A real ``ResetAuthority`` (a PORTAL socket and a separate ADMIN socket, sharing
one ledger store) is wired to a real ``ResetClient``/``AdminClient`` and a
real ``DeliveryWorker`` (authority-side) plus a real ``RecoveryDelivery``.  The
**only** substitution is the network boundary (``smtplib.SMTP`` for e-mail and
``urllib.request.urlopen`` for Telegram), so the real transport classes run and
build their messages/payloads for real.

The portal mints (no channel, no token); the admin approves on the separate
socket; the authority-side worker resolves the destination from the authority's
own bindings, issues the token and sends the link; the portal then consumes the
token it received only from the delivered link. The portal never issues or
receives a token, and can never enroll or divert a channel.
"""
import json
import os
import tempfile
import threading
import unittest
import urllib.request

from samba_key.reset_auth import ResetAuthority, ResetClient, AdminClient, Role
from samba_key.recovery import RecoveryService
from samba_key.delivery import (RecoveryDelivery, SmtpDelivery,
                               TelegramDelivery, DeliveryError)
from samba_key.delivery_worker import DeliveryWorker
from samba_key.store import Store


def _start_authority(store, eligible, reset_fn, dir_, portal_uid_gid):
    """Two real authorities sharing one store: a portal socket (PORTAL) and an
    admin socket (ADMIN), each bound to its role. Returns the socket paths,
    threads and stop events."""
    portal_sock = os.path.join(dir_, 'portal.sock')
    admin_sock = os.path.join(dir_, 'admin.sock')
    stops = [threading.Event(), threading.Event()]
    specs = [(portal_sock, Role.PORTAL, stops[0], portal_uid_gid),
             (admin_sock, Role.ADMIN, stops[1], (0, 5000))]
    threads = []
    for sock_path, role, stop, peer in specs:
        auth = ResetAuthority(store, eligible, reset_fn,
                              principals=lambda p, r=role: r,
                              peer_credential=lambda c, pe=peer: pe)
        t = threading.Thread(target=auth.serve, args=(sock_path,),
                             kwargs={'forced_role': role, 'stop_event': stop,
                                     'listen_backlog': 16, 'recv_timeout': 5},
                             daemon=True)
        t.start()
        threads.append(t)
    return portal_sock, admin_sock, threads, stops


class RecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.auth_store = Store(os.path.join(self.dir, 'auth.db'))
        self.portal_store = Store(os.path.join(self.dir, 'portal.db'))
        self.reset_log = []
        reset_fn = lambda account, new: self.reset_log.append((account, new)) or True
        (self.portal_sock, self.admin_sock,
         self.threads, self.stops) = _start_authority(
             self.auth_store, ['alice', 'bob'], reset_fn, self.dir, (1000, 1000))
        self._wait(self.portal_sock)
        self._wait(self.admin_sock)
        self.client = ResetClient(self.portal_sock)
        self.admin = AdminClient(self.admin_sock)
        self.smtp_calls = []
        self.http_requests = []
        self.smtp_log = []
        self._patch_network()
        self.delivery = RecoveryDelivery(
            email=SmtpDelivery('smtp', 587, 'u', 'p', 'from@x'),
            telegram=TelegramDelivery('token'))
        self.worker = DeliveryWorker(self.auth_store, self.delivery,
                                     'https://portal.example', link_ttl=900)
        self.svc = RecoveryService(self.client, self.portal_store,
                                   'https://portal.example',
                                   policy_min=12, policy_max=1024)

    def _patch_network(self):
        import smtplib
        smtp_log = self.smtp_log
        smtp_calls = self.smtp_calls
        http_requests = self.http_requests

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def ehlo(self):
                smtp_log.append('ehlo')
            def starttls(self, *a, **k):
                smtp_log.append('starttls')
            def login(self, user, pw):
                smtp_log.append(('login', user))
            def send_message(self, message):
                smtp_calls.append(message)
        self._orig_smtp = smtplib.SMTP
        smtplib.SMTP = FakeSMTP

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self, n=-1):
                return json.dumps({'ok': True}).encode()
        def fake_urlopen(request, *a, **k):
            http_requests.append(request)
            return FakeResp()
        self._orig_urlopen = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen

    @staticmethod
    def _wait(path, timeout=5):
        import socket as _s, time as _t
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                s.connect(path)
                return
            except OSError:
                _t.sleep(0.05)
            finally:
                s.close()
        raise unittest.SkipTest('authority socket not ready: ' + path)

    def tearDown(self):
        import smtplib
        smtplib.SMTP = self._orig_smtp
        urllib.request.urlopen = self._orig_urlopen
        for stop in self.stops:
            stop.set()
        for t in self.threads:
            t.join(timeout=3)
        self.auth_store.close()
        self.portal_store.close()

    # -- e-mail: real SmtpDelivery over a fake SMTP connection ----------
    def test_full_flow_email_builds_real_message(self):
        # Admin enrolls the destination on the authority store.
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.assertTrue(self.admin.channel_verify('alice', 'email',
                                                  'alice@example.com', code))
        # The portal requests (uniform response, no channel, no handle).
        resp = self.svc.request('alice', '1.2.3.4')
        self.assertEqual(resp['status'], 'generic')
        self.assertNotIn('handle', resp)
        # The admin approves on the separate socket.
        handle = self.admin.list_pending()[0]['handle']
        self.assertTrue(self.admin.approve(handle))
        # The authority-side worker delivers the link.
        self.assertEqual(self.worker.deliver_pending(), 1)
        msg = self.smtp_calls[0]
        self.assertEqual(msg['To'], 'alice@example.com')
        self.assertIn('starttls', self.smtp_log)
        self.assertTrue(any(c[0] == 'login' for c in self.smtp_log))
        self.assertIn('https://portal.example/reset#t=', msg.get_content())
        token = msg.get_content().split('#t=')[1].strip()
        out = self.svc.complete(token, 'a-new-password-123', '1.2.3.4')
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(self.reset_log, [('alice', 'a-new-password-123')])

    # -- telegram: real TelegramDelivery over a fake HTTP endpoint ------
    def test_full_flow_telegram_builds_real_payload(self):
        # Telegram is enrolled through the verified private conversation.
        from samba_key.telegram import TelegramBinder
        code = self.admin.channel_add('alice', 'telegram', '')
        self.assertIsNotNone(TelegramBinder(self.auth_store, 'token').process_update(
            {'message': {'chat': {'id': 123456789, 'type': 'private'},
                         'from': {'id': 123456789}, 'text': '/start ' + code}}))
        self.svc.request('alice', '1.2.3.4')
        self.assertTrue(self.admin.approve(self.admin.list_pending()[0]['handle']))
        self.assertEqual(self.worker.deliver_pending(), 1)
        payload = json.loads(self.http_requests[0].data.decode())
        self.assertEqual(payload['chat_id'], '123456789')
        self.assertIn('https://portal.example/reset#t=', payload['text'])
        token = payload['text'].split('#t=')[1].strip()
        self.assertEqual(self.svc.complete(token, 'a-new-password-123',
                                           '1.2.3.4')['status'], 'ok')

    def test_no_approval_no_delivery(self):
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.admin.channel_verify('alice', 'email', 'alice@example.com', code)
        self.svc.request('alice', '1.2.3.4')
        self.assertEqual(self.worker.deliver_pending(), 0)
        self.assertEqual(len(self.smtp_calls), 0)

    def test_no_binding_no_delivery(self):
        # An approved request with no binding cannot be delivered.
        self.svc.request('bob', '1.2.3.4')
        self.assertTrue(self.admin.approve(self.admin.list_pending()[0]['handle']))
        self.assertEqual(self.worker.deliver_pending(), 0)
        self.assertEqual(len(self.smtp_calls), 0)

    # -- destination tampering: a binding change after approval is refused
    def test_binding_change_after_approval_is_not_delivered(self):
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.admin.channel_verify('alice', 'email', 'alice@example.com', code)
        self.svc.request('alice', '1.2.3.4')
        handle = self.admin.list_pending()[0]['handle']
        self.assertTrue(self.admin.approve(handle))
        # The destination is swapped in after approval.
        code2 = self.admin.channel_add('alice', 'email', 'evil@attacker.net')
        self.admin.channel_verify('alice', 'email', 'evil@attacker.net', code2)
        # The changed binding invalidates the approved request, so nothing goes
        # out and it goes to the attacker's address.
        self.assertEqual(self.worker.deliver_pending(), 0)
        self.assertEqual(len(self.smtp_calls), 0)

    # -- delivery failure: the token is revoked, not left live ---------
    def test_delivery_failure_revokes_the_token(self):
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.admin.channel_verify('alice', 'email', 'alice@example.com', code)
        self.svc.request('alice', '1.2.3.4')
        self.admin.approve(self.admin.list_pending()[0]['handle'])
        captured = []
        import smtplib
        class CapturingFailSMTP:
            def __init__(self, *a, **k):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def ehlo(self):
                pass
            def starttls(self, *a, **k):
                pass
            def login(self, u, p):
                pass
            def send_message(self, message):
                captured.append(message)
                raise OSError('smtp down after capture')
        smtplib.SMTP = CapturingFailSMTP
        try:
            self.assertEqual(self.worker.deliver_pending(), 0)
        finally:
            smtplib.SMTP = self._orig_smtp
        # The token that would have been in the lost link is now un-consumable.
        token = captured[0].get_content().split('#t=')[1].strip()
        self.assertEqual(self.svc.complete(token, 'a-new-password-123',
                                           '1.2.3.4')['status'], 'invalid')
        self.assertEqual(self.reset_log, [])  # no reset happened

    def test_smtp_failure_error_has_no_secret(self):
        token = 'SECRET-TOKEN-abcdef'
        link = 'https://portal.example/reset#t=' + token
        import smtplib
        def boom(*a, **k):
            raise OSError('smtp down')
        smtplib.SMTP = boom
        try:
            with self.assertRaises(DeliveryError) as ctx:
                SmtpDelivery('smtp', 587, 'u', 'p', 'from@x').send(
                    'leak@example.com', 'Subj', link)
            text = str(ctx.exception)
            self.assertNotIn('leak@example.com', text)
            self.assertNotIn(token, text)
            self.assertNotIn(link, text)
        finally:
            smtplib.SMTP = self._orig_smtp

    def test_telegram_failure_error_has_no_secret(self):
        token = 'SECRET-TOKEN-abcdef'
        link = 'https://portal.example/reset#t=' + token
        def boom(req, *a, **k):
            raise OSError('http down')
        urllib.request.urlopen = boom
        try:
            with self.assertRaises(DeliveryError) as ctx:
                TelegramDelivery('tok').send('123456789', 'Subj', link)
            text = str(ctx.exception)
            self.assertNotIn(token, text)
            self.assertNotIn('123456789', text)
        finally:
            urllib.request.urlopen = self._orig_urlopen

    def test_telegram_bad_response_is_error(self):
        token = 'SECRET-TOKEN-abcdef'
        link = 'https://portal.example/reset#t=' + token
        class BadResp:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self, n=-1):
                return json.dumps({'ok': False}).encode()
        urllib.request.urlopen = lambda req, *a, **k: BadResp()
        try:
            with self.assertRaises(DeliveryError):
                TelegramDelivery('tok').send('123456789', 'Subj', link)
        finally:
            urllib.request.urlopen = self._orig_urlopen

    def test_unknown_account_is_indistinguishable(self):
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.admin.channel_verify('alice', 'email', 'alice@example.com', code)
        r_valid = self.svc.request('alice', '1.2.3.4')
        r_unknown = self.svc.request('ghost', '1.2.3.4')
        r_no_channel = self.svc.request('bob', '1.2.3.4')
        self.assertEqual(r_valid, r_unknown)
        self.assertEqual(r_valid, r_no_channel)
        for r in (r_valid, r_unknown, r_no_channel):
            self.assertNotIn('handle', r)

    def test_portal_never_sees_the_token(self):
        # A portal-role client has no issue()/revoke(); the token exists only in
        # the delivered link, which the portal did not produce.
        self.assertFalse(hasattr(self.client, 'issue'))
        self.assertFalse(hasattr(self.client, 'revoke'))


if __name__ == '__main__':
    unittest.main()

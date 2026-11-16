"""Adversarial and failure tests for the authority-owned recovery design.

These probe the guarantees that matter for a compromised or restarted portal:
* a restart between approval and delivery does not lose the request;
* tampering the *portal's* store cannot move a link, because the destination
  lives only in the *authority's* store;
* no token, password, or address reaches any portal-accessible artifact.
"""
import os
import tempfile
import unittest

from samba_key.store import Store
from samba_key.delivery_worker import DeliveryWorker


class _Capture:
    def __init__(self):
        self.sent = []

    def send(self, channel, target, subject, body):
        self.sent.append((channel, target, subject, body))


class RestartTests(unittest.TestCase):
    def _path(self):
        return os.path.join(tempfile.mkdtemp(), 'auth.db')

    def test_restart_between_approve_and_delivery(self):
        # Approve in one process; close; reopen; the request is still approved
        # and the worker delivers it.
        path = self._path()
        s = Store(path)
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 1800)
        s.approve(h)
        s.close()
        # Reopen the authority store (a fresh process / restart).
        s2 = Store(path)
        cap = _Capture()
        n = DeliveryWorker(s2, cap, 'https://p', link_ttl=900).deliver_pending()
        s2.close()
        self.assertEqual(n, 1)
        self.assertEqual(cap.sent[0][1], 'alice@example.com')

    def test_restart_does_not_reissue_after_delivery(self):
        path = self._path()
        s = Store(path)
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 1800)
        s.approve(h)
        s.close()
        cap = _Capture()
        s2 = Store(path)
        w = DeliveryWorker(s2, cap, 'https://p')
        self.assertEqual(w.deliver_pending(), 1)
        # Close and reopen: the request is already issued, so nothing is re-sent.
        s2.close()
        cap2 = _Capture()
        s3 = Store(path)
        self.assertEqual(DeliveryWorker(s3, cap2, 'https://p').deliver_pending(), 0)
        s3.close()
        self.assertEqual(len(cap2.sent), 0)


class PortalStoreTamperingTests(unittest.TestCase):
    """The destination lives in the authority store, not the portal's. A portal
    that can rewrite its own store cannot change where a link goes."""

    def setUp(self):
        self.auth_dir = tempfile.mkdtemp()
        self.portal_dir = tempfile.mkdtemp()
        self.auth = Store(os.path.join(self.auth_dir, 'auth.db'))
        self.portal = Store(os.path.join(self.portal_dir, 'portal.db'))
        self.addCleanup(self.auth.close)
        self.addCleanup(self.portal.close)

    def test_rewriting_the_portal_store_does_not_move_the_link(self):
        self.auth.bind_channel('alice', 'email', 'alice@example.com')
        h = self.auth.create_request('alice', 1800)
        self.auth.approve(h)
        # A compromised portal rewrites its own store however it likes.
        self.portal.bind_channel('alice', 'email', 'evil@attacker.net')
        self.portal.bind_channel('alice', 'telegram', '99999999')
        # The authority still resolves its OWN binding and sends there.
        cap = _Capture()
        DeliveryWorker(self.auth, cap, 'https://p').deliver_pending()
        self.assertEqual(len(cap.sent), 1)
        self.assertEqual(cap.sent[0][1], 'alice@example.com')
        for _, target, _, _ in cap.sent:
            self.assertNotEqual(target, 'evil@attacker.net')
            self.assertNotEqual(target, '99999999')


class NoSecretInPortalArtifactsTests(unittest.TestCase):
    """After a full flow, no token, password or destination address may appear
    in any file the portal process owns."""

    def test_token_and_address_absent_from_portal_store_bytes(self):
        d = tempfile.mkdtemp()
        auth = Store(os.path.join(d, 'auth.db'))
        portal = Store(os.path.join(d, 'portal.db'))
        auth.bind_channel('alice', 'email', 'alice@example.com')
        h = auth.create_request('alice', 1800)
        auth.approve(h)
        cap = _Capture()
        DeliveryWorker(auth, cap, 'https://p', link_ttl=900).deliver_pending()
        link = cap.sent[0][3]
        token = link.split('#t=')[1].strip()
        new_password = 'a-brand-new-password-123'
        auth.consume_token(token, 'recovery')  # pretend the reset ran

        # Everything the portal writes (rate-limit hits) goes in its own store.
        portal.hit('client-1.2.3.4', 10, 300)
        portal._conn.commit()
        portal._conn.close()
        auth._conn.commit()
        auth._conn.close()

        # Scan every portal-owned file's raw bytes.
        portal_blob = b''
        for name in os.listdir(d):
            if name.startswith('portal'):
                with open(os.path.join(d, name), 'rb') as fh:
                    portal_blob += fh.read()
        self.assertNotIn(token.encode(), portal_blob,
                         'the token must never be in a portal-owned file')
        self.assertNotIn(new_password.encode(), portal_blob)
        # The address is bound in the *authority* store; it is not a secret the
        # portal holds, so it is acceptable -- but it must not leak via the
        # portal's rate-limit keys.
        self.assertNotIn(b'alice@example.com', portal_blob)


class TokenIsVisibleToAnActivePortalAtUseTime(unittest.TestCase):
    """Document the one residual risk the design cannot remove and that must NOT
    be claimed away: when a user completes a reset, they type the token and the
    new password into a form served by the *portal*. That request body therefore
    passes through the portal process, so an *actively* compromised portal can
    read the token at that moment and use it before or instead of the user.

    The authority boundary stops a *passive* or *inactive* portal from obtaining
    the link at delivery time and from diverting an approved request; it cannot
    stop a portal that is actively serving the exchange page. A separate, more
    privileged exchange process could close this gap, but is out of scope here
    (see RECOVERY-DESIGN.md). This test pins the property so no future change
    silently advertises a stronger guarantee than holds.
    """

    def test_token_and_password_cross_the_portal_at_completion(self):
        import samba_key.app as appmod
        captured = {}

        class Svc:
            def request(self, u, c):
                return {'status': 'generic', 'message': 'created'}

            def complete(self, token, new_password, c):
                captured['token'] = token
                captured['new_password'] = new_password
                return {'status': 'ok', 'message': 'done'}

        cli = appmod.create_app(recovery_service=Svc()).test_client()
        page = cli.get('/reset?lang=en', base_url='https://p').get_data(as_text=True)
        csrf = __import__('re').search(r'name="csrf" value="([^"]+)"', page).group(1)
        token = 'LINK-TOKEN-SECRET'
        # The token is posted in the body of the very request the portal serves.
        cli.post('/reset', data={'csrf': csrf, 'token': token,
                                 'new_password': 'a-new-password-123'},
                 base_url='https://p')
        self.assertEqual(captured.get('token'), token)
        self.assertEqual(captured.get('new_password'), 'a-new-password-123')
        # An active portal therefore saw both: this is the documented limit.


class IssueThenCrashWindow(unittest.TestCase):
    """Pin the one residual risk between issue and send: the worker issues the
    token (issued=1, leaving the approved set) and only then sends. A crash in
    that gap leaves the token live until its TTL -- a restart will not re-send it
    (it is already issued) and cannot revoke it (revoke only runs on a caught
    send exception). This is a documented, bounded leak/DoS window, not a route
    to an unapproved reset: the token was issued only because an independent admin
    approved the request."""

    def test_issued_token_survives_a_restart_but_is_not_redispatched(self):
        path = os.path.join(tempfile.mkdtemp(), 'auth.db')
        s = Store(path)
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 1800)
        s.approve(h)
        token = s.issue(h, 900)
        self.assertIsNotNone(token)
        s.close()
        # Reopen as a restart: the request is issued, so it is not redelivered.
        s2 = Store(path)
        cap = _Capture()
        self.assertEqual(DeliveryWorker(s2, cap, 'https://p').deliver_pending(), 0)
        self.assertEqual(len(cap.sent), 0)
        # But the already-issued token is still consumable until it expires.
        self.assertIsNotNone(s2.consume_token(token, 'recovery'))
        s2.close()


class ResetFailureSurfacesAsFail(unittest.TestCase):
    """A completed-but-failed reset (smbpasswd returned nonzero) must not show
    the success message: the request is consumed and the user is told the link
    is not valid and to request again (an acceptable, generic behavior)."""

    def test_failed_reset_yields_the_fail_message_not_success(self):
        import tempfile
        from samba_key.store import Store
        from samba_key.recovery import RecoveryService, GENERIC_FAIL, GENERIC_OK

        class FakeAuthority:
            def mint(self, account):
                return 'h'

            def consume(self, token, pw, kind):
                # The store consumed the request but the reset itself failed.
                return False

        fd, path = tempfile.mkstemp()
        os.close(fd)
        store = Store(path)
        svc = RecoveryService(FakeAuthority(), store, 'https://p',
                              policy_min=12, policy_max=1024)
        out = svc.complete('any-token', 'a-new-password-123', '1.2.3.4')
        self.assertEqual(out['status'], 'invalid')
        self.assertEqual(out['message'], GENERIC_FAIL)
        self.assertNotEqual(out['message'], GENERIC_OK)


if __name__ == '__main__':
    unittest.main()

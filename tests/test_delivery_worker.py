"""Tests for the authority-side delivery worker.

The worker is the piece that closes the "divert an approved link" gap: it
resolves the destination from the *authority's own* bindings, issues the token
and sends it. A portal that cannot touch the authority store therefore cannot
divert, inject or read a destination.
"""
import os
import tempfile
import unittest

from samba_key.store import Store
from samba_key.delivery_worker import DeliveryWorker


def os_path():
    return os.path.join(tempfile.mkdtemp(), 'w.db')


class _Capture:
    def __init__(self):
        self.sent = []

    def send(self, channel, target, subject, body):
        self.sent.append((channel, target, subject, body))


class _Failing:
    def __init__(self):
        self.attempts = 0

    def send(self, channel, target, subject, body):
        self.attempts += 1
        raise RuntimeError('delivery failed')


class DeliveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os_path())
        self.addCleanup(self.store.close)

    def _approved(self, account, kind, value):
        self.store.bind_channel(account, kind, value)
        h = self.store.create_request(account, 1800)
        self.assertTrue(self.store.approve(h))
        return h

    def test_delivers_to_the_bound_destination(self):
        self._approved('alice', 'email', 'alice@example.com')
        cap = _Capture()
        n = DeliveryWorker(self.store, cap, 'https://p', link_ttl=900).deliver_pending()
        self.assertEqual(n, 1)
        self.assertEqual(cap.sent[0][1], 'alice@example.com')
        self.assertIn('https://p/reset#t=', cap.sent[0][3])
        # The token that was sent is now consumable and single-use.
        token = cap.sent[0][3].split('#t=')[1].strip()
        self.assertIsNotNone(self.store.consume_token(token, 'recovery'))
        self.assertIsNone(self.store.consume_token(token, 'recovery'))

    def test_no_binding_denies_the_request(self):
        # An approved request for an account with no binding cannot be delivered.
        h = self.store.create_request('bob', 1800)
        self.assertTrue(self.store.approve(h))
        cap = _Capture()
        self.assertEqual(DeliveryWorker(self.store, cap, 'https://p').deliver_pending(), 0)
        self.assertEqual(cap.sent, [])
        # The request is denied, not left outstanding.
        self.assertFalse(self.store.approved_requests())

    def test_binding_change_after_approval_is_refused(self):
        self._approved('alice', 'email', 'alice@example.com')
        # Swap the destination after approval.
        self.store.bind_channel('alice', 'email', 'evil@attacker.net')
        cap = _Capture()
        n = DeliveryWorker(self.store, cap, 'https://p').deliver_pending()
        self.assertEqual(n, 0)
        self.assertEqual(cap.sent, [])  # nothing went to the attacker

    def test_delivery_failure_revokes_the_token(self):
        self._approved('alice', 'email', 'alice@example.com')
        fail = _Failing()
        n = DeliveryWorker(self.store, fail, 'https://p').deliver_pending()
        self.assertEqual(n, 0)
        self.assertEqual(fail.attempts, 1)
        # The issued token is now un-consumable (revoked to denied).
        self.assertFalse(self.store.approved_requests())
        rows = self.store._conn.execute('SELECT status FROM requests').fetchall()
        self.assertTrue(all(r[0] == 'denied' for r in rows))

    def test_idempotent_no_double_delivery(self):
        self._approved('alice', 'email', 'alice@example.com')
        cap = _Capture()
        w = DeliveryWorker(self.store, cap, 'https://p')
        self.assertEqual(w.deliver_pending(), 1)
        # A second pass issues nothing new (the request is already issued).
        self.assertEqual(w.deliver_pending(), 0)
        self.assertEqual(len(cap.sent), 1)


    def test_send_failure_that_revokes_channel_kills_the_token(self):
        """A delivery whose send fails after the channel is revoked must leave
        the token un-consumable. A real send could call revoke_channel (e.g. the
        admin revokes the channel mid-send); the token must not survive."""
        self._approved('alice', 'email', 'alice@example.com')

        class _SendThenRevoke:
            def __init__(self, store):
                self.store = store
                self.attempts = 0

            def send(self, channel, target, subject, body):
                self.attempts += 1
                self.store.revoke_channel('alice', 'email')  # kills the link
                raise RuntimeError('send aborted after revoke')

        cap = _SendThenRevoke(self.store)
        n = DeliveryWorker(self.store, cap, 'https://p').deliver_pending()
        self.assertEqual(n, 0)
        # The issued link must now be un-consumable.
        rows = self.store._conn.execute('SELECT status FROM requests').fetchall()
        self.assertTrue(all(r[0] == 'denied' for r in rows))

    def test_binding_change_between_resolve_and_issue_is_caught(self):
        """A change that slips in between the worker's resolve_binding and issue
        is caught by issue()'s own fingerprint check (defense in depth)."""
        self._approved('alice', 'email', 'alice@example.com')
        real_issue = self.store.issue

        def issue_then_change(handle, ttl):
            # Drift the destination just as issue runs, without the store's
            # own invalidation hook, to exercise issue()'s self-guard.
            self.store._conn.execute(
                "UPDATE channels SET value=? WHERE account=? AND kind=?",
                ('attacker@evil.net', 'alice', 'email'))
            self.store._conn.commit()
            return real_issue(handle, ttl)

        self.store.issue = issue_then_change
        cap = _Capture()
        n = DeliveryWorker(self.store, cap, 'https://p').deliver_pending()
        self.assertEqual(n, 0)
        self.assertEqual(cap.sent, [])
        self.store.issue = real_issue


if __name__ == '__main__':
    unittest.main()

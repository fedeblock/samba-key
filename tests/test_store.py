import os
import tempfile
import time
import unittest

from samba_key.store import Store, digest_token, PENDING, APPROVED, ISSUED, USED


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    # --- channel bindings (authority store) ---
    def test_channel_binding_and_revoke(self):
        self.assertIsNone(self.store.resolve_binding('alice'))
        self.store.bind_channel('alice', 'email', 'alice@example.test')
        self.store.bind_channel('alice', 'telegram', '123456')
        rows = {c['kind']: c['value'] for c in self.store.channel_rows('alice')}
        self.assertEqual(rows, {'email': 'alice@example.test', 'telegram': '123456'})
        # E-mail is the preferred delivery destination.
        self.assertEqual(self.store.resolve_binding('alice').kind, 'email')
        self.store.revoke_channel('alice', 'email')
        self.assertEqual(self.store.resolve_binding('alice').kind, 'telegram')
        self.store.revoke_channel('alice', 'email')  # idempotent

    def test_binding_change_invalidates_inflight_requests(self):
        s = self.store
        s.bind_channel('alice', 'email', 'alice@example.test')
        h = s.create_request('alice', ttl=3600)
        self.assertTrue(s.approve(h))
        # Changing the destination must deny the in-flight (approved) request.
        s.bind_channel('alice', 'email', 'evil@attacker.net')
        self.assertFalse(s.approved_requests())
        self.assertFalse(s.pending_requests())

    # --- request lifecycle ---
    def test_mint_returns_handle_not_token(self):
        handle = self.store.create_request('alice', ttl=3600)
        self.assertTrue(handle)
        pending = self.store.pending_requests()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].handle, handle)
        self.assertEqual(pending[0].account, 'alice')

    def test_issue_only_when_approved_and_single_use(self):
        handle = self.store.create_request('alice', ttl=3600)
        # Not yet approved: cannot issue.
        self.assertIsNone(self.store.issue(handle, link_ttl=900))
        self.assertTrue(self.store.approve(handle))
        token = self.store.issue(handle, link_ttl=900)
        self.assertTrue(token)
        self.assertIsNone(self.store.issue(handle, link_ttl=900))  # once

    def test_deny_blocks_issue(self):
        handle = self.store.create_request('alice', ttl=3600)
        self.assertTrue(self.store.deny(handle))
        self.assertIsNone(self.store.issue(handle, link_ttl=900))

    def test_consume_requires_matching_kind(self):
        handle = self.store.create_request('alice', ttl=3600)
        self.store.approve(handle)
        token = self.store.issue(handle, link_ttl=900)
        self.assertIsNone(self.store.peek_token('nonexistent', 'recovery'))
        self.assertIsNone(self.store.consume_token('nonexistent', 'recovery'))
        # Wrong kind is rejected even with the right digest.
        self.assertIsNone(self.store.consume_token(token, 'email'))
        self.assertTrue(self.store.consume_token(token, 'recovery'))

    def test_digest_only_in_storage(self):
        handle = self.store.create_request('alice', ttl=3600)
        self.store.approve(handle)
        token = self.store.issue(handle, link_ttl=900)
        with self.store._connect() as conn:
            row = conn.execute('SELECT token_digest FROM requests WHERE handle=?',
                               (handle,)).fetchone()
        self.assertEqual(row[0], digest_token(token))
        self.assertNotEqual(row[0], token)

    def test_single_use_and_expiry(self):
        handle = self.store.create_request('alice', ttl=3600)
        self.store.approve(handle)
        token = self.store.issue(handle, link_ttl=0.05)
        time.sleep(0.1)
        self.assertIsNone(self.store.peek_token(token, 'recovery'))
        self.assertIsNone(self.store.consume_token(token, 'recovery'))

    def test_caps(self):
        first = self.store.create_request('alice', ttl=3600)
        self.assertTrue(first)
        self.assertIsNone(self.store.create_request('alice', ttl=3600))
        self.assertTrue(self.store.create_request('bob', ttl=3600))
        small = Store(os.path.join(self.dir, 'small.db'), max_pending_global=1)
        self.assertTrue(small.create_request('alice', ttl=3600))
        self.assertIsNone(small.create_request('bob', ttl=3600))
        small.close()


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def test_concurrent_consume_exactly_one_winner(self):
        import threading
        handle = self.store.create_request('alice', ttl=3600)
        self.store.approve(handle)
        token = self.store.issue(handle, link_ttl=900)
        n = 25
        barrier = threading.Barrier(n)
        results = [None] * n

        def worker(i):
            barrier.wait()
            results[i] = self.store.consume_token(token, 'recovery')

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 1)

    def test_concurrent_issue_exactly_one_token(self):
        import threading
        handle = self.store.create_request('alice', ttl=3600)
        self.store.approve(handle)
        n = 25
        barrier = threading.Barrier(n)
        issued = [None] * n

        def worker(i):
            barrier.wait()
            issued[i] = self.store.issue(handle, link_ttl=900)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        tokens = [t for t in issued if t is not None]
        self.assertEqual(len(tokens), 1)

    def test_concurrent_approve_exactly_one_winner(self):
        # Exactly one concurrent APPROVE can win; the request is approved once.
        import threading
        handle = self.store.create_request('alice', ttl=3600)
        n = 25
        barrier = threading.Barrier(n)
        won = [False] * n

        def worker(i):
            barrier.wait()
            won[i] = self.store.approve(handle)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for w in won if w), 1)
        # A second approve after it is already approved cannot re-win.
        self.assertFalse(self.store.approve(handle))


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def test_window(self):
        self.assertTrue(self.store.hit('account:alice', 2, 60))
        self.assertTrue(self.store.hit('account:alice', 2, 60))
        self.assertFalse(self.store.hit('account:alice', 2, 60))

    def test_separate_keys(self):
        self.assertTrue(self.store.hit('client:1.2.3.4', 1, 60))
        self.assertFalse(self.store.hit('client:1.2.3.4', 1, 60))
        self.assertTrue(self.store.hit('client:5.6.7.8', 1, 60))


class ChannelChallengeTests(unittest.TestCase):
    """One-time channel-verification challenges (authority store). Only the
    code's digest is stored; a challenge is consumed exactly once."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def _rows(self):
        return self.store._conn.execute('SELECT * FROM channel_challenges').fetchall()

    def test_email_challenge_code_stored_as_digest_only(self):
        s = self.store
        code = s.create_channel_challenge('alice', 'email', 'a@x', ttl=900)
        self.assertTrue(code)
        for row in self._rows():
            self.assertNotIn(code, [str(c) for c in row])
        # It can still be verified by its value, and only once.
        self.assertTrue(s.verify_channel_challenge('alice', 'email', 'a@x', code))
        self.assertEqual(s.resolve_binding('alice').value, 'a@x')
        self.assertFalse(s.verify_channel_challenge('alice', 'email', 'a@x', code))

    def test_wrong_address_fails(self):
        s = self.store
        code = s.create_channel_challenge('alice', 'email', 'a@x', ttl=900)
        self.assertFalse(s.verify_channel_challenge('alice', 'email', 'evil@x', code))

    def test_telegram_bind_by_code(self):
        s = self.store
        code = s.create_channel_challenge('bob', 'telegram', '', ttl=900)
        # The chat id is learned on /start; the account is discovered from the
        # challenge, not supplied by the caller.
        self.assertEqual(s.bind_by_code('telegram', code, '987654321'), 'bob')
        self.assertEqual(s.resolve_binding('bob').value, '987654321')

    def test_one_pending_challenge_per_account(self):
        s = self.store
        first = s.create_channel_challenge('alice', 'email', 'a@x', ttl=900)
        self.assertIsNotNone(first)
        self.assertIsNone(s.create_channel_challenge('alice', 'email', 'b@x', ttl=900))


class TokenNeverStoredTests(unittest.TestCase):
    """The raw recovery token must never be persisted. It is generated inside
    issue() and only its SHA-256 digest is stored."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'store.db')
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def test_token_absent_from_db_bytes_after_issue(self):
        s = self.store
        h = s.create_request('alice', 1800)
        s.approve(h)
        token = s.issue(h, 600)
        self.assertTrue(token)
        s._conn.commit()
        s._conn.close()
        blob = b''
        for name in ('store.db', 'store.db-wal', 'store.db-journal'):
            p = os.path.join(self.dir, name)
            if os.path.exists(p):
                with open(p, 'rb') as fh:
                    blob += fh.read()
        self.assertNotIn(token.encode('utf-8'), blob,
                         'the raw token must not appear in any store file')
        s2 = Store(self.path)
        self.assertTrue(s2.consume_token(token, 'recovery') is not None)
        self.assertIsNone(s2.consume_token(token, 'recovery'))
        s2.close()

    def test_create_request_persists_no_secret(self):
        s = self.store
        h = s.create_request('alice', 1800)
        s._conn.commit()
        s._conn.close()
        s3 = Store(self.path)
        row = s3._conn.execute(
            'SELECT token_digest FROM requests WHERE handle=?', (h,)).fetchone()
        self.assertIsNone(row[0])
        s3.close()


class ExpiryCapTests(unittest.TestCase):
    def test_expired_request_frees_the_cap(self):
        t = [1000.0]
        path = os.path.join(tempfile.mkdtemp(), 's.db')
        s = Store(path, now=lambda: t[0], max_pending_per_account=1)
        h1 = s.create_request('alice', 600)  # expires 1600
        self.assertIsNotNone(h1)
        self.assertIsNone(s.create_request('alice', 600))  # capped
        t[0] = 2000.0  # past expiry
        h2 = s.create_request('alice', 600)
        self.assertIsNotNone(h2, 'an expired request must free the per-account cap')
        s.close()

    def test_purge_expired_removes_terminal_states(self):
        t = [1000.0]
        path = os.path.join(tempfile.mkdtemp(), 's.db')
        s = Store(path, now=lambda: t[0])
        h = s.create_request('alice', 100)
        s.approve(h)
        s.issue(h, 100)
        t[0] = 5000.0
        s.purge_expired()
        remaining = s._conn.execute(
            'SELECT COUNT(*) FROM requests WHERE account=?', ('alice',)).fetchone()[0]
        s.close()
        self.assertEqual(remaining, 0, 'expired requests are purged')


class IssuedLinkInvalidationTests(unittest.TestCase):
    """Defect 2: revoking or changing a channel must kill an already-issued
    link, deterministically. A token is generated only after approval pins the
    binding fingerprint; a channel change/revoke after issue must defeat it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def _issued_token(self, account, kind, value):
        s = self.store
        s.bind_channel(account, kind, value)
        h = s.create_request(account, 3600)
        self.assertTrue(s.approve(h))
        token = s.issue(h, 900)
        self.assertIsNotNone(token)
        return token

    def test_revoked_channel_invalidates_issued_link(self):
        token = self._issued_token('alice', 'email', 'alice@example.com')
        # The channel is revoked after the link was issued.
        self.store.revoke_channel('alice', 'email')
        self.assertIsNone(self.store.consume_token(token, 'recovery'),
                          'a revoked channel must kill the issued link')

    def test_changed_channel_invalidates_issued_link(self):
        token = self._issued_token('alice', 'email', 'alice@example.com')
        self.store.bind_channel('alice', 'email', 'attacker@example.net')
        self.assertIsNone(self.store.consume_token(token, 'recovery'))

    def test_revoke_all_invalidates_issued_link(self):
        token = self._issued_token('alice', 'telegram', '123456')
        self.store.revoke_all('alice')
        self.assertIsNone(self.store.consume_token(token, 'recovery'))

    def test_new_channel_kind_invalidates_issued_link(self):
        # Adding any channel (even a new kind) runs the account's invalidation,
        # so an already-issued link to the previous binding is killed.
        token = self._issued_token('alice', 'email', 'alice@example.com')
        self.store.bind_channel('alice', 'telegram', '999888')
        self.assertIsNone(self.store.consume_token(token, 'recovery'),
                          'any channel change invalidates the issued link')

    def test_consume_rechecks_fingerprint_even_without_invalidate(self):
        """Defense in depth: a binding changed by a path that did not run the
        invalidation (e.g. a raw SQL write) is still caught at consume time."""
        token = self._issued_token('alice', 'email', 'alice@example.com')
        # Simulate a change that bypassed the store's own invalidation hook.
        self.store._conn.execute(
            "UPDATE channels SET value=? WHERE account=? AND kind=?",
            ('attacker@evil.net', 'alice', 'email'))
        self.store._conn.commit()
        self.assertIsNone(self.store.consume_token(token, 'recovery'),
                          'consume must re-check the pinned fingerprint')

    def test_issue_refuses_when_binding_drifts(self):
        """issue() is self-guarding: a binding that changed after approval but
        before issue (a TOCTOU the worker also guards) is refused."""
        s = self.store
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 3600)
        self.assertTrue(s.approve(h))
        # Drift the binding after approval, before issue.
        s._conn.execute(
            "UPDATE channels SET value=? WHERE account=? AND kind=?",
            ('attacker@evil.net', 'alice', 'email'))
        s._conn.commit()
        self.assertIsNone(s.issue(h, 900),
                          'issue must refuse a drifted destination')

    def test_revoke_is_idempotent_when_already_denied(self):
        """A revoke that races a channel invalidation (already denied) reports
        success, so the worker does not log a misleading 'did not confirm'."""
        s = self.store
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 3600)
        self.assertTrue(s.approve(h))
        s.issue(h, 900)
        s.revoke_channel('alice', 'email')  # moves ISSUED -> DENIED
        self.assertTrue(s.revoke(h),
                        'revoke of an already-denied request must report success')

    def test_consume_just_after_change_fails(self):
        token = self._issued_token('alice', 'email', 'alice@example.com')
        self.store.revoke_channel('alice', 'email')
        # A consume immediately after the change cannot win.
        self.assertIsNone(self.store.consume_token(token, 'recovery'))


if __name__ == '__main__':
    unittest.main()

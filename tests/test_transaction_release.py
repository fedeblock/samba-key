"""Rejected operations must not retain SQLite's write lock."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from samba_key.store import Store


class TransactionReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'store.db')
        self.store = Store(self.path, max_pending_per_account=1)
        self.addCleanup(self.store.close)

    def assert_other_writer_can_write(self):
        with sqlite3.connect(self.path, timeout=0.05) as other:
            other.execute('INSERT INTO ratelimit(key,ts) VALUES (?,?)', ('other', 1))

    def test_rejected_duplicate_request_releases_lock(self):
        self.assertIsNotNone(self.store.create_request('alice', 900))
        self.assertIsNone(self.store.create_request('alice', 900))
        self.assert_other_writer_can_write()

    def test_empty_delivery_poll_releases_lock(self):
        self.assertEqual(self.store.approved_requests(), [])
        self.assert_other_writer_can_write()

    def test_approval_of_missing_handle_releases_lock(self):
        self.assertFalse(self.store.approve('not-found'))
        self.assert_other_writer_can_write()

    def test_rejected_rate_limit_releases_lock(self):
        self.assertTrue(self.store.hit('test', 1, 300, 100))
        self.assertFalse(self.store.hit('test', 1, 300, 100))
        self.assert_other_writer_can_write()

    def test_channel_challenge_cap_releases_lock(self):
        self.assertIsNone(self.store.create_channel_challenge(
            'alice', 'email', 'alice@example.test', ttl=900, max_clients=0))
        self.assert_other_writer_can_write()

    def test_request_exception_rolls_back_and_releases_lock(self):
        with patch('samba_key.store.secrets.token_urlsafe', side_effect=RuntimeError('failed')):
            with self.assertRaises(RuntimeError):
                self.store.create_request('alice', 900)
        self.assertFalse(self.store._conn.in_transaction)
        self.assert_other_writer_can_write()

    def test_channel_binding_exception_rolls_back_and_releases_lock(self):
        code = self.store.create_channel_challenge('alice', 'email', 'alice@example.test', 900)
        with patch.object(self.store, '_invalidate_account_unlocked', side_effect=RuntimeError('failed')):
            with self.assertRaises(RuntimeError):
                self.store.verify_channel_challenge('alice', 'email', 'alice@example.test', code)
        self.assertEqual(self.store.channel_rows('alice'), [])
        self.assert_other_writer_can_write()

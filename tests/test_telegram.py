"""Telegram binding must come only from a verified private bot conversation.

The chat id is provided by Telegram in an update the bot receives from the
user's *private* chat; it is never accepted from a web request.  The binder
consumes a one-time challenge code (issued by the admin when enrolling) and binds
the chat id that the verified conversation supplies.  Everything else -- group /
supergroup / channel chats, a sender id that differs from the chat id, a
non-positive id, a wrong or replayed or expired code, a code for another user --
is rejected.
"""
import unittest

from samba_key.store import Store
from samba_key.telegram import TelegramBinder, TelegramPoller, make_polling_get_updates


def make_store():
    import os, tempfile
    return Store(os.path.join(tempfile.mkdtemp(), 'c.db'))


def _update(chat_type, chat_id, sender_id, text):
    return {'message': {'chat': {'id': chat_id, 'type': chat_type},
                        'from': {'id': sender_id},
                        'text': text}}


class TelegramBinderTests(unittest.TestCase):
    def setUp(self):
        self.store = make_store()
        self.addCleanup(self.store.close)
        # Issue a real challenge (as the admin enrollment would).
        self.code = self.store.create_channel_challenge('alice', 'telegram', '',
                                                        ttl=900)
        self.binder = TelegramBinder(self.store, 'bot-token')

    def _private_update(self, text, chat_id=123456, sender_id=123456):
        return _update('private', chat_id, sender_id, text)

    def test_failed_attempts_use_store_lock(self):
        import threading
        from unittest.mock import MagicMock
        lock = threading.RLock()
        connection = MagicMock()
        def execute(*args):
            self.assertTrue(lock._is_owned(), 'SQLite must be protected by the store lock')
            result = MagicMock()
            result.fetchone.return_value = (0,)
            return result
        connection.execute.side_effect = execute
        fake_store = MagicMock()
        fake_store._lock = lock
        fake_store._conn = connection
        binder = TelegramBinder(fake_store, 'bot-token')
        binder._record_fail(5)
        self.assertFalse(binder.is_rate_limited(5))

    def test_binds_from_verified_private_conversation(self):
        username = self.binder.process_update(self._private_update('/start ' + self.code))
        self.assertEqual(username, 'alice')
        rows = self.store.channel_rows('alice')
        self.assertEqual(rows[0]['kind'], 'telegram')
        self.assertEqual(rows[0]['value'], '123456')

    def test_group_chat_rejected(self):
        self.assertIsNone(self.binder.process_update(
            _update('group', 123456, 123456, '/start ' + self.code)))
        self.assertEqual(len(self.store.channel_rows('alice')), 0)

    def test_supergroup_and_channel_rejected(self):
        self.assertIsNone(self.binder.process_update(
            _update('supergroup', 123456, 123456, '/start ' + self.code)))
        self.assertIsNone(self.binder.process_update(
            _update('channel', 123456, 123456, '/start ' + self.code)))

    def test_sender_id_must_match_chat_id(self):
        self.assertIsNone(self.binder.process_update(
            self._private_update('/start ' + self.code, sender_id=999)))
        self.assertEqual(len(self.store.channel_rows('alice')), 0)

    def test_non_positive_chat_id_rejected(self):
        self.assertIsNone(self.binder.process_update(
            _update('private', -123456, -123456, '/start ' + self.code)))
        self.assertIsNone(self.binder.process_update(
            _update('private', 0, 0, '/start ' + self.code)))

    def test_replayed_code_rejected(self):
        u = self._private_update('/start ' + self.code)
        self.assertIsNotNone(self.binder.process_update(u))
        self.assertIsNone(self.binder.process_update(u))  # single use

    def test_expired_code_rejected(self):
        store = make_store()
        store._now = lambda: 1000.0
        code = store.create_channel_challenge('alice', 'telegram', '', ttl=100)
        store._now = lambda: 5000.0  # past the 100s TTL
        binder = TelegramBinder(store, 'bot-token')
        self.assertIsNone(binder.process_update(_update('private', 1, 1, '/start ' + code)))
        store.close()

    def test_wrong_user_code_rejected(self):
        # Bob's code must not let anyone bind Alice's account.
        store = make_store()
        bob_code = store.create_channel_challenge('bob', 'telegram', '', ttl=900)
        binder = TelegramBinder(store, 'bot-token')
        username = binder.process_update(_update('private', 7, 7, '/start ' + bob_code))
        self.assertEqual(username, 'bob')
        # Alice has no telegram channel bound by Bob's code.
        self.assertEqual([c['value'] for c in store.channel_rows('alice')], [])
        store.close()

    def test_missing_code_rejected(self):
        self.assertIsNone(self.binder.process_update(
            self._private_update('/start')))
        self.assertIsNone(self.binder.process_update(
            self._private_update('hello')))

    def test_failed_binds_are_rate_limited(self):
        # A flood of unknown codes from one chat must stop after the cap.
        store = make_store()
        binder = TelegramBinder(store, 'bot-token', max_failed=3, fail_window=300)
        for i in range(3):
            self.assertIsNone(binder.process_update(
                _update('private', 5, 5, '/start nope-' + str(i))))
        # The fourth unknown code from the same chat is refused outright.
        self.assertIsNone(binder.process_update(
            _update('private', 5, 5, '/start nope-3')))
        self.assertTrue(binder.is_rate_limited(5))
        store.close()


class TelegramPollerTests(unittest.TestCase):
    """The polling backend processes updates through the binder only. The
    network call (getUpdates) is injected, so the poller is tested with no
    network; a chat id can be learned only from updates the bot returns."""

    def _binder(self, store=None):
        store = store or make_store()
        code = store.create_channel_challenge('alice', 'telegram', '', ttl=900)
        return store, code, TelegramBinder(store, 'bot-token')

    def test_only_successful_binding_receives_confirmation(self):
        store, code, binder = self._binder()
        self.addCleanup(store.close)
        confirmations = []
        updates = [
            dict(_update('group', 123, 123, '/start ' + code), update_id=1),
            dict(_update('private', 123, 123, '/start ' + code), update_id=2),
            dict(_update('private', 123, 123, '/start ' + code), update_id=3),
        ]
        poller = TelegramPoller(binder, lambda offset: updates,
                                on_bound=confirmations.append)
        self.assertEqual(poller.run_once(), 3)
        self.assertEqual(confirmations, [123])
        self.assertEqual(poller.offset, 4)

    def test_confirmation_failure_does_not_break_polling_or_binding(self):
        store, code, binder = self._binder()
        self.addCleanup(store.close)
        update = dict(_update('private', 123, 123, '/start ' + code), update_id=9)
        def fail(_):
            raise OSError('offline')
        poller = TelegramPoller(binder, lambda offset: [update], on_bound=fail)
        self.assertEqual(poller.run_once(), 1)
        self.assertEqual(poller.offset, 10)
        self.assertEqual(store.channel_rows('alice')[0]['value'], '123')

    def test_run_once_binds_from_injected_updates(self):
        store, code, binder = self._binder()
        updates = [{'update_id': 10, 'message': {'chat': {'id': 123, 'type': 'private'},
                    'from': {'id': 123}, 'text': '/start ' + code}}]
        served = [updates]
        poller = TelegramPoller(binder, lambda offset: served[0])
        self.assertEqual(poller.run_once(), 1)
        self.assertEqual(poller.offset, 11)
        self.assertEqual(store.channel_rows('alice')[0]['value'], '123')
        store.close()

    def test_offset_is_injected_into_get_updates(self):
        store, code, binder = self._binder()
        seen = []
        poller = TelegramPoller(binder, lambda offset: (seen.append(offset), [])[1])
        poller.offset = 42
        poller.run_once()
        self.assertEqual(seen, [42])
        store.close()

    def test_transport_failure_is_swallowed_and_retried(self):
        store, code, binder = self._binder()
        state = {'fail': True}

        def get_updates(offset):
            if state['fail']:
                raise OSError('network down')
            return [{'update_id': 7, 'message': {'chat': {'id': 55, 'type': 'private'},
                    'from': {'id': 55}, 'text': '/start ' + code}}]

        poller = TelegramPoller(binder, get_updates)
        self.assertEqual(poller.run_once(), 0)  # failure swallowed, no offset
        self.assertEqual(poller.offset, 0)
        state['fail'] = False
        self.assertEqual(poller.run_once(), 1)  # retried on recovery
        self.assertEqual(poller.offset, 8)
        store.close()

    def test_run_loops_until_stop_event(self):
        store, code, binder = self._binder()
        import threading
        stop = threading.Event()
        delivered = [0]

        def get_updates(offset):
            if delivered[0] == 0:
                delivered[0] = 1
                stop.set()  # stop after the first batch
                return [{'update_id': 3, 'message': {'chat': {'id': 77, 'type': 'private'},
                         'from': {'id': 77}, 'text': '/start ' + code}}]
            return []

        poller = TelegramPoller(binder, get_updates, stop_event=stop,
                                poll_interval=0.01)
        poller.run()
        self.assertEqual(store.channel_rows('alice')[0]['value'], '77')
        store.close()


class TelegramGetUpdatesTests(unittest.TestCase):
    """The real getUpdates provider is exercised without a network by injecting
    urlopen; the bot token reaches the request URL and never a log, and a bad
    API response or a transport error yields an empty list (retried next cycle)."""

    def _capture(self, body):
        requests = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return body.encode() if n is None or n < 0 else body[:n].encode()

        def fake_urlopen(req, *a, **k):
            requests.append(req)
            return Resp()
        return requests, fake_urlopen

    def test_get_updates_parses_result(self):
        import json
        body = json.dumps({'ok': True, 'result': [
            {'update_id': 5, 'message': {'chat': {'id': 1, 'type': 'private'},
                                         'from': {'id': 1}, 'text': 'hi'}}]})
        requests, fake = self._capture(body)
        get = make_polling_get_updates('TOKEN123', 'https://api.telegram.org',
                                      urlopen=fake)
        updates = get(0)
        self.assertEqual(updates[0]['update_id'], 5)
        # The token reaches the URL and the query is well-formed JSON.
        url = requests[0].full_url
        self.assertIn('bot', url)
        self.assertIn('TOKEN123', url)
        self.assertIn('offset=0', url)
        import urllib.parse
        query = urllib.parse.urlparse(url).query
        params = urllib.parse.parse_qs(query)
        self.assertEqual(json.loads(params['allowed_updates'][0]), ['message'])

    def test_api_base_is_used(self):
        import json
        requests, fake = self._capture(json.dumps({'ok': True, 'result': []}))
        get = make_polling_get_updates('T', 'https://example.org', urlopen=fake)
        get(0)
        self.assertIn('example.org', requests[0].full_url)

    def test_empty_result_and_errors_raise(self):
        # An empty result is success (no updates); a transport/API error raises
        # so the poller can back off instead of spinning.
        import json
        from samba_key.telegram import TelegramAPIError
        reqs, fake = self._capture(json.dumps({'ok': True, 'result': []}))
        get = make_polling_get_updates('T', 'https://api.telegram.org', urlopen=fake)
        self.assertEqual(get(0), [])

        def boom(*a, **k):
            raise OSError('network down')
        get2 = make_polling_get_updates('T', 'https://api.telegram.org', urlopen=boom)
        with self.assertRaises(TelegramAPIError):
            get2(0)

    def test_ok_false_raises(self):
        import json
        from samba_key.telegram import TelegramAPIError
        reqs, fake = self._capture(json.dumps({'ok': False,
                                               'error_code': 400,
                                               'description': 'bad token'}))
        get = make_polling_get_updates('T', 'https://api.telegram.org', urlopen=fake)
        with self.assertRaises(TelegramAPIError):
            get(0)

    def test_poller_binds_through_injected_get_updates(self):
        import json
        store = make_store()
        code = store.create_channel_challenge('alice', 'telegram', '', ttl=900)
        body = json.dumps({'ok': True, 'result': [
            {'update_id': 1, 'message': {'chat': {'id': 222, 'type': 'private'},
                                         'from': {'id': 222}, 'text': '/start ' + code}}]})
        requests, fake = self._capture(body)
        get = make_polling_get_updates('T', 'https://api.telegram.org', urlopen=fake)
        poller = TelegramPoller(TelegramBinder(store, 'T'), get)
        self.assertEqual(poller.run_once(), 1)
        self.assertEqual(store.channel_rows('alice')[0]['value'], '222')
        store.close()


class TelegramPollerBehaviorTests(unittest.TestCase):
    """The poller must pause between cycles, be interruptible on stop, and back
    off on repeated failures. These use a fake waiter so they are deterministic
    and fast; the real wiring is covered in test_authority_main."""

    def _binder(self):
        store = make_store()
        return store

    class _Stop:
        """A fake stop event that stops after ``limit`` waits, recording delays.
        is_set() drives the loop and wait() both pauses (deterministically) and
        advances the counter, so the loop ends without a real sleep."""

        def __init__(self, limit):
            self.limit = limit
            self.n = 0
            self._waits = []

        def is_set(self):
            return self.n >= self.limit

        def wait(self, delay):
            self._waits.append(delay)
            self.n += 1
            return self.is_set()

    def test_respects_interval_and_stops(self):
        """With the real loop and a stop event, it must not spin: a short run
        with a small interval makes a bounded number of calls, and stop ends it
        promptly. (Fails on the old no-op default sleep, which would spin.)"""
        import threading
        import time
        store = self._binder()
        calls = [0]

        def get_updates(offset):
            calls[0] += 1
            return []

        stop = threading.Event()
        poller = TelegramPoller(TelegramBinder(store, 'T'), get_updates,
                                stop_event=stop, poll_interval=0.15)
        t = threading.Thread(target=poller.run, daemon=True)
        t.start()
        time.sleep(0.45)  # ~3 cycles at 0.15s
        stop.set()
        t.join(timeout=2)
        self.assertFalse(t.is_alive(), 'stop must end the loop promptly')
        # With a real 0.15s pause, ~3 calls; the old no-op default would give
        # thousands. Assert a tight bound so a no-op regression is caught.
        self.assertLess(calls[0], 12)
        self.assertGreaterEqual(calls[0], 2)
        store.close()

    def test_backs_off_on_repeated_failures(self):
        """Repeated failures grow the spacing up to the cap (deterministic via a
        fake stop event that records the waited delays)."""
        from samba_key.telegram import TelegramAPIError
        store = self._binder()

        def always_fail(offset):
            raise TelegramAPIError('down')

        stop = self._Stop(limit=5)
        poller = TelegramPoller(TelegramBinder(store, 'T'), always_fail,
                                stop_event=stop, poll_interval=1.0,
                                max_backoff=8.0)
        poller.run()
        self.assertEqual(stop._waits, [1.0, 2.0, 4.0, 8.0, 8.0])
        store.close()

    def test_retry_after_is_honored(self):
        from samba_key.telegram import TelegramAPIError
        store = self._binder()

        def rate_limited(offset):
            raise TelegramAPIError('too many requests', retry_after=10.0)

        stop = self._Stop(limit=2)
        poller = TelegramPoller(TelegramBinder(store, 'T'), rate_limited,
                                stop_event=stop, poll_interval=1.0,
                                max_backoff=300.0)
        poller.run()
        # The first failed cycle's delay is max(retry_after=10, backoff=1).
        self.assertEqual(stop._waits[0], 10.0)
        store.close()

    def test_success_resets_backoff(self):
        store = self._binder()
        state = {'n': 0}

        def flaky(offset):
            state['n'] += 1
            if state['n'] < 3:
                raise TelegramAPIError('transient')
            return []

        stop = self._Stop(limit=3)
        poller = TelegramPoller(TelegramBinder(store, 'T'), flaky,
                                stop_event=stop, poll_interval=1.0,
                                max_backoff=8.0)
        poller.run()
        # After the first two failures the third succeeds, so the third delay
        # resets to the base interval (1.0), not 4.0.
        self.assertEqual(stop._waits, [1.0, 2.0, 1.0])
        store.close()


if __name__ == '__main__':
    unittest.main()

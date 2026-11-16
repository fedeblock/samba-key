"""Telegram recovery binding, driven only by the verified bot conversation.

The chat id is supplied by Telegram inside an update the bot receives from the
user's *private* chat; it is never accepted from a web request.  A user, after
reauthenticating through the portal, obtains a one-time challenge code; they
send ``/start <code>`` to the bot in their private chat, and this binder binds
that chat id to the account the code belongs to.

Only the bot backend (polling getUpdates, or a webhook guarded by
``X-Telegram-Bot-Api-Secret-Token`` checked with ``hmac.compare_digest``) may
call :meth:`process_update`.  Polling is the safer default.
"""
import hmac
import time


class TelegramBinder:
    def __init__(self, store, bot_token, now_func=None,
                 max_failed=5, fail_window=900):
        self.store = store
        self.bot_token = bot_token
        self.now = now_func or time.time
        self.max_failed = max_failed
        self.fail_window = fail_window

    # -- the only caller of the binding ----------------------------------
    def process_update(self, update):
        """Bind a chat id from a verified private conversation, or None.

        Returns the username that was bound, or None for any update that does
        not prove a private, same-sender conversation carrying a valid one-time
        code.  A chat id is only ever read from the update, never from a request.
        """
        if self._no_update(update):
            return None
        message = update.get('message') or update.get('edited_message') or {}
        chat = message.get('chat') or {}
        sender = message.get('from') or {}
        chat_id = chat.get('id')
        sender_id = sender.get('id')

        # Must be a *private* chat, and the sender must own that chat id.
        if chat.get('type') != 'private':
            return None
        if not isinstance(chat_id, int) or chat_id <= 0:
            return None
        if sender_id != chat_id:
            return None
        # Rate-limit unknown-code floods per chat.
        if self.is_rate_limited(chat_id):
            return None

        text = (message.get('text') or '').strip()
        parts = text.split()
        if len(parts) != 2 or parts[0] != '/start':
            return None
        code = parts[1]

        # Consume the one-time challenge and bind the chat id that arrived in
        # this verified private conversation. The account is discovered from the
        # challenge (never supplied by the caller), and the chat id is only
        # trusted because it came from Telegram, not a web request.
        account = self.store.bind_by_code('telegram', code, str(chat_id))
        if account is None:
            self._record_fail(chat_id)
            return None
        return account

    def _no_update(self, update):
        return not isinstance(update, dict)

    # -- per-chat rate limiting of failed binds --------------------------
    def _record_fail(self, chat_id):
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                'INSERT INTO ratelimit(key, ts) VALUES (?,?)',
                ('tg-fail-' + str(chat_id), self.now()))

    def is_rate_limited(self, chat_id):
        """True if this chat has hit the failed-bind cap in the window. A pure
        query: checking does not itself record."""
        now = self.now()
        with self.store._lock:
            (n,) = self.store._conn.execute(
                'SELECT COUNT(*) FROM ratelimit WHERE key=? AND ts>?',
                ('tg-fail-' + str(chat_id), now - self.fail_window)).fetchone()
        return n >= self.max_failed

    # -- webhook secret (only if polling is not used) --------------------
    @staticmethod
    def verify_webhook_secret(provided, expected):
        return hmac.compare_digest(str(provided or ''), str(expected or ''))


class TelegramAPIError(Exception):
    """A Telegram API or transport error. Carries no secret; ``retry_after`` is
    populated on rate limiting (HTTP 429 / 503)."""
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class TelegramPoller:
    """Authority-side polling backend for the Telegram bot.

    The network call (``getUpdates``) is an injectable seam so the poller can be
    tested without any network. It is the only caller of
    :meth:`TelegramBinder.process_update` on the authority side, so a chat id can
    be learned and bound only from updates Telegram itself returns, never from a
    web request. The bot token stays in the authority process; the poller keeps
    an offset so an update is not processed twice.

    The loop pauses for ``poll_interval`` between cycles, is interruptible on the
    stop event, and backs off exponentially on repeated failures (with a hard
    cap), so a transient outage or API rate limit does not spin the API.
    """

    def __init__(self, binder, get_updates, stop_event=None,
                 poll_interval=1.0, time_sleep=None, waiter=None,
                 max_backoff=300.0, on_bound=None):
        self.binder = binder
        self.get_updates = get_updates
        self.stop_event = stop_event
        self.poll_interval = poll_interval
        self.time_sleep = time_sleep or __import__('time').sleep
        # A waiter(delay) -> stopped flag makes the loop testable and
        # interruptible; by default it waits on the stop event.
        self.waiter = waiter
        self.max_backoff = max_backoff
        self.on_bound = on_bound
        self.offset = 0
        self.processed = 0
        self.consecutive_failures = 0
        self.last_error = None
        self.retry_after = None

    def run_once(self):
        """Fetch one batch of updates and process each. Returns the number
        processed. A transport/API failure is swallowed (the offset is not
        advanced past failed updates, so they are retried) and recorded in
        ``last_error`` so the loop can back off."""
        self.last_error = None
        self.retry_after = None
        try:
            updates = self.get_updates(self.offset)
        except Exception as exc:  # noqa: BLE001 - a failed poll is retried
            self.last_error = exc
            if isinstance(exc, TelegramAPIError) and exc.retry_after:
                self.retry_after = exc.retry_after
            return 0
        if not isinstance(updates, list):
            return 0
        handled = 0
        for update in updates:
            # A bind attempt is always consumed exactly once by the binder's
            # one-time challenge, even if it fails, so we advance the offset
            # regardless of the bind result.
            bound_account = self.binder.process_update(update)
            if bound_account is not None and self.on_bound is not None:
                message = update.get('message') or update.get('edited_message') or {}
                chat_id = (message.get('chat') or {}).get('id')
                try:
                    self.on_bound(chat_id)
                except Exception:
                    # The binding already succeeded; an acknowledgement failure
                    # must not roll it back or stop processing later updates.
                    pass
            update_id = update.get('update_id') if isinstance(update, dict) else None
            if isinstance(update_id, int):
                self.offset = max(self.offset, update_id + 1)
            handled += 1
        self.processed += handled
        return handled

    def _wait(self, delay):
        """Interruptible pause. Returns True if the stop event fired."""
        if self.waiter is not None:
            return bool(self.waiter(delay))
        stop = self.stop_event
        if stop is not None:
            return stop.wait(delay)
        self.time_sleep(delay)
        return False

    def run(self):
        """Poll until the stop event is set, backing off on failures."""
        stop = self.stop_event
        self.consecutive_failures = 0
        while stop is None or not stop.is_set():
            self.run_once()
            if self.last_error is not None:
                self.consecutive_failures += 1
                backoff = min(self.max_backoff,
                              self.poll_interval * (2 ** (self.consecutive_failures - 1)))
                delay = max(self.retry_after or 0.0, backoff)
            else:
                self.consecutive_failures = 0
                delay = self.poll_interval
            if self._wait(delay):
                break


def _retry_after_from_http(exc):
    """Read a Retry-After hint from an HTTP 429/503 (header or body)."""
    import json as _json
    for header in ('retry-after', 'Retry-After', 'x-telegram-bot-api-retry-after'):
        value = exc.headers.get(header) if hasattr(exc, 'headers') else None
        if value:
            try:
                return float(value)
            except ValueError:
                pass
    body = getattr(exc, 'read', None)
    if callable(body):
        try:
            data = _json.loads(body())
            params = data.get('parameters', {}) if isinstance(data, dict) else {}
            if isinstance(params, dict) and 'retry_after' in params:
                return float(params['retry_after'])
        except Exception:  # noqa: BLE001 - best effort
            pass
    return None


def make_polling_get_updates(bot_token, api_base,
                             urlopen=None, timeout=10):
    """Build a ``get_updates(offset) -> list`` backed by the real Telegram API.

    The bot token stays in the authority process and is never logged. The HTTP
    call is injected (``urlopen``) so the poller can be tested without a
    network. A transport or API error raises ``TelegramAPIError`` (with a
    ``retry_after`` on HTTP 429/503) so the poller can distinguish "no updates"
    from "outage" and back off; this exercises the API call shape only and has
    not been run against a live Telegram server.
    """
    import json
    import urllib.parse
    import urllib.request
    import urllib.error
    import ssl
    if urlopen is None:
        urlopen = urllib.request.urlopen
    token = urllib.parse.quote(str(bot_token), safe='')
    base = str(api_base).rstrip('/') or 'https://api.telegram.org'

    def get_updates(offset):
        query = urllib.parse.urlencode({'offset': offset, 'timeout': 0,
                                        'allowed_updates': json.dumps(['message'])})
        url = base + '/bot' + token + '/getUpdates?' + query
        req = urllib.request.Request(url, headers={}, method='GET')
        try:
            with urlopen(req, timeout=timeout,
                         context=ssl.create_default_context()) as resp:
                data = json.loads(resp.read(65536))
        except urllib.error.HTTPError as exc:
            raise TelegramAPIError(
                'telegram api error %s' % (getattr(exc, 'code', '?'),
                                           ),
                retry_after=_retry_after_from_http(exc)) from None
        except Exception as exc:  # noqa: BLE001 - surface to the poller
            raise TelegramAPIError('telegram transport error') from exc
        if not isinstance(data, dict):
            raise TelegramAPIError('telegram returned a non-object')
        if not data.get('ok'):
            raise TelegramAPIError('telegram api reported an error')
        result = data.get('result')
        return result if isinstance(result, list) else []

    return get_updates


def main():
    import sys
    print('telegram.py is a library module; the bot backend wires it.',
          file=sys.stderr)
    return 1

"""Persistent state, used by two *separate* stores.

The privileged reset authority owns one store (its own file, mode 0600, owned by
the authority user/root) that holds the recovery **requests** -- the single-use
ledger.  The web portal owns a *different* store for its channel bindings and
rate-limit counters and never opens the authority's file.  That separation is
what makes "the portal cannot advance a request's state" a real guarantee: the
portal has no write path to the ledger at all.

A recovery request is created pending, approved or denied by the admin
principal, issued to the requesting portal exactly once, and consumed at most
once.  Only a SHA-256 digest of the user-facing token is exposed outside the
authority store; the raw token lives in the privileged store at 0600 and is
purged promptly.
"""
import hashlib
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    account TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (account, kind)
);
-- Recovery requests (authority store). The destination is not chosen by the
-- requester: MINT carries the account and channel type; the authority resolves the
-- destination from its own `channels` table at delivery. At approval the request
-- pins `binding_fingerprint` = sha256(kind|value) of the binding then; delivery
-- refuses if the binding has since changed, and any channel change invalidates
-- the account's in-flight requests. This is what stops a portal from diverting
-- an approved link to a channel it controls.
CREATE TABLE IF NOT EXISTS requests (
    handle TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    kind TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'auto',
    binding_fingerprint TEXT NOT NULL DEFAULT '',
    token_digest TEXT UNIQUE,
    status TEXT NOT NULL,
    issued INTEGER NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ratelimit (
    key TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_clients (
    client TEXT PRIMARY KEY,
    last_seen REAL NOT NULL
);
-- One-time channel-verification challenges (authority store). A code proves a
-- human completed a step on a channel; it is consumed exactly once and only its
-- SHA-256 digest is stored. Enrollment is admin-initiated: a compromised portal
-- cannot reach these admin-only operations, so it cannot inject a binding.
CREATE TABLE IF NOT EXISTS channel_challenges (
    handle TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    code_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL
);
"""

PENDING = 'pending'
APPROVED = 'approved'
ISSUED = 'issued'
USED = 'used'
DENIED = 'denied'

# States in which a token may be consumed (i.e. a reset attempted).
CONSUMABLE = (APPROVED, ISSUED)


def digest_token(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


@dataclass
class Request:
    handle: str
    account: str
    kind: str
    status: str
    expires_at: float
    channel: str = 'auto'


@dataclass
class Binding:
    kind: str
    value: str


class Store:
    def __init__(self, path, now=None, max_pending_per_account=1, max_pending_global=1000):
        self.path = path
        self._now = now or time.time
        self._lock = threading.RLock()
        self.max_pending_per_account = max_pending_per_account
        self.max_pending_global = max_pending_global
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _init_schema(self):
        with self._lock:
            self._conn.executescript(SCHEMA)
            columns = {row[1] for row in self._conn.execute('PRAGMA table_info(requests)')}
            if 'channel' not in columns:
                self._conn.execute("ALTER TABLE requests ADD COLUMN channel TEXT NOT NULL DEFAULT 'auto'")
            self._conn.commit()

    def _connect(self):
        return self._conn

    # --- Channel bindings (AUTHORITY store, admin-only) -----------------
    # The authority owns the bindings; a portal process never opens this file,
    # so a compromised portal cannot read, add or alter a destination. Binding
    # also invalidates the account's in-flight requests, so a destination cannot
    # be swapped in after a request is pending or approved.
    def bind_channel(self, account, kind, value, now=None):
        if kind not in ('email', 'telegram'):
            raise ValueError('unknown channel kind')
        now = self._now() if now is None else now
        with self._lock, self._conn:
            self._conn.execute(
                'INSERT INTO channels(account, kind, value, created_at) VALUES (?,?,?,?) '
                'ON CONFLICT(account, kind) DO UPDATE SET value=excluded.value, '
                'created_at=excluded.created_at',
                (account, kind, value, now))
            self._conn.commit()
        self.invalidate_requests_for_account(account)

    def revoke_channel(self, account, kind):
        with self._lock, self._conn:
            self._conn.execute('DELETE FROM channels WHERE account=? AND kind=?', (account, kind))
            self._conn.commit()
        self.invalidate_requests_for_account(account)

    def revoke_all(self, account):
        with self._lock, self._conn:
            self._conn.execute('DELETE FROM channels WHERE account=?', (account,))
            self._conn.commit()
        self.invalidate_requests_for_account(account)

    def channel_rows(self, account):
        with self._lock:
            rows = self._conn.execute(
                'SELECT kind, value FROM channels WHERE account=? ORDER BY kind',
                (account,)).fetchall()
        return [{'kind': k, 'value': v} for k, v in rows]

    def resolve_binding(self, account, channel='auto'):
        """Pick the delivery destination for an account from its bindings, or
        None. E-mail is preferred, then Telegram. The authority alone knows
        where a link goes; the portal never does."""
        with self._lock:
            rows = self._conn.execute(
                'SELECT kind, value FROM channels WHERE account=? ORDER BY kind',
                (account,)).fetchall()
        if not rows:
            return None
        if channel != 'auto':
            return next((Binding(kind, value) for kind, value in rows if kind == channel), None)
        for kind, value in rows:
            if kind == 'email':
                return Binding('email', value)
        for kind, value in rows:
            if kind == 'telegram':
                return Binding('telegram', value)
        return Binding(rows[0][0], rows[0][1])

    def binding_fingerprint(self, account, channel='auto'):
        """sha256(kind|value) of the primary binding, or '' if unbound. Pinned
        at approval so delivery can detect a destination that changed."""
        binding = self.resolve_binding(account, channel)
        if binding is None:
            return ''
        return hashlib.sha256((binding.kind + '|' + binding.value).encode('utf-8')).hexdigest()

    # --- Channel verification challenges (AUTHORITY store, admin-only) ----
    # A one-time code proves a human completed a step on a channel. It is
    # created by an admin (or the authority-side Telegram poller) and consumed
    # exactly once. The portal cannot reach these operations, so it cannot
    # inject a binding. Only the code's SHA-256 digest is stored.
    def pending_challenge_count(self, account, kind):
        now = self._now()
        with self._lock:
            n = self._conn.execute(
                'SELECT COUNT(*) FROM channel_challenges WHERE account=? AND kind=? '
                'AND status=? AND expires_at>?',
                (account, kind, 'pending', now)).fetchone()[0]
        return n

    def create_channel_challenge(self, account, kind, value, ttl,
                                 max_clients=5000, now=None):
        """Record a pending challenge and return the raw one-time code, or None
        on a cap (fail closed). The raw code is what the admin relays (Telegram)
        or that the authority sends (e-mail); it is not persisted in the clear.

        For Telegram the chat id is unknown at enrollment, so ``value`` may be
        empty; the chat id is learned when the user sends ``/start <code>`` and
        is what gets bound. For e-mail ``value`` is the address to challenge."""
        if kind not in ('email', 'telegram'):
            raise ValueError('unknown channel kind')
        if kind == 'email' and not (isinstance(value, str) and value):
            raise ValueError('e-mail challenge requires an address')
        now = self._now() if now is None else now
        with self._lock, self._conn:
            if self.pending_challenge_count(account, kind) >= 1:
                return None
            key = 'challenge-' + kind
            self._conn.execute('DELETE FROM ratelimit WHERE key=? AND ts<=?',
                               (key, now - 300))
            if self._conn.execute('SELECT COUNT(*) FROM ratelimit WHERE key=? AND ts>?',
                                  (key, now - 300)).fetchone()[0] >= max_clients:
                return None
            code = secrets.token_urlsafe(24)
            stored_value = value if isinstance(value, str) else ''
            self._conn.execute('INSERT INTO ratelimit(key, ts) VALUES (?,?)', (key, now))
            self._conn.execute(
                'INSERT INTO channel_challenges(handle, account, kind, value, '
                'code_digest, status, expires_at, created_at) '
                'VALUES (?,?,?,?,?,?,?,?)',
                (secrets.token_urlsafe(24), account, kind, stored_value, digest_token(code),
                 'pending', now + ttl, now))
            self._conn.commit()
        return code

    def verify_channel_challenge(self, account, kind, value, code):
        """Consume a pending, unexpired challenge whose code matches, then bind
        the channel. Returns True on success. For e-mail the incoming ``value``
        (the address) must match the one challenged; for Telegram the chat id is
        only learned on ``/start``, so the incoming ``value`` (the chat id from
        the verified conversation) is what gets bound. A binding change
        invalidates the account's in-flight requests so a destination cannot be
        swapped after approval."""
        if kind not in ('email', 'telegram'):
            raise ValueError('unknown channel kind')
        if not isinstance(code, str) or not code:
            return False
        with self._lock, self._conn:
            now = self._now()
            row = self._conn.execute(
                'SELECT account, kind FROM channel_challenges '
                'WHERE code_digest=? AND status=? AND expires_at>?',
                (digest_token(code), 'pending', now)).fetchone()
            if row is None:
                return False
            stored_account, stored_kind = row[0], row[1]
            if stored_account != account or stored_kind != kind:
                return False
            # E-mail must match the challenged address; Telegram binds the
            # chat id that arrived in the verified private conversation.
            if kind == 'email':
                if not isinstance(value, str) or not value:
                    return False
                stored_value = self._conn.execute(
                    'SELECT value FROM channel_challenges WHERE code_digest=?',
                    (digest_token(code),)).fetchone()[0]
                if stored_value != value:
                    return False
            elif not isinstance(value, str) or not value.isdigit() or \
                    not (1 <= int(value) <= 10**18):
                # A Telegram private chat id is a positive integer.
                return False
            self._conn.execute('DELETE FROM channel_challenges WHERE code_digest=?',
                               (digest_token(code),))
            self._conn.execute(
                'INSERT INTO channels(account, kind, value, created_at) VALUES (?,?,?,?) '
                'ON CONFLICT(account, kind) DO UPDATE SET value=excluded.value, '
                'created_at=excluded.created_at',
                (account, kind, value, now))
            # A binding change must invalidate this account's in-flight requests
            # (pending, approved AND issued) so a destination cannot be swapped
            # after approval and an already-issued link to the old destination
            # dies with the change. Shared, in the same lock and transaction.
            self._invalidate_account_unlocked(account)
            self._conn.commit()
        return True

    def bind_by_code(self, kind, code, value):
        """Consume a pending challenge by its code (account discovered from the
        challenge, not supplied by the caller) and bind ``value`` to that
        account. Used by the authority-side Telegram poller, which learns the
        account from the challenge the user's ``/start <code>`` references. The
        chat id is only trusted because it arrived in a verified private
        conversation. Returns the bound account or None."""
        if kind not in ('email', 'telegram'):
            raise ValueError('unknown channel kind')
        if not isinstance(code, str) or not code:
            return None
        with self._lock:
            now = self._now()
            row = self._conn.execute(
                'SELECT account, kind FROM channel_challenges '
                'WHERE code_digest=? AND status=? AND expires_at>?',
                (digest_token(code), 'pending', now)).fetchone()
            if row is None or row[1] != kind:
                return None
            account, stored_kind = row[0], row[1]
            if not self.verify_channel_challenge(account, kind, value, code):
                return None
            return account

    def purge_challenges(self):
        now = self._now()
        with self._lock, self._conn:
            self._conn.execute(
                'DELETE FROM channel_challenges WHERE expires_at<=? OR status=?',
                (now, 'consumed'))
            self._conn.commit()

    # --- Recovery requests (AUTHORITY store) -----------------------------
    def create_request(self, account, ttl, kind='recovery', channel='auto'):
        """Create a pending request for an account, enforcing per-account and
        global caps. Returns a random ``handle`` (an opaque reference, not the
        link secret) or ``None`` on a cap (fail closed; the portal shows a
        uniform message). The channel is a type, not a destination: the authority
        resolves the destination from its own bindings at delivery."""
        if channel not in ('auto', 'email', 'telegram'):
            return None
        now = self._now()
        with self._lock, self._conn:
            self._purge_expired(now)
            per_account = self._conn.execute(
                'SELECT COUNT(*) FROM requests WHERE account=? AND status=? AND expires_at>?',
                (account, PENDING, now)).fetchone()[0]
            if per_account >= self.max_pending_per_account:
                return None
            total = self._conn.execute(
                'SELECT COUNT(*) FROM requests WHERE status=? AND expires_at>?',
                (PENDING, now)).fetchone()[0]
            if total >= self.max_pending_global:
                return None
            handle = secrets.token_urlsafe(32)
            self._conn.execute(
                'INSERT INTO requests(handle, account, kind, channel, binding_fingerprint, '
                'status, issued, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (handle, account, kind, channel, '', PENDING, 0, now, now + ttl))
            self._conn.commit()
        return handle

    def invalidate_requests_for_account(self, account):
        """Move an account's pending, approved AND issued (not-yet-used) requests
        to denied. Called when a binding changes so a destination cannot be
        swapped in after a request is outstanding, and so an already-issued
        link to the old destination dies with the change rather than living until
        its TTL."""
        with self._lock, self._conn:
            n = self._invalidate_account_unlocked(account)
            self._conn.commit()
        return n

    def _invalidate_account_unlocked(self, account):
        """In-place invalidation for a caller that already holds the lock and
        transaction (e.g. verify_channel_challenge, which binds then invalidates
        in one transaction). Includes ISSUED so a sent link is killed."""
        return self._conn.execute(
            "UPDATE requests SET status=? WHERE account=? AND status IN (?,?,?)",
            (DENIED, account, PENDING, APPROVED, ISSUED)).rowcount

    def approve(self, handle):
        """Approve a pending request, pinning the binding fingerprint at this
        moment. Delivery will refuse if the binding changes afterwards."""
        now = self._now()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE requests SET status=? WHERE handle=? AND status=?",
                (APPROVED, handle, PENDING))
            if cur.rowcount == 1:
                account, channel = self._conn.execute(
                    'SELECT account, channel FROM requests WHERE handle=?',
                    (handle,)).fetchone()
                fp = self.binding_fingerprint(account, channel)
                self._conn.execute(
                    'UPDATE requests SET binding_fingerprint=? WHERE handle=?',
                    (fp, handle))
                self._conn.commit()
            return cur.rowcount == 1

    def deny(self, handle):
        """Deny an outstanding request (pending or approved, not yet issued).
        The worker uses this to reject an approved request that has no binding
        or whose destination changed since approval."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE requests SET status=? WHERE handle=? AND status IN (?,?) "
                "AND issued=0",
                (DENIED, handle, PENDING, APPROVED))
            self._conn.commit()
            return cur.rowcount == 1

    def revoke(self, handle):
        """Move an *issued* request to denied, so a token whose delivery failed
        can no longer be consumed. Only issued requests are affected. If the
        request is already denied (e.g. a channel was revoked concurrently) the
        goal -- unusable -- is already met, so this reports success rather than
        the misleading 'revoke did not confirm'."""
        with self._lock, self._conn:
            row = self._conn.execute(
                'SELECT status FROM requests WHERE handle=?', (handle,)).fetchone()
            if row is None:
                return False
            if row[0] == DENIED:
                return True
            cur = self._conn.execute(
                'UPDATE requests SET status=? WHERE handle=? AND status=? AND issued=1',
                (DENIED, handle, ISSUED))
            self._conn.commit()
            return cur.rowcount == 1

    def approved_requests(self, limit=200):
        """Approved, not-yet-issued, unexpired requests for the delivery worker.
        After issue() sets issued=1, a request leaves this set, so it is never
        delivered twice."""
        now = self._now()
        with self._lock, self._conn:
            self._purge_expired(now)
            rows = self._conn.execute(
                'SELECT handle, account, kind, status, expires_at, channel FROM requests '
                'WHERE status=? AND issued=0 AND expires_at>? ORDER BY created_at '
                'LIMIT ?', (APPROVED, now, limit)).fetchall()
        return [Request(*row) for row in rows]

    def pending_requests(self):
        """Admin view: pending handles with account, kind and times. The
        destination is not shown in the clear (it is resolved at delivery)."""
        now = self._now()
        with self._lock:
            rows = self._conn.execute(
                'SELECT handle, account, kind, status, expires_at, channel FROM requests '
                'WHERE status IN (?,?) AND expires_at>?',
                (PENDING, APPROVED, now)).fetchall()
        return [Request(*row) for row in rows]

    def request_binding_fingerprint(self, handle):
        """The binding fingerprint pinned at approval (empty if none)."""
        with self._lock:
            row = self._conn.execute(
                'SELECT binding_fingerprint FROM requests WHERE handle=?',
                (handle,)).fetchone()
        return row[0] if row else ''

    def issue(self, handle, link_ttl):
        """Release the user-facing token exactly once, only when approved.

        The token is generated *here*, so it is never persisted in the clear: only
        its SHA-256 digest is written (for single-use consume). The raw value
        exists only for the duration of this call, inside the authority, and in
        the link the *authority* builds and sends. The portal never sees it.

        As a TOCTOU defense (the delivery worker also checks), the destination
        pinned at approval must still match the current binding; an empty pinned
        fingerprint (no binding) is allowed through, since the worker then denies
        the request for lacking a destination.
        """
        now = self._now()
        with self._lock, self._conn:
            row = self._conn.execute(
                'SELECT account, binding_fingerprint, channel FROM requests '
                'WHERE handle=? AND status=? AND issued=0 AND expires_at>? '
                'AND token_digest IS NULL',
                (handle, APPROVED, now)).fetchone()
            if row is None:
                return None
            account, pinned, channel = row
            if pinned and self.binding_fingerprint(account, channel) != pinned:
                return None
            cur = self._conn.execute(
                'UPDATE requests SET issued=1, status=?, expires_at=? '
                'WHERE handle=? AND status=? AND issued=0 AND expires_at>? AND token_digest IS NULL',
                (ISSUED, now + link_ttl, handle, APPROVED, now))
            if cur.rowcount != 1:
                return None
            token = secrets.token_urlsafe(32)
            self._conn.execute('UPDATE requests SET token_digest=? WHERE handle=?',
                               (digest_token(token), handle))
            self._conn.commit()
        return token

    def peek_token(self, raw, kind):
        """Return a usable request for the token without consuming it.

        The kind must match so a channel-verification token can never serve as a
        recovery token.  Only issued/unexpired requests match; every other state
        (pending, denied, expired, wrong kind, unknown) is indistinguishable.
        """
        digest = digest_token(raw)
        now = self._now()
        with self._lock:
            row = self._conn.execute(
                'SELECT handle, account, kind, status, expires_at, channel FROM requests '
                'WHERE token_digest=? AND kind=? AND status IN (?,?) AND expires_at>?',
                (digest, kind, ISSUED, APPROVED, now)).fetchone()
        if row is None:
            return None
        return Request(*row)

    def recovery_details(self, raw, kind):
        """Return the request and pinned binding only while the link is usable."""
        with self._lock:
            request = self.peek_token(raw, kind)
            if request is None:
                return None
            binding = self.resolve_binding(request.account, request.channel)
            pinned = self.request_binding_fingerprint(request.handle)
            if binding is None or not pinned or pinned != self.binding_fingerprint(request.account, request.channel):
                return None
            return request, binding, self.resolve_binding(request.account, 'email')

    def consume_token(self, raw, kind):
        """Atomically claim a token for a reset. Returns the request or None.

        Exactly one caller can win; the kind is enforced and the claim is the
        only mutation, so a concurrent second attempt and a replay both fail. As
        defense in depth (the store-level invalidation already kills a request
        when its channel changes), the request's binding fingerprint pinned at
        approval must still match the current binding; a changed or revoked
        channel therefore defeats an already-issued link. An empty pinned
        fingerprint (no binding was pinned at approval) matches an empty current
        one, so the no-channel path is unaffected."""
        digest = digest_token(raw)
        now = self._now()
        with self._lock, self._conn:
            prow = self._conn.execute(
                'SELECT handle, account, status, expires_at, binding_fingerprint, channel '
                'FROM requests WHERE token_digest=? AND kind=?',
                (digest, kind)).fetchone()
            if prow is None:
                return None
            handle, account, status, exp, pinned, channel = prow
            if status not in (APPROVED, ISSUED) or not (exp > now):
                return None
            if pinned != self.binding_fingerprint(account, channel):
                # The destination changed/revoked since approval: refuse. This
                # closes the race a store-level invalidation alone could miss.
                return None
            cur = self._conn.execute(
                'UPDATE requests SET status=? WHERE token_digest=? AND kind=? '
                'AND status IN (?,?) AND expires_at>?',
                (USED, digest, kind, APPROVED, ISSUED, now))
            if cur.rowcount != 1:
                return None
            row = self._conn.execute(
                'SELECT handle, account, kind, status, expires_at, channel FROM requests '
                'WHERE token_digest=?', (digest,)).fetchone()
            self._conn.commit()
        return Request(*row)

    def _purge_expired(self, now):
        """Remove expired requests and terminal rows. Called at the start of a
        cap check so a dead request never holds a slot."""
        self._conn.execute(
            'DELETE FROM requests WHERE expires_at<=? OR status=?',
            (now, USED))
        # Terminal request states no longer need to occupy a row.
        self._conn.execute(
            'DELETE FROM requests WHERE status=? OR (status=? AND expires_at<=?)',
            (DENIED, ISSUED, now))

    def purge_expired(self):
        now = self._now()
        with self._lock, self._conn:
            self._purge_expired(now)
            self._conn.execute(
                'DELETE FROM channel_challenges WHERE expires_at<=? OR status=?',
                (now, 'consumed'))
            self._conn.execute('DELETE FROM ratelimit WHERE ts<=?', (now - 86400,))
            self._conn.commit()

    # --- Rate limiting (portal store) ------------------------------------
    def register_recovery_client(self, client, cap, window, retention, now=None):
        """Bound active client identities across threads and portal workers."""
        now = self._now() if now is None else now
        with self._lock:
            try:
                self._conn.execute('BEGIN IMMEDIATE')
                self._conn.execute('DELETE FROM recovery_clients WHERE last_seen<=?',
                                   (now - window,))
                self._conn.execute('DELETE FROM ratelimit WHERE ts<=?',
                                   (now - retention,))
                known = self._conn.execute(
                    'SELECT 1 FROM recovery_clients WHERE client=?', (client,)).fetchone()
                if known is None:
                    total = self._conn.execute('SELECT COUNT(*) FROM recovery_clients').fetchone()[0]
                    if total >= cap:
                        self._conn.commit()
                        return False
                self._conn.execute(
                    'INSERT INTO recovery_clients(client, last_seen) VALUES (?,?) '
                    'ON CONFLICT(client) DO UPDATE SET last_seen=excluded.last_seen',
                    (client, now))
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def hit(self, key, limit, window, now=None):
        now = self._now() if now is None else now
        with self._lock, self._conn:
            self._conn.execute('DELETE FROM ratelimit WHERE key=? AND ts<=?', (key, now - window))
            recent = self._conn.execute(
                'SELECT COUNT(*) FROM ratelimit WHERE key=? AND ts>?',
                (key, now - window)).fetchone()[0]
            if recent >= limit:
                return False
            self._conn.execute('INSERT INTO ratelimit(key, ts) VALUES (?,?)', (key, now))
            self._conn.commit()
        return True

    def close(self):
        with self._lock:
            if getattr(self, '_closed', False):
                return
            self._closed = True
            self._conn.close()

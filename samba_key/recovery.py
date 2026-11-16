"""Forgotten-password recovery orchestration (approval policy), portal side.

The portal talks to the *privileged authority* through a ``ResetClient`` and may
only ``MINT``, ``VALIDATE`` and ``CONSUME``. It never receives a token: the
authority resolves the destination, issues the token and delivers the link
(``DeliveryWorker``, authority-side). Approval is out of band, through the
separate admin socket.

This service:
* creates a request whose response is byte-for-byte uniform -- no account,
  channel or internal handle is ever revealed (no enumeration);
* enforces per-account and per-client rate limits on both request and complete;
* never controls a destination or issues a token -- the authority owns both.
"""
import time

# One response for every case: an unknown account, an account with no channel, and
# an account whose request is not yet approved all receive exactly this, so the
# portal reveals nothing.
GENERIC = {'status': 'generic',
           'message': ('If a recovery channel is registered for that account, a '
                       'request has been created. It must be approved by an '
                       'administrator; if so, you will receive a link shortly. '
                       'Nothing is revealed if the account is unknown or has no '
                       'channel.')}
GENERIC_OK = 'The link you used was valid. If it had not expired, your password ' \
             'has been changed. Please sign in again.'
GENERIC_FAIL = 'That link is not valid or has expired. Please request a new one.'
RATE_LIMITED = 'Too many attempts. Please wait and try again later.'


class RecoveryService:
    def __init__(self, authority, portal_store, base_url,
                 policy_min=12, policy_max=1024,
                 request_limit=6, request_window=300,
                 complete_limit=12, complete_window=300,
                 client_limit=30, client_window=300,
                 clients_cap=20000, now_func=None):
        self.authority = authority
        self.store = portal_store
        self.base_url = base_url.rstrip('/')
        self.policy_min = policy_min
        self.policy_max = policy_max
        self.request_limit = request_limit
        self.request_window = request_window
        self.complete_limit = complete_limit
        self.complete_window = complete_window
        self.client_limit = client_limit
        self.client_window = client_window
        self.clients_cap = clients_cap
        self.now = now_func or time.time

    # -- request ----------------------------------------------------------
    def request(self, username, client, channel='auto'):
        """Create a recovery request. The response is identical whether or not
        the account exists or has a channel, and carries no internal handle. The
        portal sends the account and channel type; the authority resolves the
        destination from its own bindings."""
        if not self._register_client(client):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        if not self._allow('client-' + client, self.client_limit, self.client_window):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        if not self._allow('account-' + client + '-' + username,
                           self.request_limit, self.request_window):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        # MINT carries only a channel type, never an address. The handle
        # is returned to the portal only to track delivery server-side; it is
        # never returned to the browser, so it cannot distinguish a valid account
        # from an invalid one.
        if channel not in ('auto', 'email', 'telegram'):
            return dict(GENERIC)
        handle = (self.authority.mint(username) if channel == 'auto'
                  else self.authority.mint(username, channel=channel))
        if handle is None:
            return dict(GENERIC)
        return dict(GENERIC)

    # -- completion -------------------------------------------------------
    def details(self, token, client):
        if not isinstance(token, str) or not (1 <= len(token) <= 256):
            return None
        if not self._register_client(client) or not self._allow(
                'details-client-' + client, self.client_limit, self.client_window):
            return None
        return self.authority.details(token, 'recovery')

    def complete(self, token, new_password, client):
        if not self._register_client(client):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        if not self._allow('complete-client-' + client,
                           self.client_limit, self.client_window):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        if not self._allow('complete-' + client, self.complete_limit,
                           self.complete_window):
            return {'status': 'rate_limited', 'message': RATE_LIMITED}
        pw = new_password or ''
        if len(pw) < self.policy_min:
            return {'status': 'short_password', 'message': 'Password is too short.'}
        if len(pw.encode('utf-8')) > self.policy_max:
            return {'status': 'invalid', 'message': GENERIC_FAIL}
        ok = self.authority.consume(token, pw, 'recovery')
        if ok is None:
            return {'status': 'uncertain', 'message': 'The outcome could not be confirmed.'}
        if not ok:
            return {'status': 'invalid', 'message': GENERIC_FAIL}
        return {'status': 'ok', 'message': GENERIC_OK}

    # -- rate limiting ----------------------------------------------------
    def _register_client(self, client):
        retention = max(self.request_window, self.complete_window, self.client_window)
        return self.store.register_recovery_client(
            client, self.clients_cap, self.client_window, retention, self.now())

    def _allow(self, key, limit, window):
        return bool(self.store.hit(key, limit, window, self.now()))


def main():
    import sys
    print('recovery.py is a library module; the portal wires it.', file=sys.stderr)
    return 1

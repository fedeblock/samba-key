"""Privileged reset authority for forgotten-password recovery.

The authority owns a *single-use ledger* (an external store it alone can
write) and enforces, per request:

* **peer-credential gating by operation** -- the web portal connects as the
  *portal* principal and may only ``MINT``/``VALIDATE``/``ISSUE``/``CONSUME``.
  The *admin* principal (a disjoint group, reached over a *separate* socket the
  portal container does not mount) is the only one that may ``APPROVE``/
  ``DENY``/``LIST``.  A compromised portal therefore cannot move a request to
  ``approved`` and cannot cause a reset.
* **an explicit allowlist** of eligible Samba accounts (never ``root``);
* **a fixed protocol** with no arbitrary command or argument passing -- the
  privileged password reset is a hardcoded invocation; only the allowlisted
  account and a validated new password are inputs;
* **single-use, kind-checked, time-bounded** consumption; the user-facing token
  is released exactly once (``ISSUE``) and only after an independent approval.

What a compromised portal *can* do (create fake requests; read a token *after*
an approval has been granted by an independent admin) and what a compromised
authority *can* do (reset any allowlisted account) are the residual risks
documented in ``RECOVERY-DESIGN.md`` and ``OPERATIONS.md``.
"""
import enum
import os
import re
import socket
import struct

from .store import Store

USERNAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$')


def mask_destination(kind, value):
    """Mask a channel destination for admin display: enough to recognise where a
    link will go, without disclosing the full address/chat id in listings or
    logs. E-mail keeps the domain and one trailing local char; Telegram keeps
    the last four digits."""
    if kind == 'email':
        if '@' not in value:
            return '***'
        local, _, domain = value.partition('@')
        tail = local[-1:] if local else ''
        masked = '***' if len(local) <= 1 else local[0] + '*' * 3 + tail
        return masked + '@' + domain
    # Telegram (and any numeric id): keep only the last four digits.
    digits = ''.join(ch for ch in str(value) if ch.isdigit())
    if len(digits) <= 4:
        return '****'
    return '***' + digits[-4:]

_PORTAL_OPS = frozenset({'MINT', 'VALIDATE', 'CONSUME'})
_ADMIN_OPS = frozenset({'APPROVE', 'DENY', 'LIST',
                       'CHANNEL_ADD', 'CHANNEL_VERIFY', 'CHANNEL_REMOVE',
                       'CHANNEL_LIST'})
_ALLOWED_KEYS = {
    'MINT': frozenset({'account', 'kind', 'channel'}),
    'VALIDATE': frozenset({'token', 'kind'}),
    'CONSUME': frozenset({'token', 'new_password', 'kind'}),
    'APPROVE': frozenset({'handle'}),
    'DENY': frozenset({'handle'}),
    'LIST': frozenset(),
    'CHANNEL_ADD': frozenset({'account', 'kind', 'value'}),
    'CHANNEL_VERIFY': frozenset({'account', 'kind', 'value', 'code'}),
    'CHANNEL_REMOVE': frozenset({'account', 'kind'}),
    'CHANNEL_LIST': frozenset({'account'}),
}

# ISSUE and REVOKE are deliberately NOT portal ops: the portal must never receive
# a token (delivery is authority-side) and must never revoke (it could suppress
# its own approved requests). Only the authority-side delivery worker issues and
# revokes, in-process, and the admin socket approves/denies.


class Role(enum.Enum):
    PORTAL = 'portal'
    ADMIN = 'admin'
    NONE = 'none'


class ResetAuthority:
    def __init__(self, store, eligible_accounts, reset_fn, principals,
                 peer_credential=None, pending_ttl=86400, link_ttl=900,
                 min_length=12, max_length=1024):
        self.store = store
        self.eligible = frozenset(eligible_accounts)
        self.reset_fn = reset_fn
        self.principals = principals
        self.peer_credential = peer_credential or get_peer_cred
        self.pending_ttl = pending_ttl
        self.link_ttl = link_ttl
        self.min_length = min_length
        self.max_length = max_length

    # -- pure dispatch, fully unit-testable without a socket ---------------
    def dispatch(self, role, opcode, payload):
        if not isinstance(payload, dict) or not isinstance(opcode, str):
            return {'ok': False}
        if opcode in _PORTAL_OPS and role != Role.PORTAL:
            return {'ok': False}
        if opcode in _ADMIN_OPS and role != Role.ADMIN:
            return {'ok': False}
        if opcode not in _ALLOWED_KEYS:
            return {'ok': False}
        if not set(payload) <= _ALLOWED_KEYS[opcode]:
            return {'ok': False}
        handler = getattr(self, '_op_' + opcode.lower(), None)
        if handler is None:
            return {'ok': False}
        try:
            return handler(payload)
        except Exception:
            return {'ok': False}

    def _eligible(self, account):
        return (isinstance(account, str) and USERNAME.fullmatch(account)
                and account.lower() != 'root' and account in self.eligible)

    def _password_ok(self, new):
        return (isinstance(new, str) and 0 < len(new) < 1024
                and not any(c in new for c in '\r\n\0')
                and len(new) >= self.min_length
                and len(new.encode('utf-8')) <= self.max_length)

    def _op_mint(self, payload):
        account = payload.get('account')
        kind = payload.get('kind', 'recovery')
        channel = payload.get('channel', 'auto')
        if kind != 'recovery' or channel not in ('auto', 'email', 'telegram'):
            return {'ok': False}
        if not self._eligible(account):
            return {'ok': False}
        # The caller chooses a channel type, never a destination. The authority
        # resolves the destination from its own bindings at delivery.
        handle = self.store.create_request(account, self.pending_ttl, kind, channel)
        if handle is None:
            return {'ok': False}
        return {'ok': True, 'handle': handle}

    def _op_validate(self, payload):
        raw = payload.get('token')
        kind = payload.get('kind', 'recovery')
        if not isinstance(raw, str) or kind != 'recovery':
            return {'usable': False}
        details = self.store.recovery_details(raw, kind)
        if details is None or not self._eligible(details[0].account):
            return {'usable': False}
        request, binding, email = details
        result = {'usable': True, 'account': request.account, 'channel': binding.kind,
                  'destination': mask_destination(binding.kind, binding.value)}
        if binding.kind != 'email' and email is not None:
            result['associated_email'] = mask_destination('email', email.value)
        return result

    def _op_issue(self, payload):
        handle = payload.get('handle')
        if not isinstance(handle, str):
            return {'ok': False}
        token = self.store.issue(handle, self.link_ttl)
        if token is None:
            return {'ok': False}
        return {'ok': True, 'token': token}

    def _op_consume(self, payload):
        raw = payload.get('token')
        kind = payload.get('kind', 'recovery')
        new = payload.get('new_password')
        if kind != 'recovery' or not isinstance(raw, str) or not self._password_ok(new):
            return {'ok': False}
        request = self.store.consume_token(raw, kind)
        if request is None or not self._eligible(request.account):
            return {'ok': False}
        try:
            ok = bool(self.reset_fn(request.account, new))
        except Exception:
            ok = False
        # The request is consumed regardless of reset_fn outcome: no blind
        # retry. A failed reset must be requested anew.
        return {'ok': ok}

    def _op_approve(self, payload):
        handle = payload.get('handle')
        return {'ok': bool(handle) and self.store.approve(handle)}

    def _op_deny(self, payload):
        handle = payload.get('handle')
        return {'ok': bool(handle) and self.store.deny(handle)}

    def _op_list(self, payload):
        """Admin view of outstanding requests. The destination is shown masked
        (enough for the admin to know where the link will go, not a full
        disclosure of the binding), so the admin can approve with the recipient
        in view rather than blind."""
        requests = self.store.pending_requests()
        out = []
        for r in requests:
            binding = self.store.resolve_binding(r.account, r.channel)
            out.append({
                'handle': r.handle, 'account': r.account, 'kind': r.kind,
                'channel': r.channel,
                'expires_at': r.expires_at,
                'destination': (mask_destination(binding.kind, binding.value)
                                if binding is not None else None)})
        return {'requests': out}

    # -- channel enrollment (admin only) ----------------------------------
    # A portal process cannot reach these ops, so it cannot inject or alter a
    # destination. The code is a one-time challenge; only its digest is stored.
    def _op_channel_add(self, payload):
        account = payload.get('account')
        kind = payload.get('kind')
        value = payload.get('value')
        if not self._eligible(account) or kind not in ('email', 'telegram'):
            return {'ok': False}
        # E-mail needs an address; Telegram's chat id is learned on /start, so
        # its value may be empty at enrollment.
        if not isinstance(value, str):
            return {'ok': False}
        if kind == 'email' and not value:
            return {'ok': False}
        code = self.store.create_channel_challenge(account, kind, value,
                                                   self.link_ttl)
        if code is None:
            return {'ok': False}
        # The raw code is returned so the admin can relay it (Telegram) or so
        # the authority can send it (e-mail); it is not persisted in the clear.
        return {'ok': True, 'code': code}

    def _op_channel_verify(self, payload):
        account = payload.get('account')
        kind = payload.get('kind')
        value = payload.get('value')
        code = payload.get('code')
        if not self._eligible(account) or kind not in ('email', 'telegram'):
            return {'ok': False}
        if not isinstance(value, str) or not isinstance(code, str):
            return {'ok': False}
        return {'ok': self.store.verify_channel_challenge(
            account, kind, value, code)}

    def _op_channel_remove(self, payload):
        account = payload.get('account')
        kind = payload.get('kind')
        if not self._eligible(account) or kind not in ('email', 'telegram'):
            return {'ok': False}
        self.store.revoke_channel(account, kind)
        return {'ok': True}

    def _op_channel_list(self, payload):
        account = payload.get('account')
        if account is not None and not self._eligible(account):
            return {'ok': False}
        bindings = []
        if account is not None:
            for c in self.store.channel_rows(account):
                bindings.append({'account': account, 'kind': c['kind'],
                                 'value': mask_destination(c['kind'], c['value'])})
        return {'ok': True, 'channels': bindings}

    # -- socket transport (privileged helper daemon) ----------------------
    def serve(self, socket_path, listen_backlog=16, recv_timeout=10,
              forced_role=None, stop_event=None, accept_timeout=0.5,
              owner_uid=None, owner_gid=None, mode=0o600):
        """Accept connections on a Unix socket, resolving each peer to a Role.

        The socket's *role* is fixed by ``forced_role`` (which socket you used)
        and ``SO_PEERCRED`` is a second check.  After bind and before listen the
        socket is ``chown``-ed to ``(owner_uid, owner_gid)`` and ``chmod``-ed to
        ``mode`` so, e.g., the admin socket is ``root:admin_group 0660`` and the
        portal process (a different group) cannot connect to it at all.
        """
        import threading
        if getattr(socket, 'AF_UNIX', None) is None:
            raise OSError('AF_UNIX unavailable on this platform')
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        old_umask = os.umask(0o077)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(socket_path)
            if owner_uid is not None or owner_gid is not None:
                try:
                    os.chown(socket_path, owner_uid, owner_gid)
                except PermissionError:
                    pass  # non-root cannot chown; mode is still applied
                os.chmod(socket_path, mode)
            else:
                os.chmod(socket_path, 0o600)
            sock.listen(listen_backlog)
        finally:
            os.umask(old_umask)
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                try:
                    sock.settimeout(accept_timeout)
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                try:
                    conn.settimeout(recv_timeout)
                    # The socket's role is fixed (forced_role), but the peer must
                    # actually be authorized for it: resolve the peer and require
                    # it to match. This is the real SO_PEERCRED / supplementary-
                    # group check, not a bypass.
                    if forced_role is not None:
                        if self._resolve_role(conn) != forced_role:
                            continue  # peer not authorized for this socket
                        role = forced_role
                    else:
                        role = self._resolve_role(conn)
                    _serve_one(conn, role, self, recv_timeout)
                except OSError:
                    # A client may disconnect while its response is written.
                    # That must not terminate the authority's listening socket.
                    pass
                finally:
                    conn.close()
        finally:
            sock.close()
            try:
                os.unlink(socket_path)
            except OSError:
                pass

    def _resolve_role(self, conn):
        try:
            peer = self.peer_credential(conn)
        except OSError:
            return Role.NONE
        try:
            return self.principals(peer)
        except Exception:
            return Role.NONE


def _serve_one(conn, role, authority, recv_timeout):
    import json
    header = _recv_all(conn, 4, recv_timeout)
    if header is None or len(header) != 4:
        return
    (length,) = struct.unpack('>I', header)
    body = _recv_all(conn, length, recv_timeout) if length < (1 << 20) else None
    if body is None:
        return
    try:
        request = json.loads(body.decode('utf-8'))
        if not isinstance(request, dict):
            return
        opcode = request.get('op')
        response = authority.dispatch(role, opcode, request.get('payload', {}))
    except (ValueError, UnicodeError):
        return
    out = {k: v for k, v in response.items() if k != 'ok'}
    out['ok'] = bool(response.get('ok', False))
    _write_frame(conn, json.dumps(out).encode('utf-8'))


def get_peer_cred(conn):
    """Return (uid, gid) of the peer for a connected Unix socket (Linux)."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    pid, uid, gid = struct.unpack('iii', raw)
    return (uid, gid)


def peer_groups(uid, gid):
    """Return the peer's *full* group set. SO_PEERCRED gives only the primary
    gid; supplementary groups are resolved from the user database (the peers run
    on the same host as the authority, so their uid is a real local uid).

    Python 3.13+ requires ``getgrouplist``'s first argument to be a username
    string, so resolve the uid to a name first."""
    try:
        import pwd
        import os as _os
        name = pwd.getpwuid(uid).pw_name
        return set(_os.getgrouplist(name, gid))
    except (OSError, KeyError, AttributeError, ImportError):
        return {gid}


def principal_from_peer(peer, portal_uid, admin_gids):
    """Map a peer credential to a Role, checking *supplementary* groups.

    A peer in any admin group is ADMIN; the portal user (not in an admin group)
    is PORTAL; anyone else is NONE.  The two roles are disjoint by
    construction (``validate_separation`` refuses to start otherwise), so a
    requester can never approve itself.
    """
    admin_gids = set(admin_gids)
    uid, gid = peer
    if peer_groups(uid, gid) & admin_gids:
        return Role.ADMIN
    if uid == portal_uid and not (peer_groups(uid, gid) & admin_gids):
        return Role.PORTAL
    return Role.NONE


def validate_separation(portal_uid, portal_groups, admin_gids):
    """Refuse to start if the portal identity could be an admin.

    Returns a list of problems; an empty list means the separation holds.
    """
    problems = []
    admin_gids = set(admin_gids)
    portal_groups = set(portal_groups)
    if portal_uid == 0:
        problems.append('portal uid is root (0)')
    if portal_groups & admin_gids:
        problems.append('portal groups intersect admin groups')
    return problems


# -- minimal length-prefixed JSON framing --------------------------------
def _recv_all(conn, n, timeout):
    conn.settimeout(timeout)
    chunks = []
    while n > 0:
        try:
            chunk = conn.recv(n)
        except socket.timeout:
            return None
        if not chunk:
            return None if not chunks else b''.join(chunks)
        chunks.append(chunk)
        n -= len(chunk)
    return b''.join(chunks)


def _write_frame(conn, data):
    conn.sendall(struct.pack('>I', len(data)) + data)


class _Client:
    def __init__(self, socket_path, recv_timeout=3, consume_timeout=25):
        self.socket_path = socket_path
        # A short receive timeout bounds a call so a hung or silent authority
        # cannot block the portal or amplify a denial of service; the call then
        # fails closed to {'ok': False}. Lower it further behind a proxy.
        self.recv_timeout = recv_timeout
        self.consume_timeout = consume_timeout

    def _call(self, opcode, payload):
        import json
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        timeout = self.consume_timeout if opcode == 'CONSUME' else self.recv_timeout
        try:
            sock.settimeout(timeout)
            sock.connect(self.socket_path)
            _write_frame(sock, json.dumps({'op': opcode, 'payload': payload}).encode('utf-8'))
            header = _recv_all(sock, 4, timeout)
            if header is None:
                return {'ok': False, 'transport_error': True}
            (length,) = struct.unpack('>I', header)
            body = _recv_all(sock, length, timeout) if length < (1 << 20) else None
            if body is None:
                return {'ok': False, 'transport_error': True}
            return json.loads(body.decode('utf-8'))
        except (OSError, ValueError, struct.error):
            return {'ok': False, 'transport_error': True}
        finally:
            sock.close()


class ResetClient(_Client):
    """Portal-side client for MINT/VALIDATE/CONSUME only. The portal must
    NEVER issue or revoke a token: delivery is authority-side, so the portal
    never receives a token, and a portal that could revoke could suppress its
    own approved requests."""

    def mint(self, account, kind='recovery', channel='auto'):
        resp = self._call('MINT', {'account': account, 'kind': kind, 'channel': channel})
        return resp.get('handle') if resp.get('ok') else None

    def validate(self, token, kind='recovery'):
        return bool(self._call('VALIDATE', {'token': token, 'kind': kind}).get('usable'))

    def details(self, token, kind='recovery'):
        response = self._call('VALIDATE', {'token': token, 'kind': kind})
        return response if response.get('usable') else None

    def consume(self, token, new_password, kind='recovery'):
        response = self._call('CONSUME', {'token': token, 'new_password': new_password,
                                          'kind': kind})
        if response.get('transport_error'):
            return None
        return bool(response.get('ok'))


class AdminClient(_Client):
    """Administrative client (used by the out-of-band admin tool and the
    authority-side delivery/enrollment paths)."""

    def list_pending(self):
        return self._call('LIST', {}).get('requests', [])

    def approve(self, handle):
        return bool(self._call('APPROVE', {'handle': handle}).get('ok'))

    def deny(self, handle):
        return bool(self._call('DENY', {'handle': handle}).get('ok'))

    # Channel enrollment (admin only). The code returned by add() is relayed by
    # the admin (Telegram) or sent by the authority (e-mail).
    def channel_add(self, account, kind, value):
        resp = self._call('CHANNEL_ADD', {'account': account, 'kind': kind, 'value': value})
        return resp.get('code') if resp.get('ok') else None

    def channel_verify(self, account, kind, value, code):
        return bool(self._call('CHANNEL_VERIFY',
                               {'account': account, 'kind': kind,
                                'value': value, 'code': code}).get('ok'))

    def channel_remove(self, account, kind):
        return bool(self._call('CHANNEL_REMOVE',
                               {'account': account, 'kind': kind}).get('ok'))

    def channel_list(self, account=None):
        return self._call('CHANNEL_LIST', {'account': account}).get('channels', [])

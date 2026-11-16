"""Privileged reset-authority daemon (entrypoint).

Opens the authority's own store, validates that the portal identity is disjoint
from the admin group (refusing to start otherwise), and serves two sockets with
effective ownership and permissions:

    <authority_dir>/portal.sock  root:portal_group 0660  (role PORTAL)
    <authority_dir>/admin.sock   root:admin_group 0660   (role ADMIN)
    <recovery_data_dir>/authority.db  root:root       0600    (the ledger)

The runtime dir (sockets) and the persistent data dir (ledger) are separate: the
runtime dir may be volatile (/run), but the ledger must survive a reboot,
so prepare_storage creates the data dir with 0700 and refuses the volatile
locations (/run, /var/run, /tmp).

It is the only process that can move a request to ``approved``. The web portal
talks to ``portal.sock``; the out-of-band admin tool talks to ``admin.sock``.
The web wiring is not connected in this build, so this daemon is provided and
unit-tested but not wired into a live recovery flow yet.
"""
import os
import signal
import threading
import logging

from .reset_auth import (ResetAuthority, Role, validate_separation,
                         get_peer_cred, principal_from_peer)
from .store import Store

LOG = logging.getLogger(__name__)


def load_eligible(path):
    """Read the allowlist of Samba accounts the authority may reset, one per
    line, from a root-owned file. An unreadable or absent file yields an empty
    allowlist (the authority then serves but resets nothing -- fail closed).
    Names are validated so a stray line cannot inject an invalid account."""
    import re
    name = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$')
    out = set()
    try:
        with open(path, 'r') as fh:
            for line in fh:
                token = line.strip()
                if token and not token.startswith('#') \
                        and token.lower() != 'root' and name.match(token):
                    out.add(token)
    except OSError:
        return set()
    return out


def group_gids(name):
    """Resolve a group name to its gid set (empty if it does not exist)."""
    try:
        import grp
        return {g.gr_gid for g in grp.getgrall() if g.gr_name == name}
    except (OSError, KeyError):
        return set()


def _portal_groups(portal_uid, portal_group):
    """The portal user's real group set: its primary group plus the
    supplementary groups resolved from the user database. Defends on hosts
    without getgrouplist (e.g. macOS) by falling back to the named group."""
    groups = set()
    try:
        import pwd
        import os as _os
        pw = pwd.getpwuid(portal_uid)
        groups = set(_os.getgrouplist(pw.pw_name, pw.pw_gid))
    except (OSError, KeyError, AttributeError, ImportError):
        pass
    groups |= group_gids(portal_group)
    return groups


def _admin_groups(admin_group):
    """The admin group's gid and the gids of its members."""
    out = group_gids(admin_group)
    try:
        import grp
        g = grp.getgrnam(admin_group)
        out.add(g.gr_gid)
    except (KeyError, OSError):
        pass
    return out


def check_separation(portal_uid, portal_group, admin_group):
    """Refuse to start if the portal identity could be an admin. Returns a list
    of problems; empty means the separation holds.

    Fails closed: if either side's groups cannot be resolved on this host, the
    separation cannot be verified, so startup is refused -- the only exception is
    when neither side resolves, where a conservative name comparison is used
    (this is the offline unit-test path, never a production host where the real
    groups exist)."""
    problems = []
    if portal_uid == 0:
        problems.append('portal uid is root (0)')

    import pwd
    portal_resolved = False
    try:
        pwd.getpwuid(portal_uid)
        portal_resolved = True
    except (OSError, KeyError):
        pass
    admin_gids = _admin_groups(admin_group)
    admin_resolved = bool(admin_gids)

    # If either side resolved and the other did not, we cannot verify the
    # separation -- refuse rather than fail open.
    if portal_resolved != admin_resolved:
        if not admin_resolved:
            problems.append('admin group cannot be resolved; cannot verify '
                            'separation')
        if not portal_resolved:
            problems.append('portal uid cannot be resolved; cannot verify '
                            'separation')
        return problems

    if not admin_resolved and not portal_resolved:
        # Neither side resolves on this host (offline test): compare names.
        if portal_group == admin_group:
            problems.append('portal and admin group names are identical')
        return problems

    portal = _portal_groups(portal_uid, portal_group)
    if portal & admin_gids:
        problems.append('portal groups intersect the admin group')
    return problems


def serve_sockets(store, eligible, reset_fn, authority_dir, portal_uid,
                  portal_gid, admin_gids, stop_event,
                  peer_credential=get_peer_cred, mode=0o660,
                  auth_kwargs=None, split_sockets=False):
    """Create the private directory and serve the two sockets with effective
    ownership and permissions. The role of a connection is resolved from the
    peer's credentials (supplementary groups) and must match the socket's role,
    so the admin socket accepts only admin-group peers and the portal socket
    only the portal uid. Returns (portal_sock, admin_sock, threads).

    ``auth_kwargs`` carries the configured TTLs/lengths (pending_ttl, link_ttl,
    min_length, max_length) so the two authorities honour the same policy the
    portal enforces, rather than the module defaults."""
    from functools import partial
    auth_kwargs = auth_kwargs or {}
    # The runtime dir holds only the sockets (created fresh each start). The
    # ledger lives under the persistent recovery_data_dir, prepared separately by
    # prepare_storage, so a reboot of the volatile runtime dir cannot lose the
    # channel bindings.
    os.makedirs(authority_dir, exist_ok=True)
    os.chmod(authority_dir, 0o755)

    portal_dir = os.path.join(authority_dir, 'portal') if split_sockets else authority_dir
    if split_sockets:
        os.makedirs(portal_dir, mode=0o755, exist_ok=True)
        os.chmod(portal_dir, 0o755)
    portal_sock = os.path.join(portal_dir, 'portal.sock')
    admin_sock = os.path.join(authority_dir, 'admin.sock')
    # principals resolves a peer's real groups to a Role; the authority also
    # requires it to match the socket's fixed role.
    principals = partial(principal_from_peer, portal_uid=portal_uid,
                         admin_gids=set(admin_gids))
    portal_auth = ResetAuthority(store, eligible, reset_fn,
                                 principals=principals,
                                 peer_credential=peer_credential,
                                 **auth_kwargs)
    admin_auth = ResetAuthority(store, eligible, reset_fn,
                                principals=principals,
                                peer_credential=peer_credential,
                                **auth_kwargs)
    threads = [
        threading.Thread(
            target=portal_auth.serve, args=(portal_sock,),
            kwargs={'forced_role': Role.PORTAL, 'stop_event': stop_event,
                    'owner_uid': 0, 'owner_gid': portal_gid, 'mode': mode},
            daemon=True),
        threading.Thread(
            target=admin_auth.serve, args=(admin_sock,),
            kwargs={'forced_role': Role.ADMIN, 'stop_event': stop_event,
                    'owner_uid': 0, 'owner_gid': next(iter(admin_gids)),
                    'mode': mode},
            daemon=True),
    ]
    for t in threads:
        t.start()
    return portal_sock, admin_sock, threads


def run(cfg, store, eligible, delivery, stop_event,
        peer_credential=get_peer_cred, deliver_interval=None,
        reset_transport=None, get_updates=None):
    """Wire and block: serve the two sockets, run the delivery worker, and block
    until ``stop_event`` is set (by a signal handler). Kept separate from
    ``main()`` so it can be driven by a test with a fake stop event."""
    from .delivery import RecoveryDelivery
    from .delivery_worker import DeliveryWorker
    from .reset import make_reset_fn

    reset_fn = make_reset_fn(
        eligible, min_length=cfg.reset_min_length,
        max_length=cfg.reset_max_length,
        executable=cfg.reset_executable, transport=reset_transport)
    delivery = delivery or RecoveryDelivery.from_config(cfg)
    worker = DeliveryWorker(store, delivery, cfg.base_url,
                            link_ttl=cfg.link_ttl)
    interval = deliver_interval or cfg.deliver_interval

    def _delivery_loop():
        while not stop_event.is_set():
            try:
                worker.deliver_pending()
            except Exception:
                LOG.warning('delivery cycle failed', exc_info=True)
            stop_event.wait(timeout=interval)

    _portal_sock, _admin_sock, threads = serve_sockets(store, eligible, reset_fn,
                            cfg.authority_dir, cfg.portal_uid,
                            _portal_gid(cfg.portal_group),
                            _admin_gids(cfg.admin_group), stop_event,
                            peer_credential=peer_credential,
                            split_sockets=cfg.authority_split_sockets,
                            auth_kwargs={
                                'pending_ttl': cfg.request_ttl,
                                'link_ttl': cfg.link_ttl,
                                'min_length': cfg.reset_min_length,
                                'max_length': cfg.reset_max_length})
    worker_thread = threading.Thread(target=_delivery_loop, daemon=True)
    worker_thread.start()

    # Start the Telegram poller if a bot token is configured. The token stays in
    # the authority process (never the portal, never logged); the getUpdates call
    # is injectable so tests need no network. A chat id is learned only from a
    # verified private conversation (see telegram.py). The poller pauses for
    # cfg.telegram_poll_interval and backs off on failures.
    telegram_thread = None
    if getattr(cfg, 'telegram_bot_token', ''):
        from .telegram import (TelegramBinder, TelegramPoller,
                              make_polling_get_updates)
        binder = TelegramBinder(store, cfg.telegram_bot_token)
        if get_updates is None:
            get_updates = make_polling_get_updates(
                cfg.telegram_bot_token, cfg.telegram_api_base)
        def _confirm_telegram_binding(chat_id):
            delivery.send('telegram', str(chat_id), 'Samba Key',
                          'Listo, tu cuenta de Telegram quedó vinculada para la recuperación.')
        poller = TelegramPoller(binder, get_updates, stop_event,
                                poll_interval=cfg.telegram_poll_interval,
                                on_bound=_confirm_telegram_binding)
        telegram_thread = threading.Thread(target=poller.run, daemon=True)
        telegram_thread.start()

    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    finally:
        stop_event.set()
        worker_thread.join(timeout=3)
        if telegram_thread is not None:
            telegram_thread.join(timeout=3)
        for t in threads:
            t.join(timeout=3)


def _portal_gid(name):
    import grp
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return 0


def _admin_gids(name):
    gids = group_gids(name)
    return gids or {0}


def _assert_not_volatile(data_dir):
    """Refuse a data dir on a volatile filesystem. /run and /var/run are tmpfs
    (cleared on reboot); /tmp is world-writable. The ledger and channel bindings
    must survive a restart, so a volatile location is refused."""
    from .config import ConfigError
    real = os.path.realpath(data_dir)
    for volatile in ('/run', '/var/run', '/tmp', '/private/tmp'):
        root = os.path.realpath(volatile)
        if not root or root == '/':
            continue
        if real == root or real.startswith(root + os.sep):
            raise ConfigError(
                'RECOVERY_DATA_DIR must be on a persistent filesystem; it must '
                'not be under %s (volatile). Use e.g. /var/lib/samba-key.'
                % volatile)


def prepare_storage(cfg, store_class=None):
    """Create the persistent data dir (0700, owned by the running uid) and open
    the authority store there. Refuses a volatile data dir. Returns the open
    store. Kept separate from main() so it can be unit-tested on a clean dir and
    a restart."""
    from .config import ConfigError
    store_class = store_class or Store
    _assert_not_volatile(cfg.recovery_data_dir)
    os.makedirs(cfg.recovery_data_dir, mode=0o700, exist_ok=True)
    os.chmod(cfg.recovery_data_dir, 0o700)
    try:
        os.chown(cfg.recovery_data_dir, os.geteuid(), 0)
    except (AttributeError, OSError, PermissionError):
        pass
    path = os.path.join(cfg.recovery_data_dir, 'authority.db')
    return store_class(path,
                      max_pending_per_account=cfg.max_pending_per_account,
                      max_pending_global=cfg.max_pending_global)


def main(environ=None, stop_event=None):
    """Daemon entrypoint. Validates separation, prepares the persistent store,
    serves the two sockets, and runs the delivery worker (and the Telegram
    poller, if a bot token is set) until SIGTERM/SIGINT. The privileged reset is
    ``smbpasswd -s`` as root (``reset.make_reset_fn``), the new password on a
    stdin pipe (never argv or the environment).

    Accepts an optional ``environ`` and ``stop_event`` so it can be driven by a
    test without a real signal or the process environment."""
    import sys
    from .config import Config
    cfg = Config(environ)
    if cfg.recovery_mode == 'disabled':
        print('recovery is disabled; nothing to serve', file=sys.stderr)
        return 0
    problems = check_separation(cfg.portal_uid, cfg.portal_group, cfg.admin_group)
    if problems:
        print('refusing to start: ' + '; '.join(problems), file=sys.stderr)
        return 2
    eligible = load_eligible(cfg.recovery_eligible_file)
    store = prepare_storage(cfg)
    stop_event = stop_event or threading.Event()

    def _stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        run(cfg, store, eligible, None, stop_event)
    finally:
        store.close()
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())

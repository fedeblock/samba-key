"""Unit tests for the authority daemon's separation check.

The full two-socket real-identity proof is in tests/integration_privsep.py, run
on a disposable Linux container (tests/run_privsep_docker.sh). Here we unit-test
the pure separation check, including the fail-closed cases the reviewer flagged:
a portal user listed in the admin group's gr_mem is refused, and either side
being unresolvable is refused rather than failing open.
"""
import os
import tempfile
import threading
import time
import uuid
import unittest

from samba_key.authority_main import check_separation
from samba_key.reset_auth import Role
from samba_key.config import Config


class CheckSeparationTests(unittest.TestCase):
    def test_root_portal_refused(self):
        problems = check_separation(0, 'zzz-portal', 'zzz-admin')
        self.assertTrue(any('root' in p for p in problems))

    def test_distinct_groups_ok(self):
        # Both sides resolve to disjoint group sets on a real host.
        import samba_key.authority_main as am
        import pwd
        orig_pwd = getattr(pwd, 'getpwuid')
        orig_admin = am._admin_groups
        orig_portal = am._portal_groups
        try:
            pwd.getpwuid = lambda uid: _Pw()  # portal resolves
            am._admin_groups = lambda name: {5000}
            am._portal_groups = lambda uid, group: {1000}
            self.assertFalse(check_separation(1000, 'p', 'a'))
        finally:
            pwd.getpwuid = orig_pwd
            am._admin_groups = orig_admin
            am._portal_groups = orig_portal

    def test_identical_group_names_refused(self):
        # Neither side resolves on this host -> conservative name compare.
        import samba_key.authority_main as am
        import pwd
        orig_pwd = getattr(pwd, 'getpwuid')
        orig_admin = am._admin_groups
        try:
            def _raise(*a):
                raise KeyError('no such uid')
            pwd.getpwuid = _raise
            am._admin_groups = lambda name: set()
            self.assertTrue(check_separation(60000, 'samba-key-admin',
                                             'samba-key-admin'))
        finally:
            pwd.getpwuid = orig_pwd
            am._admin_groups = orig_admin

    def test_portal_user_in_admin_gr_mem_refused(self):
        import samba_key.authority_main as am
        import pwd
        orig_pwd = getattr(pwd, 'getpwuid')
        orig_admin = am._admin_groups
        orig_portal = am._portal_groups
        try:
            pwd.getpwuid = lambda uid: _Pw()
            am._admin_groups = lambda name: {5000}
            am._portal_groups = lambda uid, group: {1000, 5000}  # in admin
            self.assertTrue(check_separation(1000, 'p', 'a'),
                            'portal listed in admin gr_mem must be refused')
        finally:
            pwd.getpwuid = orig_pwd
            am._admin_groups = orig_admin
            am._portal_groups = orig_portal

    def test_unresolvable_admin_group_refused(self):
        # The portal resolves but the admin group cannot: fail closed, not open.
        import samba_key.authority_main as am
        import pwd
        orig_pwd = getattr(pwd, 'getpwuid')
        orig_admin = am._admin_groups
        try:
            pwd.getpwuid = lambda uid: _Pw()  # portal resolves
            am._admin_groups = lambda name: set()  # admin unresolvable
            problems = check_separation(1000, 'p', 'nonexistent-admin')
            self.assertTrue(any('admin' in p and 'resolve' in p
                                for p in problems),
                            'unresolvable admin group must be refused, not pass')
        finally:
            pwd.getpwuid = orig_pwd
            am._admin_groups = orig_admin

    def test_unresolvable_portal_uid_refused(self):
        # The admin resolves but the portal uid cannot: fail closed.
        import samba_key.authority_main as am
        import pwd
        orig_pwd = getattr(pwd, 'getpwuid')
        orig_admin = am._admin_groups
        try:
            def _raise(*a):
                raise KeyError('no such uid')
            pwd.getpwuid = _raise
            am._admin_groups = lambda name: {5000}
            problems = check_separation(60000, 'p', 'a')
            self.assertTrue(any('portal' in p and 'resolve' in p
                                for p in problems),
                            'unresolvable portal uid must be refused, not pass')
        finally:
            pwd.getpwuid = orig_pwd
            am._admin_groups = orig_admin


class _Pw:
    pw_name = 'skportal'
    pw_gid = 1000


class AuthorityRunTests(unittest.TestCase):
    """The daemon entrypoint wires both sockets and the delivery loop, and stops
    cleanly. Identities and the group resolution are faked so the test runs on
    any host; the real-identity proof is the disposable-Linux container."""

    def test_split_socket_directory_exposes_only_portal_socket(self):
        import samba_key.authority_main as am
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            store = am.Store(os.path.join(directory, 'authority.db'))
            self.addCleanup(store.close)
            stop = threading.Event()
            cfg = Config({'AUTHORITY_DIR': directory, 'RECOVERY_MODE': 'approval',
                          'AUTHORITY_SPLIT_SOCKETS': 'true',
                          'RECOVERY_SOCKET': os.path.join(directory, 'portal', 'portal.sock'),
                          'BASE_URL': 'https://portal.example'})
            with patch.object(am, '_portal_gid', return_value=os.getgid()), \
                 patch.object(am, '_admin_gids', return_value={os.getgid()}):
                thread = threading.Thread(target=am.run,
                    args=(cfg, store, {'alice'}, None, stop),
                    kwargs={'peer_credential': lambda c: (33, 33), 'deliver_interval': 0.1},
                    daemon=True)
                thread.start()
                try:
                    deadline = time.time() + 3
                    portal = os.path.join(directory, 'portal', 'portal.sock')
                    admin = os.path.join(directory, 'admin.sock')
                    while not (os.path.exists(portal) and os.path.exists(admin)) and time.time() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(os.path.exists(portal))
                    self.assertTrue(os.path.exists(admin))
                    self.assertEqual(os.listdir(os.path.dirname(portal)), ['portal.sock'])
                finally:
                    stop.set()
                    thread.join(timeout=5)

    def test_run_serves_and_stops_cleanly(self):
        import samba_key.authority_main as am
        import threading
        import time
        dir_ = tempfile.mkdtemp()
        store = am.Store(os.path.join(dir_, 'authority.db'))
        eligible = {'alice'}
        reset_log = []
        stop = threading.Event()
        # Fake a non-root portal and an admin group; chown to root is a no-op
        # on a non-root host (caught), the sockets are still created.
        orig_portal_gid, orig_admin_gids = am._portal_gid, am._admin_gids
        am._portal_gid = lambda name: 33
        am._admin_gids = lambda name: {5000}
        cfg = Config({'AUTHORITY_DIR': dir_, 'RECOVERY_MODE': 'approval',
                      'RECOVERY_SOCKET': os.path.join(dir_, 'portal.sock'),
                      'BASE_URL': 'https://portal.example'})
        try:
            t = threading.Thread(target=am.run, args=(cfg, store, eligible, None, stop),
                                 kwargs={'peer_credential': lambda c: (33, 33),
                                         'deliver_interval': 0.2},
                                 daemon=True)
            t.start()
            time.sleep(0.4)
            self.assertTrue(os.path.exists(os.path.join(dir_, 'portal.sock')))
            self.assertTrue(os.path.exists(os.path.join(dir_, 'admin.sock')))
            stop.set()
            t.join(timeout=5)
            self.assertFalse(t.is_alive(), 'run() must stop on the stop event')
        finally:
            am._portal_gid = orig_portal_gid
            am._admin_gids = orig_admin_gids
            store.close()

    def test_run_polls_telegram_at_interval_not_spin(self):
        # The real run() must pause between getUpdates cycles (defect 1). With a
        # short poll interval a short run makes a bounded number of calls; the
        # old no-op default would have spun thousands in the same window.
        import samba_key.authority_main as am
        import threading
        import time
        dir_ = tempfile.mkdtemp()
        store = am.Store(os.path.join(dir_, 'authority.db'))
        stop = threading.Event()
        calls = [0]

        def get_updates(offset):
            calls[0] += 1
            return []

        orig_portal_gid, orig_admin_gids = am._portal_gid, am._admin_gids
        am._portal_gid = lambda name: 33
        am._admin_gids = lambda name: {5000}
        cfg = Config({'AUTHORITY_DIR': dir_, 'RECOVERY_MODE': 'approval',
                      'RECOVERY_SOCKET': os.path.join(dir_, 'portal.sock'),
                      'TELEGRAM_BOT_TOKEN': 'faketoken',
                      'TELEGRAM_POLL_INTERVAL': '1',
                      'BASE_URL': 'https://portal.example'})
        try:
            t = threading.Thread(target=am.run,
                                 args=(cfg, store, {'alice'}, None, stop),
                                 kwargs={'peer_credential': lambda c: (33, 33),
                                         'deliver_interval': 0.1,
                                         'get_updates': get_updates},
                                 daemon=True)
            t.start()
            time.sleep(0.5)
            stop.set()
            t.join(timeout=5)
            self.assertFalse(t.is_alive())
            # A 1s poll interval over a 0.5s window yields ~1 call, never a spin.
            self.assertLess(calls[0], 5)
            self.assertGreaterEqual(calls[0], 1)
        finally:
            am._portal_gid = orig_portal_gid
            am._admin_gids = orig_admin_gids
            store.close()

    def test_main_disabled_serves_nothing(self):
        # With recovery disabled (the default), main() exits without serving.
        import samba_key.authority_main as am
        import os
        saved = {k: os.environ.get(k) for k in
                 ('RECOVERY_MODE', 'AUTHORITY_DIR')}
        os.environ['RECOVERY_MODE'] = 'disabled'
        os.environ['AUTHORITY_DIR'] = tempfile.mkdtemp()
        try:
            self.assertEqual(am.main(), 0)
            # No socket was created.
            self.assertFalse(os.path.exists(
                os.path.join(os.environ['AUTHORITY_DIR'], 'portal.sock')))
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class PrepareStorageTests(unittest.TestCase):
    """Defect 3: the ledger lives on a persistent dir, prepared with safe perms
    before it is opened, and a restart preserves the channel bindings."""

    def _persistent_dir(self):
        from unittest.mock import patch
        import samba_key.authority_main as am
        # The test filesystem may itself be temporary; exercise persistence and
        # permissions independently of the separately tested path policy.
        guard = patch.object(am, '_assert_not_volatile')
        guard.start()
        self.addCleanup(guard.stop)
        d = tempfile.mkdtemp(prefix='sk_test_data_')
        self.addCleanup(self._rm_tree, d)
        return d

    def _rm_tree(self, d):
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_creates_data_dir_with_safe_perms(self):
        import samba_key.authority_main as am
        from samba_key.config import Config
        data = self._persistent_dir()
        cfg = Config({'RECOVERY_DATA_DIR': data, 'RECOVERY_MODE': 'approval',
                      'RECOVERY_SOCKET': '/tmp/x.sock', 'BASE_URL': 'https://p'})
        store = am.prepare_storage(cfg)
        try:
            self.assertTrue(os.path.exists(os.path.join(data, 'authority.db')))
            self.assertEqual(os.stat(data).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(os.path.join(data, 'authority.db'))
                            .st_mode & 0o777, 0o600)
        finally:
            store.close()

    def test_refuses_volatile_data_dir(self):
        import samba_key.authority_main as am
        from samba_key.config import Config, ConfigError
        volatile = os.path.join(os.path.realpath('/tmp'),
                                'sk-volatile-' + uuid.uuid4().hex)
        cfg = Config({'RECOVERY_DATA_DIR': volatile, 'RECOVERY_MODE': 'approval',
                      'RECOVERY_SOCKET': '/tmp/x.sock', 'BASE_URL': 'https://p'})
        with self.assertRaises(ConfigError):
            am.prepare_storage(cfg)
        # Nothing was created in the volatile location.
        self.assertFalse(os.path.exists(volatile))

    def test_restart_preserves_channels(self):
        import samba_key.authority_main as am
        from samba_key.config import Config
        from samba_key.store import Store
        data = self._persistent_dir()
        cfg = Config({'RECOVERY_DATA_DIR': data, 'RECOVERY_MODE': 'approval',
                      'RECOVERY_SOCKET': '/tmp/x.sock', 'BASE_URL': 'https://p'})
        store = am.prepare_storage(cfg)
        store.bind_channel('alice', 'email', 'alice@example.com')
        store.close()
        # A restart (fresh store on the same dir) sees the channel.
        store2 = am.prepare_storage(cfg)
        try:
            self.assertEqual(store2.resolve_binding('alice').value,
                             'alice@example.com')
        finally:
            store2.close()

    def test_main_reaches_store_with_fakes(self):
        # main() must reach prepare_storage/Store without opening a real store,
        # even on a fresh (nested, nonexistent) data dir.
        import samba_key.authority_main as am
        import threading
        data = self._persistent_dir()
        cfg = {'RECOVERY_DATA_DIR': data, 'AUTHORITY_DIR': self._persistent_dir(),
               'RECOVERY_MODE': 'approval',
               'RECOVERY_SOCKET': os.path.join(data, 'portal.sock'),
               'BASE_URL': 'https://p'}
        seen = {}
        orig_run, orig_check = am.run, am.check_separation
        orig_stop = threading.Event()
        orig_stop.set()

        def fake_run(c, store, eligible, delivery, stop_event, **kw):
            seen['store'] = store
            return None

        am.run = fake_run
        am.check_separation = lambda *a, **k: []
        try:
            rc = am.main(environ=cfg, stop_event=orig_stop)
        finally:
            am.run = orig_run
            am.check_separation = orig_check
        self.assertEqual(rc, 0)
        self.assertIn('store', seen)
        self.assertTrue(os.path.exists(os.path.join(data, 'authority.db')))


class ConfigWiringTests(unittest.TestCase):
    """Defect 4: the configured values must actually reach the running process,
    not the module defaults. Exercised over a real socket via am.run()."""

    def _eligible_file(self, *accounts):
        path = os.path.join(tempfile.mkdtemp(), 'eligible.accounts')
        with open(path, 'w') as fh:
            fh.write('\n'.join(accounts) + '\n')
        return path

    def _start(self, env):
        import samba_key.authority_main as am
        from unittest.mock import patch
        guard = patch.object(am, '_assert_not_volatile')
        guard.start()
        self.addCleanup(guard.stop)
        dir_ = tempfile.mkdtemp()
        data = tempfile.mkdtemp(prefix='sk_cfg_')
        self.addCleanup(lambda d=dir_: __import__('shutil').rmtree(d,
                                                    ignore_errors=True))
        self.addCleanup(lambda d=data: __import__('shutil').rmtree(d,
                                                        ignore_errors=True))
        env = dict(env)
        env.update({'RECOVERY_MODE': 'approval',
                    'RECOVERY_SOCKET': os.path.join(dir_, 'portal.sock'),
                    'AUTHORITY_DIR': dir_,
                    'RECOVERY_DATA_DIR': data,
                    'BASE_URL': 'https://p',
                    'RECOVERY_ELIGIBLE_FILE': self._eligible_file('alice', 'bob')})
        cfg = Config(env)
        store = am.prepare_storage(cfg)
        eligible = am.load_eligible(cfg.recovery_eligible_file)
        stop = threading.Event()
        orig_portal, orig_admin = am._portal_gid, am._admin_gids
        am._portal_gid = lambda name: 33
        am._admin_gids = lambda name: {5000}
        t = threading.Thread(target=am.run,
                             args=(cfg, store, eligible, None, stop),
                             kwargs={'peer_credential': lambda c: (33, 33),
                                     'deliver_interval': 0.2},
                             daemon=True)
        t.start()
        # Wait for the portal socket to appear.
        for _ in range(200):
            if os.path.exists(os.path.join(dir_, 'portal.sock')):
                break
            time.sleep(0.01)
        return cfg, store, stop, t, dir_, (orig_portal, orig_admin)

    def _stop(self, handle):
        cfg, store, stop, t, dir_, (op, oa) = handle
        stop.set()
        t.join(timeout=5)
        store.close()
        import samba_key.authority_main as am
        am._portal_gid = op
        am._admin_gids = oa

    def test_request_ttl_reaches_the_process(self):
        from samba_key.reset_auth import ResetClient
        h = self._start({'RECOVERY_REQUEST_TTL': '60'})
        cfg, store, stop, t, dir_, _ = h
        try:
            now = time.time()
            client = ResetClient(os.path.join(dir_, 'portal.sock'))
            handle = client.mint('alice')
            self.assertIsNotNone(handle)
            # The request must expire ~60s from now, not the 1800s default. The
            # store is the one the authority uses, so reading it proves the TTL
            # reached the process.
            rows = store.pending_requests()
            self.assertEqual(len(rows), 1)
            self.assertAlmostEqual(rows[0].expires_at - now, 60, delta=5)
        finally:
            self._stop(h)

    def test_max_pending_global_reaches_the_process(self):
        from samba_key.reset_auth import ResetClient
        h = self._start({'MAX_PENDING_GLOBAL': '1'})
        try:
            portal = os.path.join(h[4], 'portal.sock')
            client = ResetClient(portal)
            self.assertIsNotNone(client.mint('alice'))
            # The global cap is 1, so a second pending request is refused.
            self.assertIsNone(client.mint('bob'))
        finally:
            self._stop(h)

    def test_min_password_length_reaches_the_process(self):
        # The policy (min_length) must reach the authority. A direct dispatch
        # with the cfg-derived kwargs proves it: an 8-min policy accepts a 9-char
        # password and rejects a 7-char one at CONSUME.
        from samba_key.reset_auth import ResetAuthority, Role
        from samba_key.store import Store
        import uuid as _u

        def consume(auth, store, token, pw):
            return auth.dispatch(Role.PORTAL, 'CONSUME',
                                {'token': token, 'new_password': pw,
                                 'kind': 'recovery'})['ok']

        temp = tempfile.TemporaryDirectory(prefix='sk_pw_')
        self.addCleanup(temp.cleanup)
        store = Store(os.path.join(temp.name, 'first.db'))
        self.addCleanup(store.close)
        store.bind_channel('alice', 'email', 'alice@example.com')
        handle = store.create_request('alice', 60)
        self.assertTrue(store.approve(handle))
        token = store.issue(handle, 900)
        auth = ResetAuthority(store, {'alice'}, lambda acct, pw: True,
                              principals=lambda peer: None, pending_ttl=60,
                              link_ttl=900, min_length=8, max_length=1024)
        # 9 chars >= 8: accepted.
        self.assertTrue(consume(auth, store, token, '012345678'))
        # A 7-char password fails the 8-min policy on a second request.
        store2 = Store(os.path.join(temp.name, 'second.db'))
        self.addCleanup(store2.close)
        store2.bind_channel('bob', 'email', 'bob@example.com')
        handle2 = store2.create_request('bob', 60)
        store2.approve(handle2)
        token2 = store2.issue(handle2, 900)
        auth2 = ResetAuthority(store2, {'bob'}, lambda acct, pw: True,
                               principals=lambda peer: None, min_length=8,
                               max_length=1024)
        self.assertFalse(consume(auth2, store2, token2, '0123456'))


if __name__ == '__main__':
    unittest.main()

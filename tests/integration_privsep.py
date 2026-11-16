"""Real-identity privilege-separation proof (Linux container, run as root).

Exercises the *shipped* daemon path: ``authority_main.check_separation`` and
``authority_main.serve_sockets``. The authority serves two sockets with
effective ownership and a peer check on top of the fixed role:

    portal.sock : root:portal_group 0660, role PORTAL, peer uid must be portal
    admin.sock  : root:admin_group  0660, role ADMIN,  peer must be in admin grp
    secret/*.db : root:root 0600 in a 0700 root directory

Probes (privsep_probe.py) drop to a real (uid, gid) and attempt operations. We
assert the portal is denied the admin socket, can MINT on its own socket, cannot
APPROVE on its own socket and cannot read or write the authority database, the
admin can approve, a user in neither group reaches neither socket, and the
separation check refuses an overlapping identity. A negative control adds the
portal user to the admin group and shows the check refuses *and* the breach is
real (the portal can then reach the admin socket). No docker.sock is mounted;
everything is inside the container.
"""
import os
import subprocess
import sys
import time

from samba_key.authority_main import check_separation, serve_sockets
from samba_key.store import Store


results = []


def check(name, got, want):
    ok = got == want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}',
          flush=True)


def env(name, default=None):
    val = os.environ.get(name, default)
    if val is None:
        raise SystemExit('missing env ' + name)
    return val


def gid_of(name):
    import grp
    return grp.getgrnam(name).gr_gid


def main():
    authority_dir = env('AUTHORITY_DIR')
    portal_uid = int(env('PORTAL_UID'))
    admin_uid = int(env('ADMIN_UID'))
    neither_uid = int(env('NEITHER_UID'))
    portal_gid = gid_of(env('PORTAL_GROUP', 'skportal'))
    admin_gid = gid_of(env('ADMIN_GROUP', 'skadmin'))

    # 1) The separation check must pass for the real, disjoint identities.
    check('check_separation accepts disjoint real identities',
          bool(check_separation(portal_uid, 'skportal', 'skadmin')), False)

    os.makedirs(os.path.join(authority_dir, 'secret'), exist_ok=True)
    os.chmod(authority_dir, 0o755)
    os.chmod(os.path.join(authority_dir, 'secret'), 0o700)
    auth_db = os.path.join(authority_dir, 'secret', 'authority.db')
    store = Store(auth_db)
    stop = None
    import threading
    stop = threading.Event()
    reset_log = []
    try:
        portal_sock, admin_sock, threads = serve_sockets(
            store, ['alice', 'approvaltest'],
            lambda a, p: reset_log.append((a, p)) or True,
            authority_dir, portal_uid, portal_gid, {admin_gid}, stop)
        time.sleep(1.0)  # let both sockets bind, chown, chmod

        probe = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'privsep_probe.py')
        py = sys.executable

        def run(op, path, uid, gid, extra=None):
            args = [py, probe, op, path, str(uid), str(gid)]
            if extra is not None:
                args.append(str(extra))
            proc = subprocess.run(args, capture_output=True, text=True)
            return proc

        # 2) The portal is denied the admin socket entirely.
        check('portal denied admin socket (EACCES)',
              run('connect', admin_sock, portal_uid, portal_gid).returncode, 7)
        # 3+8) The portal (as portal_uid) mints a request on its own socket; the
        # handle is carried out of the probe's stdout for the end-to-end approve.
        mint = run('mint_handle', portal_sock, portal_uid, portal_gid)
        handle = mint.stdout.strip()
        check('portal can MINT and gets a handle (own socket)',
              mint.returncode == 0 and handle not in ('', 'NONE'), True)
        # 3b) A portal cannot enroll a channel through its own socket (admin-only),
        # so it cannot inject a destination. The admin socket allows it.
        check('portal CANNOT enroll a channel (own socket refused)',
              run('channel_add', portal_sock, portal_uid, portal_gid).returncode, 1)
        check('admin CAN enroll a channel (admin socket allowed)',
              run('channel_add', admin_sock, admin_uid, admin_gid).returncode, 0)
        # 4) The portal CANNOT approve a *real* request on its own socket: it
        # mints a real handle, the APPROVE is refused (ok=False), and the admin
        # LIST shows the request is still pending (the role gate held).
        mint2 = run('mint2', portal_sock, portal_uid, portal_gid)
        own_handle = mint2.stdout.strip()
        self_ok = run('approve_handle', portal_sock, portal_uid, portal_gid,
                      own_handle)
        check('portal APPROVE of a real handle is refused (own socket)',
              self_ok.returncode == 0 and 'refused' in self_ok.stdout,
              True)
        still = run('list_has', admin_sock, admin_uid, admin_gid, own_handle)
        check('that request is still pending after the refused approve',
              still.returncode == 0 and 'pending' in still.stdout, True)
        # 5) The admin (in the admin group) can reach the admin socket.
        check('admin can reach admin socket',
              run('connect', admin_sock, admin_uid, admin_gid).returncode, 0)
        check('admin can list via admin socket',
              run('list', admin_sock, admin_uid, admin_gid).returncode, 0)
        # 6) The portal cannot read or write the authority database.
        check('portal cannot read authority DB',
              run('read_db', auth_db, portal_uid, portal_gid).returncode, 7)
        check('portal cannot write authority DB',
              run('write_db', auth_db, portal_uid, portal_gid).returncode, 7)
        check('portal cannot create file in secret dir',
              run('write_secret', os.path.join(authority_dir, 'secret'),
                  portal_uid, portal_gid).returncode, 7)
        # 7) A user in neither group reaches neither socket.
        check('neither-user denied portal socket',
              run('connect', portal_sock, neither_uid, neither_uid).returncode, 7)
        check('neither-user denied admin socket',
              run('connect', admin_sock, neither_uid, neither_uid).returncode, 7)
        # 9) End-to-end: the admin (as admin_uid) approves the portal's real
        # request over the admin socket, with the real peer check.
        check('admin can approve the portal request',
              run('approve_real', admin_sock, admin_uid, admin_gid,
                  handle).returncode, 0)
        # 10) Separation check refuses overlapping identities.
        check('check_separation refuses root portal',
              bool(check_separation(0, 'skportal', 'skadmin')), True)

        # 11) Negative control: add the portal user to the admin group. The
        # separation check must now refuse, AND the breach must be real: with
        # the portal in the admin group, the peer check (the only thing
        # stopping it) passes, so the portal can reach the admin socket -- what
        # an operator bypassing the check would enable.
        subprocess.run(['usermod', '-aG', 'skadmin', 'skportal'], check=False)
        time.sleep(0.5)
        check('check_separation refuses portal added to admin group',
              bool(check_separation(portal_uid, 'skportal', 'skadmin')), True)
        # The breach proves the supplementary-group path: the portal keeps its
        # own primary gid but, with skadmin as a *supplementary* group, reaches
        # the admin socket. The authority's peer check resolves those
        # supplementary groups and yields ADMIN.
        breach = run('breach', admin_sock, portal_uid, portal_gid, 'skportal')
        if breach.returncode != 0:
            print('breach probe stderr: ' + (breach.stderr or '').strip(),
                  file=sys.stderr)
        check('breach is real: portal in skadmin via supplementary group gets '
              'admin service (LIST served)', breach.returncode, 0)

        stop.set()
        for t in threads:
            t.join(timeout=3)
    finally:
        store.close()

    failed = sum(1 for ok in results if not ok)
    print(f'\n{len(results) - failed}/{len(results)} privilege-separation '
          f'checks passed', flush=True)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()

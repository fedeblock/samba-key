"""Full chained forgotten-password recovery driver, run inside a disposable
Samba container as root.

It closes the loop the unit tests cannot: a *real* authority (authority_main.run)
serving real portal/admin sockets to *real, disjoint users* (the portal user and
the admin user, via the setuid probe), the actual Flask recovery and reset routes,
a *simulated* delivery that captures the link the authority itself issues, and a
*real* reset (make_reset_fn -> smbpasswd -s) triggered by the web form. The Flask
test client calls the routes directly; it is not a browser or a network HTTP test.
Then the real CredentialVerifier proves the
new password works and the old one no longer does, that a second use of the same
token fails, and that revoking a channel after issue kills the link.

All accounts and credentials are fictitious and supplied by the orchestrator via
the environment. No real account is ever touched; no message is really sent.
"""
import os
import sys
import time
import threading
import subprocess

from samba_key.authority_main import run as am_run, load_eligible, prepare_storage
from samba_key.reset import make_reset_fn
from samba_key.auth import CredentialVerifier
from samba_key.config import Config

SERVER = os.environ.get('SAMBA_SERVER', '127.0.0.1')
ACCOUNT = os.environ.get('CHAIN_ACCOUNT', 'ensayo')
OLD = os.environ.get('INIT_SHORT', 'shortpw1')
NEW = os.environ.get('RESET_NEW', 'new-reset-password')
PROBE = os.environ.get('CHAIN_PROBE') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'privsep_probe.py')
TOKEN_FILE = os.environ.get('CHAIN_TOKEN_FILE', '/tmp/chain_token.txt')
AUTHORITY_DIR = os.environ.get('AUTHORITY_DIR', '/run/sk-chain')
DATA_DIR = os.environ.get('CHAIN_DATA_DIR', '/tmp/sk-chain-data')
PORTAL_UID = int(os.environ['PORTAL_UID'])
PORTAL_GID = int(os.environ['PORTAL_GID'])
ADMIN_UID = int(os.environ['ADMIN_UID'])
ADMIN_GID = int(os.environ['ADMIN_GID'])

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print('[%s] %s: got %r, want %r'
          % ('PASS' if ok else 'FAIL', name, got, want), flush=True)


# --- A simulated delivery: the authority builds and "sends" the link; we only
# capture the token it put in the link (no real transport). The token never
# reaches the portal -- the portal only ever gets the handle. ---
class CapturingDelivery:
    def __init__(self, path):
        self.path = path
        self.destinations = []

    def send(self, kind, value, subject, body):
        token = body.rsplit('#t=', 1)[-1].strip()
        self.destinations.append((kind, value))
        with open(self.path, 'a') as fh:
            fh.write(token + '\n')


def run_probe(op, socket_path, uid, gid, extra=None, env=None):
    args = [sys.executable, PROBE, op, socket_path, str(uid), str(gid)]
    if extra is not None:
        args.append(str(extra))
    e = dict(os.environ)
    if env:
        e.update(env)
    proc = subprocess.run(args, capture_output=True, text=True, env=e)
    return proc


def wait_socket(path, deadline=15):
    end = time.time() + deadline
    while time.time() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def wait_token_file(path, at_least=1, deadline=15):
    end = time.time() + deadline
    while time.time() < end:
        if os.path.exists(path):
            with open(path) as fh:
                lines = [l.strip() for l in fh if l.strip()]
            if len(lines) >= at_least:
                return lines
        time.sleep(0.05)
    return []


# --- Start the real authority as root, with a real store and a simulated
# delivery. The portal/admin operations are done by real users via the probe. ---
cfg = Config({'RECOVERY_MODE': 'approval',
              'AUTHORITY_DIR': AUTHORITY_DIR,
              'AUTHORITY_SPLIT_SOCKETS': 'true',
              'RECOVERY_DATA_DIR': DATA_DIR,
              'RECOVERY_SOCKET': os.path.join(AUTHORITY_DIR, 'portal', 'portal.sock'),
              'PORTAL_UID': str(PORTAL_UID),
              'PORTAL_GROUP': os.environ.get('PORTAL_GROUP', 'skportal'),
              'ADMIN_GROUP': os.environ.get('ADMIN_GROUP', 'skadmin'),
              'BASE_URL': 'https://portal.example'})
store = prepare_storage(cfg)
eligible = {ACCOUNT}
stop = threading.Event()
delivery = CapturingDelivery(TOKEN_FILE)
os.makedirs(AUTHORITY_DIR, exist_ok=True)
# Reset the token file so the count starts at zero.
open(TOKEN_FILE, 'w').close()


def authority():
    am_run(cfg, store, eligible, delivery, stop,
           peer_credential=None, deliver_interval=0.5)


t = threading.Thread(target=authority, daemon=True)
t.start()
portal_sock = os.path.join(AUTHORITY_DIR, 'portal', 'portal.sock')
admin_sock = os.path.join(AUTHORITY_DIR, 'admin.sock')
check('authority portal socket came up', wait_socket(portal_sock), True)
check('authority admin socket came up', wait_socket(admin_sock), True)

# Enrollment is admin-driven and covered separately (test_admin.py). For the
# chained flow the orchestrator -- which owns the authority's store as root --
# binds a channel for the account, so the worker has a destination to deliver to
# and a fingerprint to pin at approval.
store.bind_channel(ACCOUNT, 'email', ACCOUNT + '@example.test')
store.bind_channel(ACCOUNT, 'telegram', '123456789')

# 1) Submit the actual web request as the real unprivileged portal user.
proc = run_probe('web_request', portal_sock, PORTAL_UID, PORTAL_GID,
                 env={'MINT_ACCOUNT': ACCOUNT, 'WEB_CHANNEL': 'email'})
check('portal web POST accepted recovery request', proc.returncode, 0)
# The handle is obtained by the administrator from the separate admin socket;
# it is not returned by the web page.
proc = run_probe('list_handle', admin_sock, ADMIN_UID, ADMIN_GID,
                 env={'MINT_ACCOUNT': ACCOUNT})
handle = (proc.stdout or '').strip()
check('admin LIST found the pending request', handle not in ('', 'NONE'), True)

# 2) The admin user approves, over the admin socket the portal cannot reach.
proc = run_probe('approve_real', admin_sock, ADMIN_UID, ADMIN_GID, handle)
check('admin APPROVE over the admin socket', proc.returncode, 0)

# 3) The authority's delivery worker issues the link and the simulated delivery
#    captures the token the authority itself generated (not the portal).
tokens = wait_token_file(TOKEN_FILE, at_least=1)
check('authority issued and captured the link token', bool(tokens), True)
check('first request delivered to selected email',
      delivery.destinations[:1] == [('email', ACCOUNT + '@example.test')], True)
token = tokens[0] if tokens else ''

# 4) The portal's real reset route consumes the token with a new password; the
#    authority's CONSUME runs the REAL reset_fn (smbpasswd -s) as root.
proc = run_probe('web_consume', portal_sock, PORTAL_UID, PORTAL_GID, token,
                 env={'CHAIN_NEW': NEW})
check('portal CONSUME performed the real reset', proc.returncode, 0)

# 5) The real verifier: the new password now works and the old one no longer.
verifier = CredentialVerifier(SERVER, share='sktest')
check('new password works after the chained reset',
      verifier.verify(ACCOUNT, NEW), True)
check('old password fails after the chained reset',
      verifier.verify(ACCOUNT, OLD), False)

# 6) The same token cannot be used a second time (single use).
proc = run_probe('web_consume', portal_sock, PORTAL_UID, PORTAL_GID, token,
                 env={'CHAIN_NEW': NEW})
check('second use of the token fails', proc.returncode, 1)

# 7) Negative: revoking the channel after issue kills an outstanding link. The
#    first request is consumed (freeing the per-account cap), so a second request
#    for the same account can be minted and issued; revoking the channel then
#    invalidates that issued link, so its CONSUME must fail.
proc = run_probe('web_request', portal_sock, PORTAL_UID, PORTAL_GID,
                 env={'MINT_ACCOUNT': ACCOUNT, 'WEB_CHANNEL': 'telegram'})
check('a second web request is accepted', proc.returncode, 0)
proc = run_probe('list_handle', admin_sock, ADMIN_UID, ADMIN_GID,
                 env={'MINT_ACCOUNT': ACCOUNT})
handle2 = (proc.stdout or '').strip()
check('a second request can be minted after the first is consumed',
      handle2 not in ('', 'NONE'), True)
run_probe('approve_real', admin_sock, ADMIN_UID, ADMIN_GID, handle2)
tokens = wait_token_file(TOKEN_FILE, at_least=2)
check('the second link was issued', len(tokens) >= 2, True)
check('second request delivered to selected Telegram chat',
      delivery.destinations[1:2] == [('telegram', '123456789')], True)
# Revoke the channel: the issued link to that destination must die.
store.revoke_channel(ACCOUNT, 'telegram')
if len(tokens) >= 2:
    proc = run_probe('web_consume', portal_sock, PORTAL_UID, PORTAL_GID, tokens[1],
                     env={'CHAIN_NEW': NEW})
    check('revoked channel kills the issued link (CONSUME fails)',
          proc.returncode, 1)
else:
    check('revoked channel kills the issued link (no token to consume)',
          False, True)

stop.set()
t.join(timeout=5)
store.close()

failed = sum(1 for ok in results if not ok)
print('\n%d/%d chain checks passed' % (len(results) - failed, len(results)),
      flush=True)
sys.exit(1 if failed else 0)

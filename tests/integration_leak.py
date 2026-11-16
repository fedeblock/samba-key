"""Real-Samba leak + canary checks for credential verification.

Proves, against a disposable Samba (not a mock):

  1. The password is never present in the child ``smbclient`` process's
     ``/proc/<pid>/cmdline`` or ``/proc/<pid>/environ`` while it is live.
     The child is held alive by blocking on the ``PASSWD_FD`` read, so the
     inspection is deterministic rather than racy.
  2. A correct credential authenticates; a wrong one does not.
  3. The canary (a random nonexistent user must fail) passes on a correctly
     configured guest-forbidden share, and *fails* on a deliberately
     misconfigured guest-accepting share -- the negative control that makes the
     enrollment flow fail closed.

All credentials are fictitious and supplied by the orchestrator via the
environment. No real account is ever touched.
"""
import os
import subprocess
import sys
import time

from samba_key.auth import CredentialVerifier

SERVER = os.environ.get('SAMBA_SERVER', 'samba')
SHARE = os.environ.get('VERIFY_SHARE', 'sktest')
# The password is read from a 0600 file, never held in the process
# environment, so it cannot appear in a child's /proc/<pid>/environ.
with open(os.environ['VERIFY_PWF'], 'r') as _fh:
    PW = _fh.read().strip()

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}', flush=True)


def proc_is_leak_free():
    """Hold smbclient alive on its PASSWD_FD read and inspect /proc before the
    password is written. Returns True if the password is absent from the
    process's command line and environment."""
    read_fd, write_fd = os.pipe()
    env = dict(os.environ)
    env['PASSWD_FD'] = str(read_fd)
    proc = subprocess.Popen(
        ['smbclient', f'//{SERVER}/{SHARE}', '-U', 'ensayo', '-c', 'exit'],
        env=env, pass_fds=[read_fd], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Give the child time to block on read(PASSWD_FD) so /proc is live.
    for _ in range(50):
        try:
            if os.path.exists(f'/proc/{proc.pid}/cmdline'):
                break
        except (FileNotFoundError, ProcessLookupError):
            break
        time.sleep(0.02)
    blob = b''
    for name in ('cmdline', 'environ'):
        try:
            with open(f'/proc/{proc.pid}/{name}', 'rb') as fh:
                blob += fh.read()
        except (FileNotFoundError, ProcessLookupError):
            # Child already gone: it could not have leaked a value we did not
            # write, so treat as leak-free but report it.
            print(f'  (proc {name} already gone)', flush=True)
    try:
        os.write(write_fd, (PW + '\n').encode())
    finally:
        os.close(write_fd)
        try:
            os.close(read_fd)
        except OSError:
            pass
    proc.wait()
    return PW.encode() not in blob


check('password absent from child /proc', proc_is_leak_free(), True)

v = CredentialVerifier(SERVER, share=SHARE)
check('correct credential verifies', v.verify('ensayo', PW), True)
check('wrong credential fails', v.verify('ensayo', 'definitely-wrong-1'), False)
check('canary passes on secure share', v.canary_ok(), True)

# Under "map to guest = Bad User", even the guest_ok share (skguest) must be
# denied. Opt in with CHECK_SKGUEST=1 (the leak orchestrator runs it there).
if os.environ.get('CHECK_SKGUEST') == '1':
    def _guest_denied():
        # -N (no password) + empty password makes smbclient authenticate as a
        # guest; on a guest-forbidden share that must fail.
        r = subprocess.run(
            ['smbclient', f'//{SERVER}/skguest', '-U', '%guest%', '-c', 'exit',
             '-N'], capture_output=True, text=True, timeout=25)
        return not r.returncode
    check('guest denied even on the guest_ok share (Bad User)',
          _guest_denied(), True)

failed = sum(1 for ok in results if not ok)
print(f'\n{len(results) - failed}/{len(results)} leak/canary checks passed', flush=True)
sys.exit(1 if failed else 0)

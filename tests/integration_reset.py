"""Real-Samba forgotten-password reset integration driver.

Runs inside the disposable Samba container *as root* (where the passdb lives)
and exercises the *real* ``make_reset_fn`` transport: it resets an allowlisted
account to a new password **without knowing the old one** via the real
``smbpasswd -s`` invocation (the new password on a stdin pipe, never argv/env),
then proves with the real ``CredentialVerifier`` that the new password works
and the old one no longer does. It also proves that a non-allowlisted account
and ``root`` are refused.

All credentials are fictitious and supplied by the orchestrator via the
environment. No real account is ever touched.
"""
import os
import sys

from samba_key.reset import make_reset_fn
from samba_key.auth import CredentialVerifier

SERVER = os.environ.get('SAMBA_SERVER', '127.0.0.1')
OLD = os.environ.get('INIT_SHORT', 'shortpw1')          # the old password
NEW = os.environ.get('RESET_NEW', 'new-reset-password')  # 16 chars, >= 12
OTHER = os.environ.get('INIT_LONG', '0123456789abcdefghijklmnopqrstuv0123456789')

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}',
          flush=True)


# Only the allowlisted account may be reset; the transport is the real one
# (smbpasswd -s, password on a stdin pipe).
reset_fn = make_reset_fn({'ensayo'}, executable='smbpasswd',
                         min_length=12, max_length=64, timeout=30)
verifier = CredentialVerifier(SERVER, share='sktest')

# 1) The old password is correct before the reset.
check('old password verifies before reset', verifier.verify('ensayo', OLD), True)

# 2) The privileged reset sets a new password without the old one.
check('privileged reset succeeds (no old password needed)',
      reset_fn('ensayo', NEW), True)

# 3) The new password now works and the old one no longer does.
check('new password works after reset', verifier.verify('ensayo', NEW), True)
check('old password fails after reset', verifier.verify('ensayo', OLD), False)

# 4) A non-allowlisted account and root are refused.
check('non-allowlisted account refused', reset_fn('ensayo_long', OTHER[:20]),
      False)
check('root refused', reset_fn('root', NEW), False)

# 5) A fresh reset still works (the Samba layer is idempotent); single-use
# consumption of an authority *request* is covered by the store-level tests.
check('a second privileged reset still succeeds',
      reset_fn('ensayo', NEW), True)

failed = sum(1 for ok in results if not ok)
print(f'\n{len(results) - failed}/{len(results)} reset checks passed', flush=True)
sys.exit(1 if failed else 0)

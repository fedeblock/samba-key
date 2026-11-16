"""Real-Samba credential-verification matrix.

Runs the portal's own ``samba_key.auth.CredentialVerifier`` against a disposable
Samba server and asserts that, for the current ``map to guest`` mode (supplied
by the orchestrator via the server's ``MAP_TO_GUEST`` environment), a real
authentication succeeds while wrong, empty (guest) and unknown-user attempts all
fail. This is the proof that a guest session is never mistaken for a valid login
under any guest-mapping setting.

All credentials are fictitious and supplied by the orchestrator via the
environment. No real account is ever touched.
"""
import os
import sys

from samba_key.auth import CredentialVerifier

SERVER = os.environ.get('SAMBA_SERVER', 'samba')
PW = os.environ.get('INIT_SHORT', 'shortpw1')

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}', flush=True)


v = CredentialVerifier(SERVER, share='sktest')

check('correct credentials verify', v.verify('ensayo', PW), True)
check('wrong password fails', v.verify('ensayo', 'definitely-wrong-1'), False)
check('empty (guest) password fails', v.verify('ensayo', ''), False)
check('nonexistent user fails', v.verify('ghost-account', PW), False)

# Finding 2: the guest-forbidden preflight (canary) must SUCCEED on this secure
# share: a random *nonexistent* user with a random password must fail, so a
# guest session is never mistaken for a valid login under any map-to-guest mode.
# This is the property the retired channel-binding path relied on; the verifier
# itself now owns it.
check('canary: a nonexistent user fails (guest-forbidden share)',
      v.canary_ok(), True)

failed = sum(1 for ok in results if not ok)
print(f'\n{len(results) - failed}/{len(results)} verification checks passed', flush=True)
sys.exit(1 if failed else 0)

"""Negative control for the verifier canary.

Against a disposable Samba configured with ``map to guest = Bad Password`` and a
guest-*accepting* share, a random nonexistent user *succeeds* as a guest.  The
canary must therefore report the verifier as **unsafe** (``canary_ok() ==
False``), which is what makes any reauthentication-gated flow fail closed instead
of trusting a misconfigured share.
"""
import os
import sys

from samba_key.auth import CredentialVerifier

SERVER = os.environ.get('SAMBA_SERVER', 'samba')

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}', flush=True)


v = CredentialVerifier(SERVER, share='skguest')
# On a guest-accepting share, the canary must fail: an unknown user "passes".
check('canary detects guest-accepting share', v.canary_ok(), False)
# A wrong password must also fail on this share (not be mapped to a guest that
# "succeeds").
check('wrong password fails on guest-accepting share',
      v.verify('ensayo', 'definitely-wrong-1'), False)

failed = sum(1 for ok in results if not ok)
print(f'\n{len(results) - failed}/{len(results)} negative-control checks passed', flush=True)
sys.exit(1 if failed else 0)

"""Real-Samba integration driver.

Runs the portal's own ``samba_key.core.PasswordChanger`` against a disposable
Samba server over the test network. It is launched by
``tests/run_integration_docker.sh`` inside an ephemeral client container; it is
not part of the default ``unittest`` discovery.

It exercises the actual SMB password-change protocol (not a mock) and checks:

  A. A short but valid current password can be changed to a compliant new one.
  B. An incorrect current password is rejected.
  C. After a change, the previous password stops working and the new one works.
  D. A current password longer than the *new-password* maximum can still be
     changed to a compliant new one (the new policy must not block it). A
     contrast case shows that capping the current password at the new-password
     maximum would reject it.

All credentials are fictitious and supplied by the orchestrator via the
environment. No real account is ever touched.
"""
import os
import sys

from samba_key.core import PasswordChanger

SERVER = os.environ.get('SAMBA_SERVER', 'samba')
INIT_SHORT = os.environ.get('INIT_SHORT', 'shortpw1')           # 8 chars, < min(12)
INIT_LONG = os.environ.get(
    'INIT_LONG', '0123456789abcdefghijklmnopqrstuv0123456789')  # 42 chars, > new max
NEW_A = 'new-password-aaa'  # 16 chars, within [12, 1024]
NEW_B = 'new-password-bbb'
LONG_NEW = 'abcd12345678'   # 12 chars, within [12, 12]

results = []


def check(name, got, want):
    ok = got is want
    results.append(ok)
    print(f'[{"PASS" if ok else "FAIL"}] {name}: got {got!r}, want {want!r}', flush=True)


# A short but valid current password is allowed; the new password meets policy.
pc = PasswordChanger(SERVER, min_length=12, max_length=1024, max_current_length=4096)

# B. An incorrect current password must be rejected.
check('A/B wrong current password is rejected',
      pc.change('ensayo', 'definitely-wrong-1', NEW_A), False)
# A. A short, correct current password can change to a compliant new password.
check('A short valid current password changes to compliant new',
      pc.change('ensayo', INIT_SHORT, NEW_A), True)
# C. The previous password no longer works ...
check('C previous password no longer works',
      pc.change('ensayo', INIT_SHORT, NEW_B), False)
# C. ... and the new password works for the next change.
check('C new password works for the next change',
      pc.change('ensayo', NEW_A, NEW_B), True)

# D. A current password longer than the new-password maximum can still be
#    changed to a compliant new one. The current password is bounded by the
#    generous technical cap, not by the new-password policy.
pc_small = PasswordChanger(SERVER, min_length=12, max_length=12, max_current_length=4096)
check('D long current (within cap) changes to short compliant new',
      pc_small.change('ensayo_long', INIT_LONG, LONG_NEW), True)

# Contrast: capping the current password at the new-password maximum (the old,
# buggy behaviour) would reject the same change locally, before contacting Samba.
pc_tight = PasswordChanger(SERVER, min_length=12, max_length=12, max_current_length=12)
check('D contrast: current beyond new-max is rejected when capped',
      pc_tight.change('ensayo_long', INIT_LONG, LONG_NEW), False)

failed = sum(1 for ok in results if not ok)
print(f'\n{len(results) - failed}/{len(results)} checks passed', flush=True)
sys.exit(1 if failed else 0)

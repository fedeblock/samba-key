"""Run only inside the isolated test network against the disposable Samba."""
import os
import re
import time

assert os.environ.get('SAMBA_SERVER') == 'samba-ensayo', 'Refusing to run against a non-test server'
from samba_key.app import create_app

client = create_app().test_client()
base = 'https://test.invalid'


def change(old, new):
    page = client.get('/?lang=en', base_url=base).get_data(as_text=True)
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    return client.post('/?lang=en', base_url=base, data={
        'csrf': token, 'username': 'ensayo', 'old_password': old,
        'new_password': new, 'confirm_password': new,
    }).get_data(as_text=True)


time.sleep(3)
assert 'Could not change' in change('IncorrectPassword123!', 'NewPasswordForTest456!')
assert 'Password changed' in change('OldPasswordForTest123!', 'NewPasswordForTest456!')
assert 'Could not change' in change('OldPasswordForTest123!', 'ThirdPasswordForTest789!')
assert 'Password changed' in change('NewPasswordForTest456!', 'ThirdPasswordForTest789!')
print('Integration passed: incorrect password rejected, valid change accepted, old password rejected, new password accepted.')

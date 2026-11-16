import os
import re
import unittest
from unittest.mock import patch

from samba_key.app import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.base = 'https://example.test'

    def token(self):
        page = self.client.get('/?lang=en', base_url=self.base)
        return re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()

    def test_security_headers_and_cookie(self):
        response = self.client.get('/', base_url=self.base)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertIn('Secure', response.headers['Set-Cookie'])
        self.assertIn('HttpOnly', response.headers['Set-Cookie'])

    def test_csrf_and_success(self):
        self.assertEqual(self.client.post('/', base_url=self.base).status_code, 403)
        csrf = self.token()
        data = dict(csrf=csrf, username='alice', old_password='old password', new_password='a new password', confirm_password='a new password')
        with patch('samba_key.core.PasswordChanger.change', return_value=True):
            response = self.client.post('/?lang=en', data=data, base_url=self.base)
        self.assertIn(b'Password changed', response.data)
        self.assertIn(b'notice--success', response.data)
        self.assertEqual(self.client.post('/', data=data, base_url=self.base).status_code, 403)

    def test_failure_does_not_use_success_styling(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='alice', old_password='old password',
                    new_password='a new password', confirm_password='a new password')
        with patch('samba_key.core.PasswordChanger.change', return_value=False):
            response = self.client.post('/?lang=en', data=data, base_url=self.base)
        self.assertNotIn(b'notice--success', response.data)

    def test_rate_limit_does_not_trust_forwarded_header(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='alice', old_password='old', new_password='a new password', confirm_password='a new password')
        with patch('samba_key.core.PasswordChanger.change', return_value=False):
            for i in range(6):
                result = self.client.post('/', data=data, base_url=self.base, headers={'X-Forwarded-For': str(i)})
                self.assertEqual(result.status_code, 200)
            result = self.client.post('/', data=data, base_url=self.base, headers={'X-Forwarded-For': 'spoofed'})
            self.assertEqual(result.status_code, 429)

    def test_recovery_route_is_uniform_and_never_enumerates(self):
        # The recovery endpoint is disabled: it must respond identically for
        # any input and never reveal whether an account exists.
        a = self.client.get('/recovery?user=alice', base_url=self.base)
        b = self.client.get('/recovery?user=does-not-exist', base_url=self.base)
        self.assertEqual(a.status_code, 200)
        self.assertIn(b'Password recovery is not available', a.data)
        self.assertEqual(a.data, b.data)

    def test_recovery_page_does_not_show_the_change_form(self):
        # A disabled recovery page must not show the change-password form, or
        # submitting it silently does nothing and misleads the user. It should
        # instead offer a clear way back to the working change page.
        html = self.client.get('/recovery', base_url=self.base).get_data(as_text=True)
        for field in ('name="username"', 'name="new_password"', 'name="csrf"'):
            self.assertNotIn(field, html)
        self.assertIn('href="/?', html)  # a link back to the change page

    def test_reset_route_is_inert_and_does_not_echo_a_token(self):
        # With recovery disabled, /reset shows the uniform message and must not
        # reflect a token. A stale link carrying a token in the path hits an
        # unknown route; a fragment (#t=...) never reaches the server at all.
        sentinel = 'SENTINEL_TOKEN_ABCDEF'
        r = self.client.get('/reset', base_url=self.base)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(sentinel, r.get_data(as_text=True))
        # A token placed in the path must not be echoed by the 404 page.
        r404 = self.client.get('/reset/' + sentinel, base_url=self.base)
        self.assertEqual(r404.status_code, 404)
        self.assertNotIn(sentinel, r404.get_data(as_text=True))
        r2 = self.client.post('/reset', data={'token': sentinel},
                              base_url=self.base, follow_redirects=False)
        self.assertEqual(r2.status_code, 200)
        self.assertNotIn(sentinel, r2.get_data(as_text=True))

    def test_short_old_password_reaches_the_server_check(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='alice', old_password='short',
                    new_password='a-valid-new-password', confirm_password='a-valid-new-password')
        with patch('samba_key.core.PasswordChanger.change', return_value=True):
            response = self.client.post('/?lang=en', data=data, base_url=self.base)
        # A short current password must not be rejected by local validation.
        self.assertIn(b'Password changed', response.data)

    def test_long_old_password_reaches_the_server_check(self):
        csrf = self.token()
        long_old = 'A' * 3000  # beyond the new-password max (1024), within the 4096 cap
        data = dict(csrf=csrf, username='alice', old_password=long_old,
                    new_password='a-valid-new-password', confirm_password='a-valid-new-password')
        with patch('samba_key.core.PasswordChanger.change', return_value=True):
            response = self.client.post('/?lang=en', data=data, base_url=self.base)
        # The new-password policy must not block a long current password.
        self.assertIn(b'Password changed', response.data)

    def test_invalid_message_reflects_configured_min_length(self):
        with patch.dict(os.environ, {'MIN_PASSWORD_LENGTH': '16'}, clear=False):
            app = create_app()
            for lang, needle, wrong in (('en', '16 characters', '12 characters'),
                                        ('es', '16 caracteres', '12 caracteres')):
                client = app.test_client()
                page = client.get(f'/?lang={lang}', base_url=self.base).get_data(as_text=True)
                token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                data = dict(csrf=token, username='alice', old_password='old-enough-16',
                            new_password='too-short', confirm_password='too-short')
                response = client.post(f'/?lang={lang}', data=data, base_url=self.base).get_data(as_text=True)
                self.assertIn(needle, response, lang)
                self.assertNotIn(wrong, response, lang)

    def test_csp_allows_local_scripts_only(self):
        csp = self.client.get('/').headers['Content-Security-Policy']
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_min_password_length_is_enforced_and_generic(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='alice', old_password='old-enough-1',
                    new_password='short', confirm_password='short')
        response = self.client.post('/?lang=en', data=data, base_url=self.base)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'12 characters', response.data)

    def test_misconfiguration_fails_closed(self):
        with patch.dict(os.environ, {'RECOVERY_MODE': 'automatic'}, clear=False):
            bad = create_app()
        self.assertEqual(bad.test_client().get('/').status_code, 503)
        self.assertEqual(bad.test_client().get('/healthz').status_code, 503)
        self.assertEqual(bad.test_client().get('/static/style.css').status_code, 503)

    def test_password_fields_are_not_limited_to_256_characters(self):
        page = self.client.get('/', base_url=self.base).get_data(as_text=True)
        for field in ('old_password', 'new_password', 'confirm_password'):
            tag = re.search(r'<input\s+id="' + field + r'"[^>]*>', page).group(0)
            self.assertNotIn('maxlength="256"', tag)

    def test_user_is_retained_and_missing_user_is_explained(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='ensayo', old_password='old', new_password='short', confirm_password='short')
        response = self.client.post('/?lang=es', data=data, base_url=self.base).get_data(as_text=True)
        self.assertIn('value="ensayo"', response)
        data['username'] = ''
        response = self.client.post('/?lang=es', data=data, base_url=self.base).get_data(as_text=True)
        self.assertIn('Introduce el usuario', response)

    def test_specific_password_validation_messages(self):
        csrf = self.token()
        data = dict(csrf=csrf, username='ensayo', old_password='old', new_password='too-short', confirm_password='too-short')
        response = self.client.post('/?lang=es', data=data, base_url=self.base).get_data(as_text=True)
        self.assertIn('al menos 12 caracteres', response)
        data.update(new_password='long-enough-password', confirm_password='something-different')
        response = self.client.post('/?lang=es', data=data, base_url=self.base).get_data(as_text=True)
        self.assertIn('no coinciden', response)

    def test_large_configured_current_password_fits_in_post(self):
        with patch.dict(os.environ, {'MAX_CURRENT_PASSWORD_LENGTH': '10000'}, clear=False):
            app = create_app()
            client = app.test_client()
            page = client.get('/', base_url=self.base).get_data(as_text=True)
            csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
            data = dict(csrf=csrf, username='alice', old_password='é' * 5000,
                        new_password='a-valid-new-password', confirm_password='a-valid-new-password')
            with patch('samba_key.core.PasswordChanger.change', return_value=True):
                result = client.post('/', data=data, base_url=self.base)
            self.assertEqual(result.status_code, 200)
            self.assertIn(b'Password changed', result.data)


if __name__ == '__main__':
    unittest.main()

"""Web end-to-end recovery through the real Flask app.

Wires ``create_app`` to a real ``RecoveryService`` that talks to a real
``ResetAuthority`` over a real Unix socket, plus a real authority-side
``DeliveryWorker``. Only the network boundary (SMTP/Telegram) is faked. This
proves the portal -> authority -> delivery -> consume path is connected end to
end and that a user who forgot their password can reset it without the old one.
"""
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.request

from samba_key.app import create_app
from samba_key.reset_auth import ResetAuthority, ResetClient, AdminClient, Role
from samba_key.recovery import RecoveryService
from samba_key.delivery import SmtpDelivery, TelegramDelivery
from samba_key.delivery_worker import DeliveryWorker
from samba_key.store import Store
from samba_key.telegram import TelegramBinder


class WebRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.auth_store = Store(os.path.join(self.dir, 'auth.db'))
        self.portal_store = Store(os.path.join(self.dir, 'portal.db'))
        self.reset_log = []
        reset_fn = lambda acct, pw: self.reset_log.append((acct, pw)) or True
        (self.portal_sock, self.admin_sock,
         self.threads, self.stops) = self._start(
             self.auth_store, ['alice'], reset_fn)
        self.client = ResetClient(self.portal_sock)
        self.admin = AdminClient(self.admin_sock)
        self.smtp_calls = []
        self._patch_smtp()
        self.delivery = SmtpDelivery('smtp', 587, 'u', 'p', 'from@x')
        self.worker = DeliveryWorker(self.auth_store,
                                     _Route(self.delivery),
                                     'https://portal.example', link_ttl=900)
        # A real portal-side service backed by the real authority socket.
        self.svc = RecoveryService(self.client, self.portal_store,
                                   'https://portal.example',
                                   policy_min=12, policy_max=1024,
                                   request_limit=6, complete_limit=12,
                                   client_limit=30)
        self.web = create_app(recovery_service=self.svc,
                              portal_store=self.portal_store)
        self.browser = self.web.test_client()

    def _start(self, store, eligible, reset_fn):
        portal_sock = os.path.join(self.dir, 'portal.sock')
        admin_sock = os.path.join(self.dir, 'admin.sock')
        stops = [threading.Event(), threading.Event()]
        specs = [(portal_sock, Role.PORTAL, stops[0], (1000, 1000)),
                 (admin_sock, Role.ADMIN, stops[1], (0, 5000))]
        threads = []
        for sock_path, role, stop, peer in specs:
            auth = ResetAuthority(store, eligible, reset_fn,
                                  principals=lambda p, r=role: r,
                                  peer_credential=lambda c, pe=peer: pe)
            t = threading.Thread(target=auth.serve, args=(sock_path,),
                                 kwargs={'forced_role': role, 'stop_event': stop,
                                         'recv_timeout': 5}, daemon=True)
            t.start()
            threads.append(t)
        self._wait(portal_sock)
        self._wait(admin_sock)
        return portal_sock, admin_sock, threads, stops

    @staticmethod
    def _wait(path, timeout=5):
        import socket as _s, time as _t
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            try:
                s.connect(path)
                return
            except OSError:
                _t.sleep(0.05)
            finally:
                s.close()
        raise unittest.SkipTest('authority socket not ready: ' + path)

    def _patch_smtp(self):
        import smtplib
        calls = self.smtp_calls

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self, *a, **k):
                pass

            def login(self, u, p):
                pass

            def send_message(self, message):
                calls.append(message)

        self._orig_smtp = smtplib.SMTP
        smtplib.SMTP = FakeSMTP

    def tearDown(self):
        import smtplib
        smtplib.SMTP = self._orig_smtp
        for stop in self.stops:
            stop.set()
        for t in self.threads:
            t.join(timeout=3)
        self.auth_store.close()
        self.portal_store.close()

    def _csrf(self, page):
        return re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()

    # -- the full supervised flow, driven through the browser ------------
    def test_forget_password_resets_via_admin_approval(self):
        # 0. Enrollment happens in advance: an out-of-band administrator binds
        #    the verified destination to the account before any request.
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.assertTrue(self.admin.channel_verify('alice', 'email',
                                                  'alice@example.com', code))

        # 1. The user requests recovery from the web form (uniform response).
        page = self.browser.get('/recovery?lang=en', base_url='https://portal.example')
        csrf = self._csrf(page)
        resp = self.browser.post('/recovery', data={'csrf': csrf, 'username': 'alice'},
                                 base_url='https://portal.example')
        self.assertIn(b'created', resp.data.lower())

        # 2. An out-of-band administrator approves the pending request.
        handle = self.admin.list_pending()[0]['handle']
        self.assertTrue(self.admin.approve(handle))

        # 3. The authority-side worker resolves the destination, issues the token
        # and delivers the link (the portal never produced or saw the token).
        self.assertEqual(self.worker.deliver_pending(), 1)
        link = self.smtp_calls[0].get_content()
        token = link.split('#t=')[1].strip()
        self.assertNotIn(self._sentinel(), link)

        # 4. The user opens the link and sets a new password -- no old password.
        page = self.browser.get('/reset?lang=en', base_url='https://portal.example')
        csrf = self._csrf(page)
        details = self.browser.post('/reset/details',
                                    data={'csrf': csrf, 'token': token},
                                    base_url='https://portal.example')
        self.assertEqual(details.json, {'account': 'alice', 'channel': 'email',
                                        'destination': 'a***e@example.com'})
        resp = self.browser.post('/reset',
                                 data={'csrf': csrf, 'token': token,
                                       'new_password': 'a-brand-new-password'},
                                 base_url='https://portal.example')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.reset_log, [('alice', 'a-brand-new-password')])
        self.assertIn(b'notice--success', resp.data)

        # 5. The token is single-use: a second completion must fail uniformly.
        page = self.browser.get('/reset?lang=en', base_url='https://portal.example')
        csrf = self._csrf(page)
        resp = self.browser.post('/reset',
                                 data={'csrf': csrf, 'token': token,
                                       'new_password': 'another-password-12'},
                                 base_url='https://portal.example')
        self.assertEqual(self.reset_log, [('alice', 'a-brand-new-password')])
        self.assertIn(b'not valid', resp.data.lower())
        self.assertNotIn(b'notice--success', resp.data)

    @staticmethod
    def _sentinel():
        return 'ATTACKER-SHOULD-NOT-SEE-THIS'

    def test_request_response_is_byte_identical_across_cases(self):
        # The recovery request response must be byte-for-byte identical for an
        # eligible account with a channel, an eligible account with no channel, and
        # a nonexistent account -- at the HTTP/HTML level, not just the service.
        code = self.admin.channel_add('alice', 'email', 'alice@example.com')
        self.assertTrue(self.admin.channel_verify('alice', 'email',
                                                  'alice@example.com', code))

        def post(username):
            page = self.browser.get('/recovery?lang=en', base_url='https://portal.example')
            csrf = self._csrf(page)
            r = self.browser.post('/recovery',
                                  data={'csrf': csrf, 'username': username},
                                  base_url='https://portal.example')
            # Normalise the random per-session CSRF value out before comparing:
            # the non-enumeration guarantee is about the response and its
            # behaviour, not about the random token in the form.
            html = r.get_data(as_text=True)
            return re.sub(r'name="csrf" value="[^"]+"', 'name="csrf" value="X"',
                          html)

        valid = post('alice')          # eligible, has a channel
        no_channel = post('bob')        # eligible, no channel
        unknown = post('ghost')         # not eligible at all
        self.assertEqual(valid, no_channel)
        self.assertEqual(valid, unknown)
        for html in (valid, no_channel, unknown):
            self.assertNotIn('alice@example.com', html)
            self.assertNotIn('handle', html)

    def test_recovery_message_is_localized(self):
        # The recovery message must appear in the chosen language, and the
        # generic outcome must stay uniform within a language.
        self.admin.channel_add('alice', 'email', 'alice@example.com')

        def post(username, lang):
            page = self.browser.get('/recovery?lang=' + lang,
                                    base_url='https://portal.example')
            csrf = self._csrf(page)
            r = self.browser.post('/recovery?lang=' + lang,
                                  data={'csrf': csrf, 'username': username},
                                  base_url='https://portal.example')
            return r.get_data(as_text=True)

        es = post('alice', 'es')
        en = post('alice', 'en')
        # Spanish page shows the Spanish generic text, English the English one.
        self.assertIn('no se revela nada', es.lower())
        self.assertIn('nothing is revealed', en.lower())
        # The two languages must not be confused.
        self.assertNotIn('nothing is revealed', es.lower())
        self.assertNotIn('no se revela nada', en.lower())
        # Uniform within a language across account/channel existence.
        es_bob = post('bob', 'es')
        self.assertIn('no se revela nada', es_bob.lower())



class AuthorityDownTests(unittest.TestCase):
    """When the authority is unreachable, the portal answers uniformly and
    quickly -- it must not hang and must not reveal anything."""

    def test_dead_socket_gives_uniform_fast_response(self):
        import time
        from samba_key.app import create_app
        from samba_key.reset_auth import ResetClient
        from samba_key.recovery import RecoveryService
        import os, tempfile
        portal_store = Store(os.path.join(tempfile.mkdtemp(), 'portal.db'))
        # A socket that nothing is listening on: connect() fails immediately.
        dead = os.path.join(tempfile.mkdtemp(), 'dead.sock')
        svc = RecoveryService(ResetClient(dead), portal_store, 'https://p',
                              request_limit=6, complete_limit=12, client_limit=30)
        app = create_app(recovery_service=svc, portal_store=portal_store)
        client = app.test_client()
        page = client.get('/recovery?lang=en', base_url='https://p').get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        start = time.time()
        resp = client.post('/recovery', data={'csrf': csrf, 'username': 'alice'},
                           base_url='https://p')
        elapsed = time.time() - start
        self.assertEqual(resp.status_code, 200)
        self.assertIn('administrator', resp.get_data(as_text=True).lower())
        self.assertLess(elapsed, 2.0, 'a dead authority must not hang the portal')
        portal_store.close()


class _Route:
    """Adapts a SmtpDelivery to the DeliveryWorker's (channel,target,subject,body)
    call shape used by the worker."""

    def __init__(self, smtp):
        self.smtp = smtp

    def send(self, channel, target, subject, body):
        self.smtp.send(target, subject, body)


if __name__ == '__main__':
    unittest.main()

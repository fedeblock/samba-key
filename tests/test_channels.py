import tempfile
import os
import unittest

from samba_key.store import Store
from samba_key.reset_auth import AdminClient
from samba_key.channels import ChannelEnroller
from samba_key.delivery import RecoveryDelivery, DeliveryError


def make_store():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return Store(path)


class _CapturingDelivery:
    """A stand-in for the real transport that records what was sent. In the
    integration tests the real SmtpDelivery/TelegramDelivery are exercised over
    a patched network boundary; here we only need to prove the enroller sends the
    code to the right place and that a portal has no such client."""

    def __init__(self):
        self.sent = []

    def send(self, channel, target, subject, body):
        self.sent.append((channel, target, subject, body))


class _FailingDelivery:
    def send(self, channel, target, subject, body):
        raise DeliveryError('down')


class ChannelEnrollerTests(unittest.TestCase):
    def setUp(self):
        self.store = make_store()
        self.addCleanup(self.store.close)
        self.admin = AdminClient(self._admin_socket())
        self.delivery = _CapturingDelivery()
        self.enroller = ChannelEnroller(self.admin, delivery=self.delivery)

    def _admin_socket(self):
        # A real admin socket over the store, so the channel ops go through the
        # same protocol a portal socket would refuse.
        import socket as _s
        import threading, time
        from samba_key.reset_auth import ResetAuthority, Role
        d = tempfile.mkdtemp()
        path = os.path.join(d, 'admin.sock')
        stop = threading.Event()
        auth = ResetAuthority(self.store, eligible_accounts=frozenset(
            {'alice', 'bob'}), reset_fn=lambda a, p: True,
            principals=lambda peer: Role.ADMIN, peer_credential=lambda c: (0, 0))
        threading.Thread(target=auth.serve, args=(path,),
                         kwargs={'forced_role': Role.ADMIN, 'stop_event': stop,
                                 'recv_timeout': 5}, daemon=True).start()
        for _ in range(300):
            probe = None
            try:
                probe = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                probe.connect(path)
                break
            except OSError:
                time.sleep(0.01)
            finally:
                if probe is not None:
                    probe.close()
        return path

    def test_email_enrollment_sends_code_and_binds(self):
        code = self.enroller.add_email('alice', 'alice@example.org')
        self.assertIsNotNone(code)
        # The code was sent to the addressed e-mail destination.
        self.assertEqual(len(self.delivery.sent), 1)
        self.assertEqual(self.delivery.sent[0][1], 'alice@example.org')
        self.assertTrue(any(code in body for _, _, _, body in self.delivery.sent))
        # Verify binds the channel.
        self.assertTrue(self.enroller.verify('alice', 'email',
                                             'alice@example.org', code))
        self.assertEqual(self.store.resolve_binding('alice').value,
                         'alice@example.org')

    def test_wrong_code_does_not_bind(self):
        code = self.enroller.add_email('alice', 'alice@example.org')
        self.assertFalse(self.enroller.verify('alice', 'email',
                                              'alice@example.org', 'wrong-code'))
        self.assertIsNone(self.store.resolve_binding('alice'))

    def test_one_pending_challenge_per_account(self):
        self.assertIsNotNone(self.enroller.add_email('alice', 'a@x'))
        self.assertIsNone(self.enroller.add_email('alice', 'b@x'))

    def test_telegram_enroll_returns_code_for_relay(self):
        code = self.enroller.enroll_telegram('bob')
        self.assertIsNotNone(code)
        # No e-mail was sent for a Telegram enrollment.
        self.assertEqual(self.delivery.sent, [])

    def test_delivery_failure_still_returns_code(self):
        # A best-effort send failure does not prevent the code being relayed.
        enroller = ChannelEnroller(self.admin, delivery=_FailingDelivery())
        code = enroller.add_email('alice', 'alice@example.org')
        self.assertIsNotNone(code)


class PortalCannotEnrollTests(unittest.TestCase):
    """The crux: a portal socket must refuse every channel operation, so a
    compromised portal cannot inject or alter a destination."""

    def test_portal_client_has_no_channel_methods(self):
        from samba_key.reset_auth import ResetClient
        pc = ResetClient('/nonexistent.sock')
        for method in ('channel_add', 'channel_verify', 'channel_remove',
                       'channel_list', 'issue', 'revoke'):
            self.assertFalse(hasattr(pc, method),
                             'portal client must not expose ' + method)


class NoWebPathEnrollsADestination(unittest.TestCase):
    """No web route and no portal-side object may enroll or alter a channel:
    enrollment is only reachable through the admin socket, so the portal can
    never declare an arbitrary destination."""

    def test_portal_service_has_no_channel_methods(self):
        from samba_key.recovery import RecoveryService
        svc = RecoveryService(object(), object(), 'https://p')
        for method in ('channel_add', 'channel_verify', 'channel_remove',
                       'channel_list', 'bind_channel', 'issue', 'revoke'):
            self.assertFalse(hasattr(svc, method),
                             'portal recovery service must not expose ' + method)

    def test_web_app_exposes_no_enrollment_route(self):
        import os
        from samba_key.app import create_app
        # A misconfiguration fails closed to a 503 app; that still has a url_map.
        app = create_app(recovery_service=None, portal_store=None)
        rules = {str(r.rule) for r in app.url_map.iter_rules()}
        # Only the known, destination-free routes exist; there is no route that
        # accepts a channel destination or an enrollment payload.
        self.assertTrue(rules <= {'/', '/recovery', '/reset', '/reset/details', '/healthz',
                                  '/static/<path:filename>', '/static/<path:filename>'},
                        'unexpected web route: ' + str(rules - {
                            '/', '/recovery', '/reset', '/reset/details', '/healthz',
                            '/static/<path:filename>'}))


if __name__ == '__main__':
    unittest.main()

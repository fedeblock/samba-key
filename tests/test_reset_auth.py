import os
import tempfile
import unittest

from samba_key.store import Store
from samba_key.reset_auth import ResetAuthority, ResetClient, AdminClient, Role


def make_authority(eligible=('alice',), reset_fn=None, store=None, **kw):
    dir_ = tempfile.mkdtemp()
    if store is None:
        store = Store(os.path.join(dir_, 'store.db'))
        _open_stores.append(store)
    calls = []
    if reset_fn is None:
        def reset_fn(account, new_password):
            calls.append((account, new_password))
            return True
    auth = ResetAuthority(
        store, eligible_accounts=frozenset(eligible), reset_fn=reset_fn,
        principals=lambda peer: Role.PORTAL, **kw)
    return auth, calls, store


_open_stores = []


def tearDownModule():
    for s in _open_stores:
        try:
            s.close()
        except Exception:
            pass
    _open_stores.clear()


class ProtocolTests(unittest.TestCase):
    def test_only_valid_bound_token_discloses_masked_recovery_details(self):
        auth, _, store = make_authority()
        store.bind_channel('alice', 'email', 'alice@example.test')
        handle = store.create_request('alice', 900, 'recovery', 'email')
        self.assertTrue(store.approve(handle))
        token = store.issue(handle, 900)
        valid = auth.dispatch(Role.PORTAL, 'VALIDATE', {'token': token})
        self.assertTrue(valid['usable'])
        self.assertEqual(valid['account'], 'alice')
        self.assertEqual(valid['channel'], 'email')
        self.assertEqual(valid['destination'], 'a***e@example.test')
        invalid = auth.dispatch(Role.PORTAL, 'VALIDATE', {'token': 'wrong'})
        self.assertFalse(invalid['usable'])
        self.assertNotIn('account', invalid)
        store.revoke_channel('alice', 'email')
        revoked = auth.dispatch(Role.PORTAL, 'VALIDATE', {'token': token})
        self.assertFalse(revoked['usable'])
        self.assertNotIn('account', revoked)

    def test_telegram_link_shows_masked_associated_email(self):
        auth, _, store = make_authority()
        store.bind_channel('alice', 'email', 'alice@example.test')
        store.bind_channel('alice', 'telegram', '123456789')
        handle = store.create_request('alice', 900, 'recovery', 'telegram')
        self.assertTrue(store.approve(handle))
        result = auth.dispatch(Role.PORTAL, 'VALIDATE', {'token': store.issue(handle, 900)})
        self.assertEqual(result['channel'], 'telegram')
        self.assertEqual(result['associated_email'], 'a***e@example.test')

    def test_mint_returns_handle_not_secret_token(self):
        auth, calls, store = make_authority()
        # MINT carries only the account; the authority resolves the destination
        # from its own bindings. The response is a handle, never a token.
        resp = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice',
                                                   'kind': 'recovery'})
        self.assertTrue(resp['ok'])
        self.assertNotIn('token', resp)
        self.assertTrue(resp['handle'])

    def test_mint_rejects_non_eligible_and_root(self):
        auth, calls, store = make_authority(eligible=('alice',))
        self.assertFalse(auth.dispatch(Role.PORTAL,
                                       'MINT', {'account': 'bob'})['ok'])
        self.assertFalse(auth.dispatch(Role.PORTAL,
                                       'MINT', {'account': 'root'})['ok'])
        self.assertEqual(calls, [])

    def test_portal_cannot_issue_or_revoke_or_approve(self):
        # The crux of the threat model: a portal principal can mint but can
        # NEVER issue a token, revoke, or approve. Delivery is authority-side.
        auth, calls, store = make_authority()
        handle = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['handle']
        for op in ('ISSUE', 'REVOKE', 'APPROVE', 'DENY', 'LIST',
                   'CHANNEL_ADD', 'CHANNEL_VERIFY', 'CHANNEL_REMOVE', 'CHANNEL_LIST'):
            self.assertFalse(auth.dispatch(Role.PORTAL, op,
                                           {'handle': handle, 'account': 'alice',
                                            'kind': 'email', 'value': 'x'}).get('ok', True),
                             'portal must not be able to ' + op)
        self.assertEqual(calls, [])

    def test_no_reset_without_independent_approval(self):
        # A portal principal can mint but cannot advance a request to approved,
        # so it can never obtain a token to consume.
        auth, calls, store = make_authority()
        handle = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['handle']
        self.assertFalse(auth.dispatch(Role.PORTAL,
                                       'VALIDATE',
                                       {'token': 'anything', 'kind': 'recovery'})['usable'])
        # No approval, no issue, hence nothing to consume.
        self.assertIsNone(store.issue(handle, 900))
        self.assertEqual(calls, [])

    def test_issue_single_use_and_only_when_approved(self):
        auth, calls, store = make_authority()
        handle = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['handle']
        # Unapproved: no token.
        self.assertIsNone(store.issue(handle, 900))
        auth.dispatch(Role.ADMIN, 'APPROVE', {'handle': handle})
        first = store.issue(handle, 900)
        second = store.issue(handle, 900)
        self.assertTrue(first)
        self.assertIsNone(second)  # issued exactly once


class ConsumeSafetyTests(unittest.TestCase):
    def _approved_token(self, auth, store):
        handle = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['handle']
        auth.dispatch(Role.ADMIN, 'APPROVE', {'handle': handle})
        return store.issue(handle, 900)

    def test_consume_enforces_kind(self):
        auth, calls, store = make_authority()
        token = self._approved_token(auth, store)
        # A channel-verification kind must not be accepted as a recovery token.
        self.assertFalse(auth.dispatch(Role.PORTAL, 'CONSUME',
                                       {'token': token,
                                        'new_password': 'a-new-password-1',
                                        'kind': 'email'})['ok'])
        self.assertEqual(calls, [])

    def test_reset_failure_marks_request_dead(self):
        calls = []

        def failing(account, new_password):
            calls.append((account, new_password))
            return False

        auth, _, store = make_authority(reset_fn=failing)
        token = self._approved_token(auth, store)
        self.assertFalse(auth.dispatch(Role.PORTAL, 'CONSUME',
                                       {'token': token,
                                        'new_password': 'a-new-password-1',
                                        'kind': 'recovery'})['ok'])
        self.assertEqual(len(calls), 1)  # no blind retry
        self.assertFalse(auth.dispatch(Role.PORTAL, 'CONSUME',
                                       {'token': token,
                                        'new_password': 'a-new-password-2',
                                        'kind': 'recovery'})['ok'])

    def test_consume_rejects_bad_policy_password(self):
        auth, calls, store = make_authority()
        token = self._approved_token(auth, store)
        for bad in ('short', 'new\npassword', 'new\0password', ''):
            self.assertFalse(auth.dispatch(Role.PORTAL, 'CONSUME',
                                           {'token': bad,
                                            'new_password': bad,
                                            'kind': 'recovery'})['ok'])
        self.assertEqual(calls, [])

    def test_successful_consume_resets_once(self):
        auth, calls, store = make_authority()
        token = self._approved_token(auth, store)
        self.assertTrue(auth.dispatch(Role.PORTAL, 'CONSUME',
                                      {'token': token,
                                       'new_password': 'a-new-password-1',
                                       'kind': 'recovery'})['ok'])
        self.assertEqual(calls, [('alice', 'a-new-password-1')])


class ChannelOpsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)
        self.calls = []
        self.auth = ResetAuthority(
            self.store, eligible_accounts=frozenset({'alice'}),
            reset_fn=lambda a, p: self.calls.append((a, p)) or True,
            principals=lambda peer: Role.ADMIN)

    def test_channel_ops_are_admin_only(self):
        # A portal principal cannot enroll or list channels at all.
        for op in ('CHANNEL_ADD', 'CHANNEL_VERIFY', 'CHANNEL_REMOVE', 'CHANNEL_LIST'):
            self.assertFalse(self.auth.dispatch(Role.PORTAL, op,
                {'account': 'alice', 'kind': 'email',
                 'value': 'alice@example.com', 'code': 'x'}).get('ok', True),
                             op + ' must be admin-only')
        self.assertEqual(self.calls, [])

    def test_admin_enrolls_and_verifies_email(self):
        code = self.auth.dispatch(Role.ADMIN, 'CHANNEL_ADD',
                                  {'account': 'alice', 'kind': 'email',
                                   'value': 'alice@example.com'})
        self.assertTrue(code['ok'])
        raw = code['code']
        # Wrong address or wrong code is refused.
        self.assertFalse(self.auth.dispatch(Role.ADMIN, 'CHANNEL_VERIFY',
            {'account': 'alice', 'kind': 'email',
             'value': 'evil@example.com', 'code': raw})['ok'])
        self.assertTrue(self.auth.dispatch(Role.ADMIN, 'CHANNEL_VERIFY',
            {'account': 'alice', 'kind': 'email',
             'value': 'alice@example.com', 'code': raw})['ok'])
        self.assertEqual(self.store.resolve_binding('alice').value,
                         'alice@example.com')

    def test_channel_list_is_masked(self):
        code = self.auth.dispatch(Role.ADMIN, 'CHANNEL_ADD',
                                  {'account': 'alice', 'kind': 'email',
                                   'value': 'alice@example.com'})['code']
        self.auth.dispatch(Role.ADMIN, 'CHANNEL_VERIFY',
                           {'account': 'alice', 'kind': 'email',
                            'value': 'alice@example.com', 'code': code})
        listing = self.auth.dispatch(Role.ADMIN, 'CHANNEL_LIST',
                                     {'account': 'alice'})['channels']
        self.assertEqual(len(listing), 1)
        self.assertIn('@example.com', listing[0]['value'])
        self.assertNotIn('alice@', listing[0]['value'])  # local part masked


class AllowlistTests(unittest.TestCase):
    def test_admin_and_none_cannot_mint_or_consume(self):
        auth, calls, store = make_authority()
        for role in (Role.ADMIN, Role.NONE):
            self.assertFalse(auth.dispatch(role, 'MINT', {'account': 'alice'}).get('ok', True))
            self.assertFalse(auth.dispatch(role, 'CONSUME',
                                           {'token': 'x',
                                            'new_password': 'a-new-password-1'}).get('ok', True))
        self.assertEqual(calls, [])

    def test_unknown_opcode_and_malformed_payload_rejected(self):
        auth, calls, store = make_authority()
        self.assertFalse(auth.dispatch(Role.PORTAL, 'DROP TABLE requests', {})['ok'])
        # MINT with an extra key is rejected; a bare account is now valid.
        self.assertFalse(auth.dispatch(Role.PORTAL,
                                       'MINT', {'account': 'alice', 'evil': 1})['ok'])
        self.assertTrue(auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['ok'])
        self.assertEqual(calls, [])

    def test_list_shows_pending_without_token(self):
        auth, calls, store = make_authority()
        handle = auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})['handle']
        listing = auth.dispatch(Role.ADMIN, 'LIST', {})['requests']
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]['account'], 'alice')
        self.assertEqual(listing[0]['handle'], handle)
        self.assertNotIn('token', listing[0])

    def test_list_shows_masked_destination_never_full(self):
        # The admin must be able to see *where* a link will go, but only masked.
        auth, calls, store = make_authority()
        code = store.create_channel_challenge('alice', 'email',
                                             'alice@example.com', ttl=900)
        self.assertTrue(store.verify_channel_challenge(
            'alice', 'email', 'alice@example.com', code))
        auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})
        listing = auth.dispatch(Role.ADMIN, 'LIST', {})['requests']
        dest = listing[0].get('destination')
        self.assertIsNotNone(dest)
        # The domain is visible (so the admin can recognise it) but the local
        # part is masked; the full address must never appear.
        self.assertIn('example.com', dest)
        self.assertNotIn('alice@example.com', dest)
        self.assertNotIn('alice', dest.split('@')[0])

    def test_list_shows_no_destination_when_unbound(self):
        auth, calls, store = make_authority()
        auth.dispatch(Role.PORTAL, 'MINT', {'account': 'alice'})
        listing = auth.dispatch(Role.ADMIN, 'LIST', {})['requests']
        self.assertIsNone(listing[0].get('destination'))


class PrincipalMappingTests(unittest.TestCase):
    def test_peer_maps_to_roles(self):
        from samba_key import reset_auth
        orig = reset_auth.peer_groups
        try:
            reset_auth.peer_groups = lambda uid, gid: {gid}
            self.assertEqual(reset_auth.principal_from_peer(
                (1000, 1000), portal_uid=1000, admin_gids={5000}), Role.PORTAL)
            self.assertEqual(reset_auth.principal_from_peer(
                (0, 5000), portal_uid=1000, admin_gids={5000}), Role.ADMIN)
            self.assertEqual(reset_auth.principal_from_peer(
                (1001, 1001), portal_uid=1000, admin_gids={5000}), Role.NONE)
        finally:
            reset_auth.peer_groups = orig


class SeparationTests(unittest.TestCase):
    def test_root_portal_refused(self):
        from samba_key.reset_auth import validate_separation
        self.assertTrue(validate_separation(0, {1000}, {5000}),
                        'a root portal uid must be refused')

    def test_portal_in_admin_group_refused(self):
        from samba_key.reset_auth import validate_separation
        self.assertTrue(validate_separation(1000, {1000, 5000}, {5000}),
                        'a portal group that is an admin group must be refused')

    def test_disjoint_identities_ok(self):
        from samba_key.reset_auth import validate_separation
        self.assertEqual(validate_separation(1000, {1000}, {5000}), [])

    def test_supplementary_group_makes_admin(self):
        from samba_key import reset_auth
        orig = reset_auth.peer_groups
        try:
            reset_auth.peer_groups = lambda uid, gid: {1000, 5000}  # sup grp
            self.assertEqual(reset_auth.principal_from_peer(
                (1000, 1000), portal_uid=1000, admin_gids={5000}), Role.ADMIN)
        finally:
            reset_auth.peer_groups = orig


class BindingFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def test_binding_change_invalidates_pending_request(self):
        s = self.store
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 1800)
        self.assertTrue(s.approve(h))
        fp = s.request_binding_fingerprint(h)
        self.assertTrue(fp)
        # Changing the destination invalidates the in-flight request.
        s.bind_channel('alice', 'email', 'evil@attacker.net')
        self.assertFalse(s.approved_requests())
        self.assertFalse(s.pending_requests())

    def test_unapproved_binding_change_denies_pending(self):
        s = self.store
        s.bind_channel('alice', 'email', 'alice@example.com')
        h = s.create_request('alice', 1800)
        s.bind_channel('alice', 'email', 'other@example.com')
        # The request is denied, so it can no longer be approved.
        self.assertFalse(s.approve(h))
        self.assertFalse(s.approved_requests())


class RevokeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, 'store.db'))
        self.addCleanup(self.store.close)

    def test_revoke_makes_token_unconsumable(self):
        s = self.store
        h = s.create_request('alice', 1800)
        s.approve(h)
        token = s.issue(h, 900)
        self.assertTrue(s.peek_token(token, 'recovery'))
        self.assertTrue(s.revoke(h))
        # After revocation the token can no longer be consumed.
        self.assertIsNone(s.peek_token(token, 'recovery'))
        self.assertIsNone(s.consume_token(token, 'recovery'))

    def test_revoke_only_affects_issued(self):
        s = self.store
        h = s.create_request('alice', 1800)
        s.approve(h)
        self.assertFalse(s.revoke(h))  # nothing issued yet
        s.issue(h, 900)
        self.assertTrue(s.revoke(h))


class ExpiredPurgeTests(unittest.TestCase):
    def test_purge_removes_old_terminal_rows(self):
        t = [1000.0]
        s = Store(os.path.join(tempfile.mkdtemp(), 's2.db'), now=lambda: t[0])
        h = s.create_request('alice', 100)  # expires at 1100
        s.approve(h)
        s.issue(h, 100)
        t[0] = 1000 + 90000  # well past expiry
        s.purge_expired()
        remaining = s._conn.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
        s.close()
        self.assertEqual(remaining, 0, 'expired/terminal requests are purged')


class GlobalCapTests(unittest.TestCase):
    def test_expired_requests_free_the_global_cap(self):
        t = [1000.0]
        s = Store(os.path.join(tempfile.mkdtemp(), 'g.db'), now=lambda: t[0],
                  max_pending_per_account=5, max_pending_global=2)
        self.assertIsNotNone(s.create_request('a', 100))
        self.assertIsNotNone(s.create_request('b', 100))
        self.assertIsNone(s.create_request('c', 100))  # global cap
        t[0] = 2000.0  # both expire at 1100
        self.assertIsNotNone(s.create_request('c', 100))
        s.close()

    def test_per_account_cap(self):
        s = Store(os.path.join(tempfile.mkdtemp(), 'p.db'),
                  max_pending_per_account=1)
        self.assertIsNotNone(s.create_request('alice', 100))
        self.assertIsNone(s.create_request('alice', 100))  # per-account cap
        s.close()


if __name__ == '__main__':
    unittest.main()

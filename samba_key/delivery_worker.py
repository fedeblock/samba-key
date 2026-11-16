"""Authority-side delivery worker for forgotten-password recovery.

This is the piece that closes the "divert an approved link" gap: the *authority*,
not the portal, resolves the destination from its own channel store, releases the
token (``store.issue``), builds the link and sends it. The portal never receives
the token, so a compromised portal cannot read or redirect an approved link.

Guarantees the worker enforces:
* the destination is resolved from the authority's own bindings, not from the
  request or the portal;
* delivery refuses -- and the request is denied -- if the binding changed since
  approval (the fingerprint pinned at approval no longer matches), so a
  destination cannot be swapped in after approval;
* a link is issued exactly once per approved request (``issue`` is single-use and
  sets ``issued=1`` so the request leaves the approved set);
* if the send fails after the token is released, the token is revoked (moved to
  ``denied``) so the lost link cannot be used;
* no token, handle, destination, address or new password is ever logged.
"""
import logging

LOG = logging.getLogger(__name__)

SUBJECT = 'Password recovery link'


class DeliveryWorker:
    def __init__(self, store, delivery, base_url, link_ttl=900, limit=200):
        self.store = store
        self.delivery = delivery
        self.base_url = base_url.rstrip('/')
        self.link_ttl = link_ttl
        self.limit = limit

    def deliver_pending(self):
        """Resolve, issue and send each approved, not-yet-issued request.

        Returns the number of links sent. A request with no binding, or whose
        binding drifted since approval, is denied (it cannot be delivered safely).
        A send failure revokes the token. Generic logging only.
        """
        self.store.purge_expired()
        sent = 0
        for request in self.store.approved_requests(self.limit):
            binding = self.store.resolve_binding(request.account, request.channel)
            if binding is None:
                # No destination: deny rather than leave it outstanding.
                self.store.deny(request.handle)
                LOG.warning('recovery request denied: no delivery destination '
                            'for an approved account')
                continue
            # The destination must be exactly the one pinned at approval. If the
            # binding has since changed, the request is denied, not delivered.
            current = self.store.binding_fingerprint(request.account, request.channel)
            pinned = self.store.request_binding_fingerprint(request.handle)
            if not pinned or current != pinned:
                self.store.deny(request.handle)
                LOG.warning('recovery request denied: destination changed since '
                            'approval')
                continue
            token = self.store.issue(request.handle, self.link_ttl)
            if token is None:
                continue  # already issued or moved; nothing to do
            link = self.base_url + '/reset#t=' + token
            try:
                self.delivery.send(binding.kind, binding.value, SUBJECT,
                                   'Recovery link (use once, expires soon):\n'
                                   + link)
            except Exception:
                # The token was released; revoke it so the lost link cannot be
                # used. Generic warning only -- no token, handle or target.
                if not self.store.revoke(request.handle):
                    LOG.warning('delivery failed and revoke did not confirm; the '
                                'issued link may remain usable until it expires -- '
                                'a residual risk for this request')
                continue
            sent += 1
        return sent

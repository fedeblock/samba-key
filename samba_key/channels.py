"""Authority-side, admin-driven channel enrollment for recovery.

A recovery channel (an e-mail address or a Telegram private chat) is enrolled by
an *operator* through the authority's admin socket, not by the user in the web
portal. This is the heart of the "a compromised portal cannot bind or alter a
destination" guarantee: the portal process has no admin client (the admin socket
is not mounted into it), so it cannot create or change a binding at all.

Two enrollment paths:

* **E-mail.** The operator runs ``channel add <account> email <addr>``; the
  authority creates a one-time challenge and, if an e-mail transport is
  configured, sends the code to that address (proving it is live). The user
  relays the code out of band and the operator runs ``channel verify``. The
  address the code was challenged for must match the one verified.
* **Telegram.** The operator runs ``channel enroll <account> telegram`` and gets
  a one-time code, which they give to the user. The user sends ``/start
  <code>`` in their *private* chat with the bot; the authority-side poller
  (:class:`samba_key.telegram.TelegramBinder`) binds the chat id it learns from
  that verified conversation.

A binding change invalidates the account's in-flight recovery requests, so a
destination cannot be swapped in after a request is pending or approved.
"""
import logging

LOG = logging.getLogger(__name__)

SUBJECT = 'Recovery channel verification'


class ChannelEnroller:
    """Enroll and remove recovery channels through the admin socket.

    ``admin_client`` is an :class:`samba_key.reset_auth.AdminClient` over the
    admin socket. ``delivery`` is an optional :class:`RecoveryDelivery` used to
    send an e-mail verification code to the address (best effort); the code is
    also returned to the operator, who can relay it by any channel.
    """

    def __init__(self, admin_client, delivery=None, link_ttl=900,
                 max_challenge_clients=5000):
        self.admin = admin_client
        self.delivery = delivery
        self.link_ttl = link_ttl
        self.max_challenge_clients = max_challenge_clients

    def add_email(self, account, address):
        """Create an e-mail challenge and, if a transport is configured, send the
        code to the address. Returns the code (for the operator to relay) or
        None on a cap / ineligible account."""
        code = self.admin.channel_add(account, 'email', address)
        if code is None:
            return None
        if self.delivery is not None:
            try:
                self.delivery.send('email', address, SUBJECT,
                                   'Verification code (use once, expires soon):\n'
                                   + code)
            except Exception:
                # Best effort: the code was still returned to the operator, who
                # can relay it another way. No secret reaches the log.
                LOG.warning('e-mail verification code could not be sent; the '
                            'operator must relay it out of band')
        return code

    def enroll_telegram(self, account):
        """Create a Telegram challenge and return the one-time code for the
        operator to give the user, who will send ``/start <code>``."""
        return self.admin.channel_add(account, 'telegram', '')

    def verify(self, account, kind, value, code):
        return self.admin.channel_verify(account, kind, value, code)

    def remove(self, account, kind):
        return self.admin.channel_remove(account, kind)

    def list(self, account=None):
        return self.admin.channel_list(account)


def main():
    import sys
    print('Channel enrollment is driven by the admin CLI and the Telegram '
          'poller, not a standalone CLI.', file=sys.stderr)
    return 1

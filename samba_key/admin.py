"""Out-of-band recovery approval and channel-enrollment CLI
(``samba-key-admin``).

This is the human authority. It is a local program run by an operator on the
host (or via a privileged, access-controlled path). It connects to the
authority's **admin socket** -- which the portal container does not mount -- so
only an operator in the admin group can approve a request or enroll a channel.
The portal has no code path that can call any of these.

Commands:
    samba-key-admin list
    samba-key-admin approve <handle>
    samba-key-admin deny <handle>
    samba-key-admin channel add <account> <kind> <value>      # create + send/relay a code
    samba-key-admin channel verify <account> <kind> <value> <code>
    samba-key-admin channel remove <account> <kind>
    samba-key-admin channel list [account]

The admin identity is the operating system: the admin socket enforces that the
caller is in the configured admin group. No password is stored for this role.

Approval stops *unapproved* resets. Because the destination is pinned at approval
and a binding change invalidates in-flight requests, a compromised portal cannot
inject or alter a destination either. The operator must still confirm the
requester's identity out of band before approving -- that is a human step, not
something the system can verify.
"""
import os
import sys


def run(argv, client, out=None):
    out = out or sys.stdout
    if not argv:
        print('usage: samba-key-admin {list|approve <handle>|deny <handle>|'
              'channel ...}', file=out)
        return 2
    cmd = argv[0]
    if cmd == 'list':
        items = client.list_pending()
        if not items:
            print('(no pending requests)', file=out)
            return 0
        for r in items:
            print('handle=%-24s account=%-16s kind=%-8s dest=%-22s expires=%s'
                  % (r['handle'], r['account'], r.get('kind', ''),
                     r.get('destination') or '(none)', r.get('expires_at', '')),
                  file=out)
        return 0
    if cmd in ('approve', 'deny'):
        if len(argv) != 2:
            print('usage: samba-key-admin %s <handle>' % cmd, file=out)
            return 2
        handle = argv[1]
        if cmd == 'approve':
            ok = client.approve(handle)
            print('approved' if ok else 'not found or already handled', file=out)
        else:
            ok = client.deny(handle)
            print('denied' if ok else 'not found or already handled', file=out)
        return 0 if ok else 1
    if cmd == 'channel':
        return _run_channel(argv[1:], client, out)
    print('unknown command: %s' % cmd, file=out)
    return 2


def _run_channel(argv, client, out):
    if not argv:
        print('usage: samba-key-admin channel {add|verify|remove|list}', file=out)
        return 2
    sub = argv[0]
    if sub == 'add':
        # add <account> <kind> [<value>]. E-mail needs an address; Telegram's
        # chat id is learned on /start, so its value may be omitted (empty).
        if (len(argv) not in (3, 4)) or argv[2] not in ('email', 'telegram'):
            print('usage: samba-key-admin channel add <account> <email|telegram> '
                  '[<value>]', file=out)
            return 2
        account, kind = argv[1], argv[2]
        value = argv[3] if len(argv) == 4 else ''
        if kind == 'email' and not value:
            print('usage: samba-key-admin channel add <account> email '
                  '<address>', file=out)
            return 2
        code = client.channel_add(account, kind, value)
        if code is None:
            print('could not start the challenge (account not eligible, a pending '
                  'challenge exists, or a limit was hit)', file=out)
            return 1
        # For e-mail the operator attests control of the address and relays the
        # code out of band; for Telegram the operator relays the code to the
        # user, who sends /start <code> in their private chat.
        print('challenge started for %s %s. One-time code: %s' %
              (account, kind, code), file=out)
        return 0
    if sub == 'verify':
        # verify <account> <kind> <value> <code>
        if len(argv) != 5 or argv[2] not in ('email', 'telegram'):
            print('usage: samba-key-admin channel verify <account> <email|telegram> '
                  '<value> <code>', file=out)
            return 2
        ok = client.channel_verify(argv[1], argv[2], argv[3], argv[4])
        print('channel bound' if ok else 'verification failed (wrong code, '
              'expired, or account not eligible)', file=out)
        return 0 if ok else 1
    if sub == 'remove':
        if len(argv) != 3 or argv[2] not in ('email', 'telegram'):
            print('usage: samba-key-admin channel remove <account> <email|telegram>',
                  file=out)
            return 2
        ok = client.channel_remove(argv[1], argv[2])
        print('channel removed' if ok else 'not found or account not eligible',
              file=out)
        return 0 if ok else 1
    if sub == 'list':
        account = argv[1] if len(argv) >= 2 else None
        for c in client.channel_list(account):
            print('%-16s %-8s %s' % (c['account'], c['kind'], c['value']), file=out)
        return 0
    print('unknown channel command: %s' % sub, file=out)
    return 2


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    socket_path = os.environ.get('RECOVERY_ADMIN_SOCKET')
    if not socket_path:
        # The authority creates the admin socket at <AUTHORITY_DIR>/admin.sock.
        # Derive it from AUTHORITY_DIR so the out-of-band CLI needs no separate
        # env var to match the authority's layout, but refuse to run silently if
        # neither is set (a missing socket must not look like 'no requests').
        authority_dir = os.environ.get('AUTHORITY_DIR')
        if not authority_dir:
            print('set RECOVERY_ADMIN_SOCKET or AUTHORITY_DIR', file=sys.stderr)
            return 2
        socket_path = os.path.join(authority_dir, 'admin.sock')
    from samba_key.reset_auth import AdminClient
    client = AdminClient(socket_path)
    return run(argv, client)


if __name__ == '__main__':
    raise SystemExit(main())

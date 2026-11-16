"""Private, operator-managed contact directory; not an authentication source.

The directory only supplies contact details. Adding an address here does not
verify or activate a recovery channel, and a phone number is never a Telegram
chat ID. All enrollment still goes through the authority's admin socket.
"""
import argparse
import getpass
import os
import re
import stat
import sys
import tomllib

from .reset import USERNAME

MAX_FILE = 1024 * 1024


class ContactError(Exception):
    pass


def load_contacts(path):
    """Read a private TOML file without following a symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise ContactError('contact file must be private and owned by the current user')
            contents = source.read(MAX_FILE + 1)
        if len(contents) > MAX_FILE:
            raise ContactError('contact file is too large')
        document = tomllib.loads(contents.decode('utf-8'))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ContactError('cannot read contact file') from exc
    users = document.get('users', [])
    if not isinstance(users, list):
        raise ContactError('users must be an array of tables')
    contacts = {}
    for item in users:
        if not isinstance(item, dict) or set(item) - {'username', 'name', 'email', 'phone'}:
            raise ContactError('invalid contact fields')
        username = item.get('username')
        if not isinstance(username, str) or not USERNAME.fullmatch(username) or username.lower() == 'root':
            raise ContactError('invalid Samba username')
        if username in contacts:
            raise ContactError('duplicate Samba username')
        entry = {'username': username}
        for field in ('name', 'email', 'phone'):
            value = item.get(field, '')
            if (not isinstance(value, str) or len(value) > 254
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ContactError('invalid contact value')
            entry[field] = value.strip()
        if entry['email'] and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', entry['email']):
            raise ContactError('invalid email address')
        if entry['phone'] and not re.fullmatch(r'[+0-9 ()-]{5,40}', entry['phone']):
            raise ContactError('invalid phone number')
        contacts[username] = entry
    return contacts


def run(argv, path, admin=None, out=None):
    out = out or sys.stdout
    try:
        contacts = load_contacts(path)
    except ContactError as exc:
        print(str(exc), file=out)
        return 2
    if argv == ['list']:
        for c in contacts.values():
            print(f"{c['username']} | {c['name']} | {c['email']} | {c['phone']}", file=out)
        return 0
    if len(argv) == 2 and argv[0] == 'show':
        c = contacts.get(argv[1])
        if c is None:
            print('contact not found', file=out)
            return 1
        print(f"{c['username']} | {c['name']} | {c['email']} | {c['phone']}", file=out)
        return 0
    if len(argv) == 3 and argv[0] == 'enroll' and argv[2] in ('email', 'telegram'):
        contact = contacts.get(argv[1])
        if contact is None or admin is None:
            print('contact or admin connection unavailable', file=out)
            return 1
        kind = argv[2]
        target = contact['email'] if kind == 'email' else ''
        if kind == 'email' and not target:
            print('contact has no email address', file=out)
            return 1
        code = admin.channel_add(contact['username'], kind, target)
        if not code:
            print('could not start enrollment', file=out)
            return 1
        print('One-time enrollment code:', code, file=out)
        print('Confirm the recipient independently; this contact is not yet a recovery channel.', file=out)
        return 0
    if len(argv) == 3 and argv[0] == 'verify' and argv[2] == 'email':
        contact = contacts.get(argv[1])
        if contact is None or admin is None or not contact['email']:
            print('contact or admin connection unavailable', file=out)
            return 1
        code = getpass.getpass('Verification code: ').strip()
        verified = admin.channel_verify(contact['username'], 'email', contact['email'], code)
        print('channel verified' if verified else 'verification failed', file=out)
        return 0 if verified else 1
    print('usage: contacts {list|show USER|enroll USER email|telegram|verify USER email}', file=out)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description='Manage private Samba user contacts')
    parser.add_argument('--file', default='/etc/samba-key/contacts.toml')
    parser.add_argument('action', choices=['list', 'show', 'enroll', 'verify'])
    parser.add_argument('username', nargs='?')
    parser.add_argument('channel', nargs='?', choices=['email', 'telegram'])
    args = parser.parse_args(argv)
    cmd = [value for value in (args.action, args.username, args.channel) if value]
    admin = None
    if args.action in ('enroll', 'verify'):
        from .reset_auth import AdminClient
        socket = os.environ.get('RECOVERY_ADMIN_SOCKET') or os.path.join(
            os.environ.get('AUTHORITY_DIR', '/run/samba-key'), 'admin.sock')
        admin = AdminClient(socket)
    return run(cmd, args.file, admin)


if __name__ == '__main__':
    raise SystemExit(main())

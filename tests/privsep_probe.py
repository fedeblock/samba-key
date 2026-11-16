"""Privilege-separation probe: drops to a target (uid, gid) and attempts one
operation, reporting success via the exit code. Run as root inside a Linux
container; the drop is done with setgroups/setgid/setuid.

Usage:
    probe.py <op> <path> <uid> <gid>
where op is one of:
    connect        connect to the socket at <path>
    mint           MINT over the portal socket at <path>
    approve        APPROVE over the admin socket at <path>
    list           LIST over the admin socket at <path>
    read_db        open the file at <path> for reading
"""
import os
import socket
import sys
import json
import struct


def drop(uid, gid):
    os.setgroups([gid])
    os.setgid(gid)
    os.setuid(uid)


def drop_supplementary(uid, name, primary_gid):
    """Drop to uid keeping its real *supplementary* groups (via initgroups) and
    its own primary gid. Used by the breach control: after the portal is added
    to the admin group as a supplementary group, its primary gid is unchanged but
    it can now reach the admin socket through the supplementary membership."""
    os.initgroups(name, primary_gid)
    os.setgid(primary_gid)
    os.setuid(uid)


def connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    s.close()
    return 0


def _call(path, op, payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    body = json.dumps({'op': op, 'payload': payload}).encode()
    s.sendall(struct.pack('>I', len(body)) + body)
    header = s.recv(4)
    (length,) = struct.unpack('>I', header)
    out = s.recv(length)
    s.close()
    return json.loads(out.decode())


def web_probe(op, path):
    """Exercise real Flask recovery routes as the dropped portal identity."""
    import re
    os.environ.update({
        'RECOVERY_MODE': 'approval',
        'RECOVERY_SOCKET': path,
        'PORTAL_STORE': ':memory:',
        'BASE_URL': 'https://portal.example',
        'SAMBA_KEY_SECRET': 'disposable-integration-session-key',
    })
    from samba_key.app import app
    client = app.test_client()
    route = '/recovery?lang=en' if op == 'web_request' else '/reset?lang=en'
    page = client.get(route, base_url='https://portal.example')
    match = re.search(r'name="csrf" value="([^"]+)"', page.get_data(as_text=True))
    if page.status_code != 200 or not match:
        return 2
    form = {'csrf': match.group(1)}
    if op == 'web_request':
        form['username'] = os.environ.get('MINT_ACCOUNT', 'alice')
        form['channel'] = os.environ.get('WEB_CHANNEL', 'auto')
    else:
        form['token'] = sys.argv[5]
        form['new_password'] = os.environ.get('CHAIN_NEW', 'new-reset-password')
    response = client.post(route, data=form, base_url='https://portal.example')
    body = response.get_data(as_text=True)
    if response.status_code != 200:
        return 2
    if op == 'web_request':
        return 0 if 'If a recovery channel' in body else 2
    return 0 if 'has been changed' in body else 1


def main():
    op, path, uid, gid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    try:
        if op != 'breach':
            drop(uid, gid)
    except OSError as e:
        print('drop failed: ' + str(e), file=sys.stderr)
        return 99
    try:
        if op == 'breach':
            # argv[5] is the portal username. Keep the portal's own primary gid
            # and load its real *supplementary* groups (which, after usermod -aG,
            # include the admin group). A bare connect() would only prove the
            # socket-file permission; instead we send a LIST and require the
            # authority to *serve* an admin op, which only happens if the peer
            # check resolved this peer to the admin role (supplementary group).
            username = sys.argv[5]
            drop_supplementary(uid, username, gid)
            r = _call(path, 'LIST', {})
            return 0 if 'requests' in r else 1
        if op == 'connect':
            connect(path)
            return 0
        if op == 'read_db':
            with open(path, 'rb') as fh:
                fh.read(1)
            return 0
        if op == 'write_db':
            with open(path, 'ab') as fh:
                fh.write(b'x')
            return 0
        if op == 'write_secret':
            with open(os.path.join(path, 'probe.txt'), 'wb') as fh:
                fh.write(b'x')
            return 0
        if op == 'mint2':
            # MINT for a unique account (so the per-account cap is not hit) and
            # print the real handle for the non-vacuous approve test.
            r = _call(path, 'MINT',
                      {'account': 'approvaltest', 'kind': 'recovery'})
            handle = r.get('handle')
            print(handle if handle else 'NONE')
            return 0 if handle else 1
        if op == 'approve_handle':
            # APPROVE the real handle (argv[5]) on THIS socket; return 0 only if
            # the call was refused (ok=False) -- the portal socket must refuse.
            handle = sys.argv[5]
            r = _call(path, 'APPROVE', {'handle': handle})
            print('refused' if not r.get('ok') else 'ALLOWED')
            return 0 if not r.get('ok') else 1
        if op == 'list_has':
            # LIST and report whether the handle (argv[5]) is still pending; a
            # portal-approved request would have left the pending list.
            handle = sys.argv[5]
            r = _call(path, 'LIST', {})
            present = any(x.get('handle') == handle
                          for x in r.get('requests', []))
            print('pending' if present else 'gone')
            return 0 if present else 1
        if op == 'mint':
            r = _call(path, 'MINT', {'account': 'alice', 'kind': 'recovery'})
            return 0 if r.get('ok') else 1
        if op == 'mint_handle':
            r = _call(path, 'MINT',
                      {'account': os.environ.get('MINT_ACCOUNT', 'alice'),
                       'kind': 'recovery'})
            handle = r.get('handle')
            print(handle if handle else 'NONE')
            return 0 if handle else 1
        if op == 'list_handle':
            r = _call(path, 'LIST', {})
            account = os.environ.get('MINT_ACCOUNT', 'alice')
            handles = [entry['handle'] for entry in r.get('requests', [])
                       if entry.get('account') == account]
            print(handles[0] if handles else 'NONE')
            return 0 if handles else 1
        if op in ('web_request', 'web_consume'):
            return web_probe(op, path)
        if op == 'consume':
            # CONSUME a recovery token (argv[5]) with a new password (env
            # CHAIN_NEW) over the portal socket; the authority's CONSUME runs the
            # real reset_fn. Report OK/FAIL and the exit code accordingly.
            token = sys.argv[5]
            new = os.environ.get('CHAIN_NEW', 'new-reset-password')
            r = _call(path, 'CONSUME',
                      {'token': token, 'new_password': new, 'kind': 'recovery'})
            print('OK' if r.get('ok') else 'FAIL')
            return 0 if r.get('ok') else 1
        if op == 'approve_real':
            # The handle is passed as the 5th argv; approve it on the admin socket.
            handle = sys.argv[5]
            r = _call(path, 'APPROVE', {'handle': handle})
            return 0 if r.get('ok') else 1
        if op == 'approve':
            r = _call(path, 'APPROVE', {'handle': 'no-such-handle'})
            # APPROVE is only *reachable* if the connection is allowed; the
            # handle is fake so it will not succeed, but ok=False with a
            # reachable call means the portal could not have been blocked.
            return 0 if r.get('ok') else 1
        if op == 'list':
            r = _call(path, 'LIST', {})
            return 0 if 'requests' in r else 1
        if op == 'channel_add':
            # Enroll a channel through THIS socket; return 0 only if allowed.
            r = _call(path, 'CHANNEL_ADD',
                      {'account': 'alice', 'kind': 'email',
                       'value': 'alice@example.com'})
            return 0 if r.get('ok') else 1
        print('unknown op', file=sys.stderr)
        return 99
    except PermissionError:
        return 7  # EACCES / denied  # EACCES / denied
    except OSError as e:
        print('oserror: ' + str(e), file=sys.stderr)
        return 8
    except Exception as e:  # noqa: BLE001
        print('error: ' + str(e), file=sys.stderr)
        return 9


if __name__ == '__main__':
    sys.exit(main())

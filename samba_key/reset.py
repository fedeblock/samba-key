"""Privileged password reset (no old password needed).

This is the only place a new password reaches the Samba passdb. It runs as the
authority (root, on the Samba host) and resets an *allowlisted* account. The new
password is delivered on **stdin through a pipe** -- it is never in argv, the
environment, a file, or a log.  The account is validated against the authority's
allowlist and the password against a policy before anything is invoked, and no
arbitrary command or argument is passed: the invocation is a fixed template.

For standalone Samba the reset is ``smbpasswd -s <user>`` (root sets the
password without the old one). ``smbpasswd -s`` reads the new password from
**standard input** (prompting twice: the password and its confirmation), so the
transport writes ``new\nnew\n`` to a stdin pipe. (``smbclient`` is the one
binary that understands a ``PASSWD_FD`` pipe; ``smbpasswd`` does not.) The
transport is an injectable seam so the unit tests exercise the real argument
construction and password delivery without a live Samba; the real-Samba
invocation is exercised by ``tests/run_reset_docker.sh``.
"""
import logging
import re
import subprocess

LOG = logging.getLogger(__name__)

USERNAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$')


def make_reset_fn(eligible, min_length=12, max_length=1024,
                  executable='smbpasswd', timeout=15, transport=None):
    """Return a ``reset_fn(account, new_password) -> bool``.

    Only allowlisted accounts may be reset; the account is matched exactly
    (case-sensitive) against ``eligible`` and ``root`` is refused. The new
    password must satisfy the policy and carry no control bytes.
    """
    eligible = frozenset(eligible)

    def _policy_ok(new):
        return (isinstance(new, str) and 0 < len(new) < 1024
                and not any(c in new for c in '\r\n\0')
                and len(new) >= min_length
                and len(new.encode('utf-8')) <= max_length)

    def _command(account):
        # No password anywhere in the command line.
        return [executable, '-s', account]

    def _transport_stdin(account, new_password):
        # The password is written to the child's stdin pipe and to nowhere else:
        # not argv, not the environment, not a file, not a log. smbpasswd -s
        # reads the new password (twice) from standard input.
        payload = (new_password + '\n' + new_password + '\n').encode('utf-8')
        try:
            process = subprocess.Popen(
                _command(account),
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        except OSError:
            raise
        try:
            _out, _err = process.communicate(input=payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        return process.returncode

    _transport = transport or _transport_stdin

    def reset_fn(account, new_password):
        if not (isinstance(account, str) and USERNAME.fullmatch(account)
                and account.lower() != 'root' and account in eligible):
            LOG.warning('refusing reset for non-allowlisted account')
            return False
        if not _policy_ok(new_password):
            LOG.warning('refusing reset: new password fails policy')
            return False
        try:
            rc = _transport(account, new_password)
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOG.warning('privileged reset unavailable: %s', type(exc).__name__)
            return False
        ok = rc == 0
        if not ok:
            LOG.warning('privileged reset failed for an allowlisted account')
        return ok

    return reset_fn


def main():
    import sys
    print('reset.py is a library module; authority_main wires it.',
          file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())

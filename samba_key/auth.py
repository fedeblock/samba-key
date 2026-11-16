"""Reauthentication for enrollment: verify that a user knows their current
Samba password *without* changing it, *without* confusing a guest session, and
*without* exposing the password.

Mechanism
---------
``smbclient`` connects to a **guest-forbidden** share (``guest ok = no``) so a
globally mapped guest can never complete the connection, regardless of the
server's ``map to guest`` setting (proven against a disposable Samba under
``never``, ``Bad User`` and ``Bad Password``).  The password is delivered
through a **private pipe file descriptor** via the ``PASSWD_FD`` environment
variable, so it is never in the argument vector, the environment (only the
numeric fd is), any file, or any log.  This is TTY-independent, which matters
more than stdin because ``smbclient`` may otherwise read ``/dev/tty``.

Canary
------
Because a misconfigured share (``guest ok = yes``) or a Samba quirk could let a
wrong/empty/guest credential *succeed*, the verifier self-tests: a random
*nonexistent* user with a random password must **fail**.  If the canary ever
fails, reauthentication must be disabled (fail closed) rather than trusted.

The guest-forbidden share is an operator-supplied deployment requirement
(documented in OPERATIONS.md); without it there is no reauthentication.
"""
import logging
import os
import re
import secrets
import string
import subprocess

USERNAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$')
STATUS = re.compile(r'\bNT_STATUS_[A-Z0-9_]{1,80}\b')
LOG = logging.getLogger(__name__)


class CredentialVerifier:
    def __init__(self, server, share='skverify', executable='smbclient',
                 max_password_length=1024, timeout=15, transport=None):
        self.server = server
        self.share = share
        self.executable = executable
        self.max_password_length = max_password_length
        self.timeout = timeout
        # The transport seam is injectable so unit tests can stub execution
        # without a live Samba; the default is the real PASSWD_FD transport.
        self._transport = transport or self._transport_passwd_fd

    # -- public API --------------------------------------------------------
    def verify(self, username, password):
        username = username.strip()
        if not USERNAME.fullmatch(username) or username.lower() == 'root':
            return False
        if not password or any(c in password for c in '\r\n\0'):
            # Empty (would map to a guest under any "map to guest" setting) or
            # control bytes that corrupt the protocol are rejected up front.
            return False
        if len(password.encode('utf-8')) > self.max_password_length:
            return False
        try:
            rc = self._transport(username, password)
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOG.warning('Samba credential verification unavailable: %s',
                        type(exc).__name__)
            return False
        if rc != 0:
            LOG.warning('Samba credential verification failed for %s', username)
            return False
        return True

    def canary_ok(self):
        """Return True only if a random nonexistent user fails to authenticate.

        A misconfigured (guest-accepting) share or a broken verifier would make
        this succeed; the enrollment flow must then disable reauthentication.
        """
        username = 'skcanary' + secrets.token_hex(8)
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(24))
        return not self.verify(username, password)

    # -- real transport ----------------------------------------------------
    def _command(self, username):
        # No password ever appears here.
        return [self.executable, '//' + self.server + '/' + self.share,
                '-U', username, '-c', 'exit']

    def _transport_passwd_fd(self, username, password):
        # The password flows through a pipe fd named by PASSWD_FD. It is never
        # in argv, env (only the fd number), a file, or a log.
        read_fd, write_fd = os.pipe()
        env = dict(os.environ)
        env['PASSWD_FD'] = str(read_fd)
        try:
            process = subprocess.Popen(
                self._command(username), env=env, pass_fds=[read_fd],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            os.write(write_fd, password.encode('utf-8') + b'\n')
        finally:
            os.close(write_fd)
            try:
                os.close(read_fd)
            except OSError:
                pass
        try:
            rc = process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        return rc

    # -- fallback transport (stdin) ----------------------------------------
    def _transport_stdin(self, username, password):
        return subprocess.run(
            self._command(username), input=password + '\n', text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=self.timeout, check=False).returncode


def make_stdin_verifier(server, share='skverify', executable='smbclient',
                        max_password_length=1024, timeout=15):
    v = CredentialVerifier(server, share=share, executable=executable,
                           max_password_length=max_password_length, timeout=timeout)
    v._transport = v._transport_stdin
    return v

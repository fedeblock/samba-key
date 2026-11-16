import collections
import logging
import re
import subprocess
import threading
import time

USERNAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$')
LOG = logging.getLogger(__name__)


class PasswordChanger:
    """Changes a Samba password through the unprivileged smbpasswd client.

    Returns a boolean so callers can show a single generic result. It never
    distinguishes "wrong current password" from "account does not exist",
    which keeps the change endpoint resistant to account enumeration.
    """

    def __init__(self, server, executable='smbpasswd', min_length=12,
                 max_length=1024, max_current_length=4096, timeout=15):
        self.server = server
        self.executable = executable
        self.min_length = min_length
        self.max_length = max_length
        self.max_current_length = max_current_length
        self.timeout = timeout

    def policy_ok(self, old, new):
        """Local checks that do not require contacting the server.

        The minimum length and the policy maximum apply to the NEW password
        only, so a user whose current Samba password is shorter than the
        minimum (or longer than the new-password maximum) can still change it
        to a compliant one. The current password is bounded only by a separate,
        generous technical cap (max_current_length): it must be non-empty, free
        of the control bytes that would corrupt the newline-delimited stdin
        protocol, and within that cap so it can be processed safely without a
        pathological amount of memory. It is never forced to satisfy the new
        password policy.
        """
        if not old or any(c in old for c in '\r\n\0'):
            return False
        if len(old.encode('utf-8')) > self.max_current_length:
            return False
        if not new or any(c in new for c in '\r\n\0'):
            return False
        if len(new.encode('utf-8')) > self.max_length:
            return False
        return len(new) >= self.min_length

    def change(self, username, old, new):
        if not USERNAME.fullmatch(username) or username.lower() == 'root':
            return False
        if not self.policy_ok(old, new):
            return False
        try:
            result = subprocess.run(
                [self.executable, '-s', '-r', self.server, '-U', username],
                input=f'{old}\n{new}\n{new}\n', text=True,
                capture_output=True, timeout=self.timeout,
                check=False,
            )
            if result.returncode != 0:
                # Never log raw client output: it can contain names or secrets.
                output = ' '.join(x for x in (result.stdout, result.stderr) if isinstance(x, str))
                match = re.search(r'\bNT_STATUS_[A-Z0-9_]{1,80}\b', output)
                LOG.warning('Samba password change failed: %s', match.group(0) if match else 'no_status')
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOG.warning('Samba password change unavailable: %s', type(exc).__name__)
            return False


class AttemptLimiter:
    def __init__(self, limit=6, window=300, max_clients=10000):
        self.limit, self.window, self.max_clients = limit, window, max_clients
        self.attempts = collections.OrderedDict()
        self.lock = threading.Lock()

    def allow(self, client, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            for key in list(self.attempts):
                if not self.attempts[key] or now - self.attempts[key][-1] >= self.window:
                    del self.attempts[key]
            if client not in self.attempts and len(self.attempts) >= self.max_clients:
                return False
            times = self.attempts.setdefault(client, collections.deque())
            while times and now - times[0] >= self.window:
                times.popleft()
            if len(times) >= self.limit:
                return False
            times.append(now)
            return True

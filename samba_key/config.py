"""Configuration loaded from the environment with safe, validated defaults.

The portal validates its configuration before serving. If the environment is
misconfigured the application responds to every request with HTTP 503 instead
of serving with insecure settings; it does not necessarily refuse to load.
No value here is a deployment secret; secrets are read separately and never
stored in source control.
"""
import os


class ConfigError(Exception):
    """Raised when the environment describes an unsafe or invalid setup."""


def _make_get(environ):
    """Build readers over the supplied mapping so tests can inject an
    environment without touching the process globals."""

    def get_str(name, default):
        raw = environ.get(name)
        return default if raw is None else raw.strip()

    def get_int(name, default, minimum=None, maximum=None):
        raw = environ.get(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise ConfigError(f'{name} must be an integer') from None
        if minimum is not None and value < minimum:
            raise ConfigError(f'{name} must be at least {minimum}')
        if maximum is not None and value > maximum:
            raise ConfigError(f'{name} must be at most {maximum}')
        return value

    return get_str, get_int


class Config:
    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        get_str, get_int = _make_get(env)

        self.server = get_str('SAMBA_SERVER', 'host.docker.internal')
        if not self.server:
            raise ConfigError('SAMBA_SERVER must not be empty')

        self.min_password_length = get_int('MIN_PASSWORD_LENGTH', 12, 8, 64)
        self.max_password_length = get_int('MAX_PASSWORD_LENGTH', 1024, 32, 1024)
        if self.max_password_length < self.min_password_length:
            raise ConfigError('MAX_PASSWORD_LENGTH must be at least MIN_PASSWORD_LENGTH')

        # A separate, generous technical cap for the CURRENT password. A user's
        # existing password is not forced to satisfy the new-password policy, so
        # a current password longer than MAX_PASSWORD_LENGTH can still be changed
        # to a compliant one. The cap only bounds processing cost.
        self.max_current_password_length = get_int(
            'MAX_CURRENT_PASSWORD_LENGTH', 4096, 32, 65536)
        if self.max_current_password_length < self.max_password_length:
            raise ConfigError(
                'MAX_CURRENT_PASSWORD_LENGTH must be at least MAX_PASSWORD_LENGTH')

        self.rate_limit = get_int('RATE_LIMIT', 6, 1, 10000)
        self.rate_window = get_int('RATE_WINDOW', 300, 10, 86400)
        self.rate_max_clients = get_int('RATE_MAX_CLIENTS', 10000, 1, 1_000_000)

        # --- Recovery (optional, disabled by default) ---
        # Automatic recovery is NOT enabled: a portal that can read channel
        # bindings cannot re-bind them, so a fully compromised portal is trusted
        # for delivery and it is not secure. Only the "approval" policy is
        # offered, and it requires a configured privileged authority boundary.
        self.recovery_mode = get_str('RECOVERY_MODE', 'disabled').lower()
        if self.recovery_mode not in {'disabled', 'automatic', 'approval'}:
            raise ConfigError('RECOVERY_MODE must be disabled, automatic or approval')

        self.recovery_socket = get_str('RECOVERY_SOCKET', '')
        # The admin socket lives at <AUTHORITY_DIR>/admin.sock; the out-of-band
        # admin CLI falls back to that path when RECOVERY_ADMIN_SOCKET is unset.
        self.admin_socket = get_str('RECOVERY_ADMIN_SOCKET',
                                    get_str('AUTHORITY_DIR',
                                           '/run/samba-key') + '/admin.sock')
        self.portal_store = get_str('PORTAL_STORE',
                                    '/run/samba-key/portal.db')
        self.request_ttl = get_int('RECOVERY_REQUEST_TTL', 1800, 60, 86400)
        self.link_ttl = get_int('RECOVERY_LINK_TTL', 900, 60, 86400)
        self.max_pending_global = get_int('MAX_PENDING_GLOBAL', 50, 1, 100000)
        self.max_pending_per_account = get_int('MAX_PENDING_PER_ACCOUNT', 1, 1, 100)
        self.recovery_clients_limit = get_int('RECOVERY_CLIENTS_LIMIT', 20000,
                                              1, 1_000_000)
        # A short client receive timeout so a hung or silent authority cannot
        # block the portal or amplify a denial of service.
        self.recovery_client_timeout = get_int('RECOVERY_CLIENT_TIMEOUT', 3, 1, 120)

        # Privilege separation. The authority daemon runs as root and binds the
        # admin socket as root:admin_group 0660 and the portal socket as
        # root:portal_group 0660. The portal process runs as portal_uid and must
        # be disjoint from the admin group, so it cannot reach the admin socket
        # or approve. A root or overlapping portal identity is refused to start.
        self.portal_uid = get_int('PORTAL_UID', 33, 0, 65534)
        self.portal_group = get_str('PORTAL_GROUP', 'www-data')
        self.admin_group = get_str('ADMIN_GROUP', 'samba-key-admin')
        # The sockets live under the (volatile) runtime dir; the ledger lives
        # under a PERSISTENT data dir. /run and /var/run are tmpfs and are
        # cleared on reboot, so a data dir there would lose the channel bindings
        # on every restart; prepare_storage refuses the volatile locations.
        self.authority_dir = get_str('AUTHORITY_DIR', '/run/samba-key')
        split_sockets = get_str('AUTHORITY_SPLIT_SOCKETS', 'false').lower()
        if split_sockets not in {'true', 'false'}:
            raise ConfigError('AUTHORITY_SPLIT_SOCKETS must be true or false')
        self.authority_split_sockets = split_sockets == 'true'
        self.recovery_data_dir = get_str('RECOVERY_DATA_DIR',
                                         '/var/lib/samba-key')
        if self.portal_group == self.admin_group:
            raise ConfigError(
                'PORTAL_GROUP and ADMIN_GROUP must differ: the portal identity '
                'must be disjoint from the admin group')

        # Delivery providers. Both are optional; at least one must be usable for
        # approval recovery to be functional (a request with no channel cannot
        # be delivered), but this is not required to start the app.
        self.smtp_host = get_str('SMTP_HOST', '')
        self.smtp_port = get_int('SMTP_PORT', 587, 1, 65535)
        self.smtp_from = get_str('SMTP_FROM', '')
        # SMTP credentials are deployment secrets: read from the environment or a
        # root-owned secret file, never from source control. Empty means e-mail
        # delivery is unavailable (Telegram can still be used on its own).
        # SMTP credentials are deployment secrets: read from a root-owned secret
        # file (preferred) or the environment, never from source control. Empty
        # means e-mail delivery is unavailable (Telegram can still be used on its
        # own). The secret itself is never placed in the public summary or logs.
        self.smtp_user = get_str('SMTP_USER', '')
        # A secret may come from a root-owned file (preferred, so it is not in
        # the process environment or any command line) or from the environment.
        def read_secret(var, file_var):
            path = get_str(file_var, '')
            if path:
                try:
                    with open(path, 'r') as fh:
                        return fh.read().strip()
                except OSError:
                    return ''
            return get_str(var, '')
        self.smtp_password = read_secret('SMTP_PASSWORD', 'SMTP_PASSWORD_FILE')
        self.smtp_sender = get_str('SMTP_SENDER', self.smtp_from)
        self.telegram_bot_token = read_secret('TELEGRAM_BOT_TOKEN',
                                              'TELEGRAM_BOT_TOKEN_FILE')
        self.telegram_api_base = get_str('TELEGRAM_API_BASE',
                                        'https://api.telegram.org').rstrip('/')
        # The polling cadence is its own knob (not the delivery interval, which
        # is coarser): a short pause so a transient outage does not spin the
        # API. A minimum of 1s guards against an aggressive loop.
        self.telegram_poll_interval = get_int(
            'TELEGRAM_POLL_INTERVAL', 3, 1, 3600)

        # The privileged reset and the eligible-accounts allowlist. The allowlist
        # is read from a root-owned file (not the environment, which the web
        # process can see), so a portal compromise cannot widen what the authority
        # will reset. Empty means the authority serves but resets nothing.
        self.recovery_eligible_file = get_str(
            'RECOVERY_ELIGIBLE_FILE', '/etc/samba-key/eligible.accounts')
        self.reset_executable = get_str('RECOVERY_RESET_EXECUTABLE', 'smbpasswd')
        self.reset_min_length = self.min_password_length
        self.reset_max_length = self.max_password_length
        self.deliver_interval = get_int('RECOVERY_DELIVER_INTERVAL', 30, 5, 3600)

        # An administrator-specified HTTPS origin, used only when recovery is
        # enabled. It must never be derived from the Host or forwarded headers
        # of an incoming request.
        self.base_url = get_str('BASE_URL', '').rstrip('/')

        if self.recovery_mode == 'automatic':
            raise ConfigError(
                'RECOVERY_MODE=automatic is not enabled: a portal that can read '
                'channel bindings cannot be trusted to deliver recovery links to '
                'the right person, so automatic recovery is not secure against a '
                'compromised portal. It is blocked. Use RECOVERY_MODE=approval.')
        if self.recovery_mode == 'approval':
            # Approval is the only enabled non-default policy. It is safe to run
            # only with a configured authority socket and an HTTPS origin, so a
            # misconfiguration fails closed rather than silently serving inert
            # routes that look enabled.
            if not self.recovery_socket:
                raise ConfigError(
                    'RECOVERY_MODE=approval requires RECOVERY_SOCKET to be set '
                    '(the portal->authority socket); recovery is disabled.')
            if not self.base_url or not self.base_url.lower().startswith('https'):
                raise ConfigError(
                    'RECOVERY_MODE=approval requires an HTTPS BASE_URL for the '
                    'recovery links; recovery is disabled.')
            self._recovery_available = True
            return

        # Recovery is disabled: nothing is served, routes stay inert.
        self._recovery_available = False

    def public(self):
        """Non-secret summary suitable for a diagnostics endpoint."""
        return {
            'recovery_mode': self.recovery_mode,
            'min_password_length': self.min_password_length,
            'max_password_length': self.max_password_length,
            'max_current_password_length': self.max_current_password_length,
            'rate_limit': self.rate_limit,
            'rate_window': self.rate_window,
            'recovery_available': self._recovery_available,
        }

import hmac
import os
import secrets

from flask import Flask, jsonify, render_template, request, session

from .config import Config, ConfigError
from .core import PasswordChanger, AttemptLimiter

TEXT = {
    'es': {
        'title': 'Cambia tu contraseña',
        'description': 'Actualiza la contraseña con la que accedes a tus carpetas compartidas.',
        'user': 'Usuario',
        'old': 'Contraseña actual',
        'new': 'Nueva contraseña',
        'confirm': 'Repite la nueva contraseña',
        'button': 'Cambiar contraseña',
        'help': 'Si no recuerdas tu contraseña, contacta con la persona administradora del servidor.',
        'recovery_link': '¿Olvidaste tu contraseña? Solicitar recuperación',
        'limited': 'Demasiados intentos. Vuelve a probar en unos minutos.',
        'invalid': 'Comprueba que las nuevas contraseñas coincidan, tengan al menos {min} caracteres y sean distintas de la anterior.',
        'missing_user': 'Introduce el usuario.',
        'missing_old': 'Introduce la contraseña actual.',
        'mismatch': 'Las contraseñas nuevas no coinciden.',
        'too_short': 'La contraseña nueva debe tener al menos {min} caracteres.',
        'same_password': 'La contraseña nueva debe ser diferente de la actual.',
        'success': 'Contraseña cambiada. Actualízala en tus dispositivos.',
        'failed': 'No se pudo cambiar la contraseña. Comprueba tus datos y vuelve a intentarlo.',
        'recovery_unavailable': 'La recuperación de contraseña no está disponible. Contacta con la persona administradora del servidor.',
        'recovery_title': 'Recuperar contraseña',
        'recovery_hint': 'Si tienes un canal de recuperación verificado, se creará una solicitud. Un administrador debe aprobarla; si lo hace, recibirás un enlace de corta duración.',
        'recovery_complete_hint': 'Introduce la nueva contraseña. El enlace se usa una sola vez y caduca pronto.',
        'recovery_submit': 'Solicitar recuperación',
        'recovery_channel': '¿Dónde querés recibir el enlace?',
        'recovery_auto': 'Cualquier canal disponible',
        'recovery_email': 'Correo electrónico',
        'recovery_telegram': 'Telegram',
        'recovery_new_password': 'Nueva contraseña',
        'recovery_token': 'Código del enlace (lo encontrarás en el correo o en Telegram)',
        'recovery_account_label': 'Cuenta de Samba',
        'recovery_destination_label': 'Enlace enviado a',
        'recovery_associated_email_label': 'Correo asociado',
        'recovery_email_label': 'Correo',
        'recovery_telegram_label': 'Telegram',
        'back_to_start': 'Volver al inicio',
        'recovery_password_hint': 'Usá al menos {min} caracteres.',
        'recovery_generic': 'Si existe un canal de recuperación para ese usuario, se ha creado una solicitud. Debe ser aprobada por un administrador; si lo es, pronto recibirás un enlace. No se revela nada si el usuario es desconocido o no tiene canal.',
        'recovery_ok': 'Listo, tu contraseña se cambió. Actualizala en tus dispositivos.',
        'recovery_invalid': 'Ese enlace no es válido o ha caducado. Solicita uno nuevo.',
        'recovery_limited': 'Demasiados intentos. Espera y prueba de nuevo más tarde.',
        'recovery_uncertain': 'No se pudo confirmar el resultado. Probá la nueva contraseña antes de solicitar otro enlace o contactá a la persona administradora.',
        'change_password': 'Cambiar contraseña',
        'show': 'Mostrar contraseña',
        'hide': 'Ocultar contraseña',
        'skip': 'Saltar al formulario',
        'language': 'Idioma',
    },
    'en': {
        'title': 'Change your password',
        'description': 'Update the password you use to access your shared folders.',
        'user': 'Username',
        'old': 'Current password',
        'new': 'New password',
        'confirm': 'Repeat new password',
        'button': 'Change password',
        'help': 'If you forgot your password, contact your server administrator.',
        'recovery_link': 'Forgot your password? Request recovery',
        'limited': 'Too many attempts. Please try again in a few minutes.',
        'invalid': 'Make sure your new passwords match, have at least {min} characters, and differ from your current password.',
        'missing_user': 'Enter your username.',
        'missing_old': 'Enter your current password.',
        'mismatch': 'The new passwords do not match.',
        'too_short': 'The new password must have at least {min} characters.',
        'same_password': 'The new password must differ from the current password.',
        'success': 'Password changed. Update it on your devices.',
        'failed': 'Could not change your password. Check your details and try again.',
        'recovery_unavailable': 'Password recovery is not available. Contact your server administrator.',
        'recovery_title': 'Recover password',
        'recovery_hint': 'If you have a verified recovery channel, a request will be created. An administrator must approve it; if they do, you will receive a short-lived link.',
        'recovery_complete_hint': 'Enter your new password. The link is single-use and expires soon.',
        'recovery_submit': 'Request recovery',
        'recovery_channel': 'Where should we send the link?',
        'recovery_auto': 'Any available channel',
        'recovery_email': 'Email',
        'recovery_telegram': 'Telegram',
        'recovery_new_password': 'New password',
        'recovery_token': 'Link code (find it in your e-mail or Telegram)',
        'recovery_account_label': 'Samba account',
        'recovery_destination_label': 'Link sent to',
        'recovery_associated_email_label': 'Associated email',
        'recovery_email_label': 'Email',
        'recovery_telegram_label': 'Telegram',
        'back_to_start': 'Back to start',
        'recovery_password_hint': 'Use at least {min} characters.',
        'recovery_generic': 'If a recovery channel is registered for that account, a request has been created. It must be approved by an administrator; if so, you will receive a link shortly. Nothing is revealed if the account is unknown or has no channel.',
        'recovery_ok': 'Your password has been changed. Update it on your devices.',
        'recovery_invalid': 'That link is not valid or has expired. Please request a new one.',
        'recovery_limited': 'Too many attempts. Please wait and try again later.',
        'recovery_uncertain': 'The result could not be confirmed. Try the new password before requesting another link, or contact your administrator.',
        'change_password': 'Change password',
        'show': 'Show password',
        'hide': 'Hide password',
        'skip': 'Skip to form',
        'language': 'Language',
    },
}


# Map a recovery service status to a localized message key, so the user sees the
# message in the chosen language. The generic key keeps every non-enumerating
# outcome (unknown account, no channel, not yet approved, ...) byte-identical; the
# rate_limited key is the one documented exception to uniformity.
_RECOVERY_STATUS = {
    'generic': 'recovery_generic',
    'ok': 'recovery_ok',
    'invalid': 'recovery_invalid',
    'rate_limited': 'recovery_limited',
    'uncertain': 'recovery_uncertain',
}


def _recovery_message(t, result, fallback='recovery_unavailable'):
    """Render a recovery service result as a localized, non-enumerating message."""
    status = result.get('status', 'generic')
    return t.get(_RECOVERY_STATUS.get(status), t.get(fallback))


def _build_recovery_service(config, portal_store=None):
    """Build the portal-side recovery service from configuration, or None if the
    authority cannot be reached (fail closed to an inert page). The service only
    requests and completes; delivery is authority-side."""
    try:
        from .reset_auth import ResetClient
        from .recovery import RecoveryService
        from .store import Store
        client = ResetClient(config.recovery_socket,
                             recv_timeout=config.recovery_client_timeout)
        store = portal_store or Store(config.portal_store)
        return RecoveryService(
            client, store, config.base_url,
            policy_min=config.min_password_length,
            policy_max=config.max_password_length,
            request_limit=config.rate_limit,
            request_window=config.rate_window,
            complete_limit=config.rate_limit,
            complete_window=config.rate_window,
            client_limit=config.rate_limit,
            client_window=config.rate_window,
            clients_cap=config.recovery_clients_limit)
    except OSError:
        return None


def create_app(recovery_service=None, portal_store=None):
    try:
        config = Config()
    except ConfigError:
        # Fail closed: a misconfigured portal must not serve.
        def unavailable(_request=None):
            return 'Service temporarily unavailable', 503

        app = Flask(__name__)
        app.secret_key = os.environ.get('SAMBA_KEY_SECRET') or secrets.token_bytes(32)
        app.before_request(unavailable)
        return app

    app = Flask(__name__)
    app.secret_key = os.environ.get('SAMBA_KEY_SECRET') or secrets.token_bytes(32)
    # Form URL encoding may expand each byte to three ASCII characters.
    max_form_size = 3 * (config.max_current_password_length + 2 * config.max_password_length) + 4096
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_SAMESITE='Strict', MAX_CONTENT_LENGTH=max_form_size)
    changer = PasswordChanger(config.server, min_length=config.min_password_length,
                              max_length=config.max_password_length,
                              max_current_length=config.max_current_password_length)
    limiter = AttemptLimiter(limit=config.rate_limit, window=config.rate_window,
                             max_clients=config.rate_max_clients)

    # Recovery is optional and disabled by default. When enabled, the routes call
    # the authority through an injected (or config-built) service; when disabled
    # or the authority is unreachable, the routes render one uniform, inert page
    # that never reveals whether an account or channel exists.
    recovery_svc = recovery_service
    if recovery_svc is None and getattr(config, '_recovery_available', False):
        recovery_svc = _build_recovery_service(config, portal_store)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "connect-src 'self'")
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.route('/', methods=['GET', 'POST'])
    def index():
        lang = request.args.get('lang', 'en')
        if lang not in TEXT:
            lang = 'en'
        t = TEXT[lang]
        message, status, username = '', 200, ''
        message_success = False
        if request.method == 'POST':
            sent = request.form.get('csrf', '')
            expected = session.get('csrf', '')
            if not expected or not sent.isascii() or not hmac.compare_digest(sent, expected):
                return 'Invalid request', 403
            # Do not trust X-Forwarded-For from clients. A reverse proxy will
            # share one limit across its clients unless configured separately.
            if not limiter.allow(request.remote_addr or 'unknown'):
                message, status = t['limited'], 429
            else:
                username = request.form.get('username', '').strip()
                old = request.form.get('old_password', '')
                new = request.form.get('new_password', '')
                confirm = request.form.get('confirm_password', '')
                # Local policy first; the generic message avoids disclosing
                # which check failed and does not reveal account existence.
                if not username:
                    message = t['missing_user']
                elif not old:
                    message = t['missing_old']
                elif new != confirm:
                    message = t['mismatch']
                elif len(new) < config.min_password_length:
                    message = t['too_short'].format(min=config.min_password_length)
                elif old == new:
                    message = t['same_password']
                elif (len(new.encode('utf-8')) > config.max_password_length
                      or any(c in new for c in '\r\n\0')):
                    message = t['invalid'].format(min=config.min_password_length)
                elif changer.change(username, old, new):
                    message = t['success']
                    message_success = True
                    session.pop('csrf', None)
                else:
                    message = t['failed']
        token = session.setdefault('csrf', secrets.token_urlsafe(32))
        return render_template('index.html', csrf=token, message=message, t=t, lang=lang,
                              min_length=config.min_password_length, username=username,
                              message_success=message_success,
                              enable_recovery=recovery_svc is not None), status

    @app.route('/recovery', methods=['GET', 'POST'])
    def recovery_request():
        lang = request.args.get('lang', 'en')
        if lang not in TEXT:
            lang = 'en'
        t = TEXT[lang]
        message = '' if recovery_svc is not None else t['recovery_unavailable']
        if recovery_svc is not None and request.method == 'POST':
            sent = request.form.get('csrf', '')
            expected = session.get('csrf', '')
            if not expected or not sent.isascii() or \
                    not hmac.compare_digest(sent, expected):
                return 'Invalid request', 403
            # A uniform response regardless of account/channel existence.
            result = recovery_svc.request(request.form.get('username', '').strip(),
                                         request.remote_addr or 'unknown',
                                         request.form.get('channel', 'auto'))
            message = _recovery_message(t, result)
            session.pop('csrf', None)
        token = session.setdefault('csrf', secrets.token_urlsafe(32))
        return render_template('recovery.html', t=t, lang=lang, message=message,
                              enable_form=recovery_svc is not None, mode='request',
                              csrf=token, min_length=config.min_password_length,
                              username=''), 200

    @app.post('/reset/details')
    def reset_details():
        sent = request.form.get('csrf', '')
        expected = session.get('csrf', '')
        if not expected or not sent.isascii() or not hmac.compare_digest(sent, expected):
            return 'Invalid request', 403
        if recovery_svc is None:
            return jsonify({})
        details = recovery_svc.details(request.form.get('token', ''), request.remote_addr or 'unknown')
        if not details:
            return jsonify({})
        return jsonify({key: details[key] for key in ('account', 'channel', 'destination', 'associated_email')
                        if key in details})

    @app.route('/reset', methods=['GET', 'POST'])
    def reset_link():
        """Consumes a recovery link. The token arrives in the URL fragment
        (client-side only) and is posted in the body, never in the path, so it
        cannot reach the access log. The response is uniform whether or not the
        link was valid. When recovery is disabled or the authority is
        unreachable, the same uniform page is shown."""
        lang = request.args.get('lang', 'en')
        if lang not in TEXT:
            lang = 'en'
        t = TEXT[lang]
        message = '' if recovery_svc is not None else t['recovery_unavailable']
        recovery_token = ''
        message_success = False
        if recovery_svc is not None and request.method == 'POST':
            sent = request.form.get('csrf', '')
            expected = session.get('csrf', '')
            if not expected or not sent.isascii() or \
                    not hmac.compare_digest(sent, expected):
                return 'Invalid request', 403
            result = recovery_svc.complete(request.form.get('token', ''),
                                          request.form.get('new_password', ''),
                                          request.remote_addr or 'unknown')
            message = (t['too_short'].format(min=config.min_password_length)
                       if result.get('status') == 'short_password'
                       else _recovery_message(t, result))
            message_success = result.get('status') == 'ok'
            if result.get('status') == 'short_password':
                recovery_token = request.form.get('token', '')
            session.pop('csrf', None)
        token = session.setdefault('csrf', secrets.token_urlsafe(32))
        return render_template('recovery.html', t=t, lang=lang, message=message,
                              enable_form=recovery_svc is not None, mode='complete',
                              csrf=token, min_length=config.min_password_length,
                              recovery_token=recovery_token, message_success=message_success,
                              username=''), 200

    @app.route('/healthz')
    def healthz():
        return jsonify(config.public())

    return app


app = create_app()

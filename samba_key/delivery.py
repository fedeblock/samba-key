"""Optional notification transports. These do not implement account recovery."""
import json
import re
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage


class DeliveryError(Exception):
    """A notification could not be delivered; no provider secrets are included."""


class SmtpDelivery:
    def __init__(self, host, port, username, password, sender):
        self.host, self.port = host, port
        self.username, self.password, self.sender = username, password, sender

    def send(self, recipient, subject, body):
        try:
            message = EmailMessage()
            message['From'], message['To'], message['Subject'] = self.sender, recipient, subject
            message.set_content(body)
            with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(self.username, self.password)
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException, ValueError):
            raise DeliveryError('SMTP delivery failed') from None


class TelegramDelivery:
    def __init__(self, bot_token):
        self.bot_token = bot_token

    def send(self, chat_id, subject, body):
        if not re.fullmatch(r'[1-9][0-9]{0,19}', str(chat_id)):
            raise DeliveryError('Invalid Telegram private chat ID')
        url = 'https://api.telegram.org/bot' + urllib.parse.quote(self.bot_token, safe=':') + '/sendMessage'
        payload = json.dumps({'chat_id': str(chat_id), 'text': f'{subject}\n\n{body}',
                              'disable_web_page_preview': True}).encode('utf-8')
        request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=10, context=ssl.create_default_context()) as response:
                result = json.loads(response.read(65536))
            if not isinstance(result, dict) or result.get('ok') is not True:
                raise DeliveryError('Telegram delivery failed')
        except (OSError, ValueError, UnicodeError):
            raise DeliveryError('Telegram delivery failed') from None


class RecoveryDelivery:
    """Common adapter the recovery service uses to reach a verified channel.

    It routes a (channel, target) to the real transport for that channel --
    ``SmtpDelivery.send(recipient, subject, body)`` for e-mail and
    ``TelegramDelivery.send(chat_id, subject, body)`` for Telegram -- so the
    transports themselves are exercised and only the network boundary (the SMTP
    server / the Telegram API) is substituted in tests.  A missing transport for
    the requested channel is a delivery failure, not a silent success.
    """

    def __init__(self, email=None, telegram=None):
        self.email = email
        self.telegram = telegram

    def send(self, channel, target, subject, body):
        provider = self.email if channel == 'email' else \
            self.telegram if channel == 'telegram' else None
        if provider is None:
            raise DeliveryError('No transport configured for that channel')
        if not target:
            raise DeliveryError('No target for that channel')
        provider.send(target, subject, body)

    @classmethod
    def from_config(cls, cfg):
        email = None
        telegram = None
        if getattr(cfg, 'smtp_host', None):
            email = SmtpDelivery(cfg.smtp_host, cfg.smtp_port, cfg.smtp_user,
                                 cfg.smtp_password, cfg.smtp_sender)
        if getattr(cfg, 'telegram_bot_token', None):
            telegram = TelegramDelivery(cfg.telegram_bot_token)
        return cls(email=email, telegram=telegram)

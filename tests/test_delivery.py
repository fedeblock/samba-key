import unittest
from unittest.mock import call, patch

from samba_key.delivery import DeliveryError, SmtpDelivery, TelegramDelivery


class DeliveryTests(unittest.TestCase):
    @patch('samba_key.delivery.smtplib.SMTP')
    def test_smtp_uses_tls_then_auth_and_sends_no_password(self, smtp):
        conn = smtp.return_value.__enter__.return_value
        client = SmtpDelivery('smtp.example.test', 587, 'sender@example.test', 'secret', 'sender@example.test')
        client.send('person@example.test', 'Reset', 'https://example.test/reset/token')
        conn.starttls.assert_called_once()
        conn.login.assert_called_once_with('sender@example.test', 'secret')
        msg = conn.send_message.call_args.args[0]
        self.assertEqual(msg['To'], 'person@example.test')
        self.assertIn('https://example.test/reset/token', msg.get_content())
        self.assertNotIn('secret', msg.as_string())
        self.assertLess(conn.method_calls.index(call.starttls(context=conn.starttls.call_args.kwargs['context'])), conn.method_calls.index(call.login('sender@example.test', 'secret')))

    @patch('samba_key.delivery.urllib.request.urlopen')
    def test_telegram_sends_to_registered_chat_id(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.read.return_value = b'{"ok":true}'
        TelegramDelivery('test-token').send('123456', 'Reset', 'https://example.test/reset/token')
        request = urlopen.call_args.args[0]
        self.assertIn(b'"chat_id": "123456"', request.data)
        self.assertIn(b'example.test/reset/token', request.data)
        self.assertNotIn('123456', request.full_url)

    @patch('samba_key.delivery.urllib.request.urlopen')
    def test_telegram_fails_closed_without_exposing_token(self, urlopen):
        urlopen.side_effect = OSError('https://api.telegram.org/botsecret-token/sendMessage')
        with self.assertRaises(DeliveryError) as error:
            TelegramDelivery('secret-token').send('123', 'Reset', 'message')
        self.assertNotIn('secret-token', str(error.exception))
        self.assertIsNone(error.exception.__cause__)


if __name__ == '__main__':
    unittest.main()

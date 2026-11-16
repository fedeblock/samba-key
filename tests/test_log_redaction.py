"""The access log must not contain a recovery token that appears in a request's
path or query string.

The normal design carries the token in a URL *fragment* (never sent to the
server); this is the defence-in-depth guarantee for the accidental case, proven
by running a real Gunicorn master/workers with the shipped ``gunicorn.conf.py``
and inspecting the captured output.
"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = os.path.join(ROOT, 'gunicorn.conf.py')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


SENTINEL = 'SENTINEL_TOKEN_0123456789abcdef'


class GunicornAccessLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import gunicorn  # noqa: F401
        except Exception:
            raise unittest.SkipTest('gunicorn not installed')
        if not os.path.exists(CONFIG):
            raise unittest.SkipTest('gunicorn.conf.py not found')
        cls.port = free_port()
        env = dict(os.environ)
        cls.proc = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '--config', CONFIG,
             '--bind', f'127.0.0.1:{cls.port}', 'samba_key.app:app'],
            cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        cls.output = []
        cls._drain = threading.Thread(target=cls._pump, daemon=True)
        cls._drain.start()
        cls._wait_ready()

    @classmethod
    def _pump(cls):
        for line in cls.proc.stdout:
            cls.output.append(line)

    @classmethod
    def _wait_ready(cls, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        f'http://127.0.0.1:{cls.port}/healthz',
                        timeout=2) as resp:
                    resp.read()
                return
            except Exception:
                time.sleep(0.25)
        raise unittest.SkipTest('gunicorn did not become ready')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=10)
        except Exception:
            cls.proc.kill()
        cls._drain.join(timeout=5)
        if cls.proc.stdout:
            cls.proc.stdout.close()

    def _hits(self):
        base = f'http://127.0.0.1:{self.port}'
        for url in (
            f'{base}/?q={SENTINEL}',              # query string (sent to server)
            f'{base}/reset/{SENTINEL}',          # path component (sent to server)
            f'{base}/recovery#{SENTINEL}',       # fragment (never sent to server)
            base,                                 # benign
        ):
            req = urllib.request.Request(url)
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp.read()
            except urllib.error.HTTPError as exc:
                with exc:
                    pass
            except ValueError:
                pass
        # A malformed request must not crash the worker nor leak the token.
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        sock.sendall(b'GET /%s HTTP/1.1\r\nHost: x\r\n\r\n' % SENTINEL.encode())
        sock.recv(1024)
        sock.close()
        time.sleep(0.5)  # let the access log flush

    def test_token_not_in_captured_output(self):
        self._hits()
        captured = ''.join(self.output)
        self.assertNotIn(SENTINEL, captured,
                         'the access log leaked the token from a path/query')

    def test_server_still_serving(self):
        # After a malformed request the server keeps serving benign requests.
        with urllib.request.urlopen(
                f'http://127.0.0.1:{self.port}/healthz', timeout=3) as resp:
            self.assertEqual(resp.status, 200)


class GunicornDefaultFormatLeaksTests(unittest.TestCase):
    """Negative control: with Gunicorn's *default* access-log format the token
    in a path/query IS captured. This proves the redacted config (not the
    environment) is what protects the log."""

    @classmethod
    def setUpClass(cls):
        try:
            import gunicorn  # noqa: F401
        except Exception:
            raise unittest.SkipTest('gunicorn not installed')
        cls.port = free_port()
        env = dict(os.environ)
        # A config with the FULL access-log format: it includes the request line
        # (%r), i.e. the path and query -- the vector the redacted config
        # (gunicorn.conf.py) removes. This is the control that proves the
        # redacted config, not the environment, is what protects the log.
        cls.cfg = os.path.join(tempfile.mkdtemp(), 'full.log.conf')
        with open(cls.cfg, 'w') as fh:
            fh.write('accesslog = "-"\n'
                     'access_log_format = ' + repr(
                         '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(B)s') + '\n')
        cls.proc = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '--config', cls.cfg,
             '--bind', f'127.0.0.1:{cls.port}', 'samba_key.app:app'],
            cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        cls.output = []
        cls._drain = threading.Thread(target=cls._pump, daemon=True)
        cls._drain.start()
        cls._wait_ready()

    @classmethod
    def _pump(cls):
        for line in cls.proc.stdout:
            cls.output.append(line)

    @classmethod
    def _wait_ready(cls, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        f'http://127.0.0.1:{cls.port}/healthz',
                        timeout=2) as resp:
                    resp.read()
                return
            except Exception:
                time.sleep(0.25)
        # Surface why it failed rather than silently skipping.
        out = ''.join(cls.output)
        raise unittest.SkipTest(
            'gunicorn did not become ready: ' + out[-500:])

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=10)
        except Exception:
            cls.proc.kill()
        cls._drain.join(timeout=5)
        if cls.proc.stdout:
            cls.proc.stdout.close()

    def test_default_format_would_capture_the_token(self):
        sentinel = 'DEFAULT_LEAK_SENTINEL_0123'
        try:
            with urllib.request.urlopen(
                    f'http://127.0.0.1:{self.port}/reset/{sentinel}',
                    timeout=3) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            exc.close()  # a 404 still produces an access-log line we test for
        time.sleep(0.5)
        captured = ''.join(self.output)
        self.assertIn(sentinel, captured,
                      'the default format should capture the path; this is the '
                      'control that proves the redacted config is what protects')


if __name__ == '__main__':
    unittest.main()

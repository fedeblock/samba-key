"""Hardened Gunicorn configuration for the Samba Key portal.

The access-log format deliberately omits the request *path* and *query string*.
The normal design carries the recovery token in a URL *fragment*, which never
reaches the server or any proxy; this redaction is defence in depth for the
accidental case in which a token does appear in the path or query (for example a
stale or hand-edited link). The password is never placed in the request body's
logged portion. Operators still must not log request bodies upstream.
"""
# Bind is supplied on the command line.
backlog = 2048
workers = 1
threads = 4
# Redacted access log: time, client, method, status, size -- no path, no query.
accesslog = '-'
access_log_format = '%(t)s %(h)s %(m)s %(s)s %(B)s'
# Do not let the application log leak secrets.
logconfig = None
max_requests = 1000
max_requests_jitter = 50

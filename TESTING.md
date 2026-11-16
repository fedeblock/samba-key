# Testing

Samba Key is tested in layers, and each layer proves something different:

1. **Unit tests** check the logic quickly, with the outside world replaced by stand-ins. No Samba, Docker or credentials needed.
2. **Disposable-container tests** run the code against a real Samba, real Linux users and real sockets, in containers that are removed afterwards.
3. **Trials on a real host** with a dedicated test account and real email and Telegram providers. These are not automated and are not part of this repository's scripts.

A green unit test does not prove that Samba or a provider behaves as assumed; that is what layers 2 and 3 are for. When a result is quoted in these documents, it says which layer it came from.

Install `requirements.txt` in a virtual environment, then run `python3 -m unittest discover -s tests -v`. The core-only tests can run without external Python packages: `python3 -m unittest discover -s tests -p test_core.py -v`.

## Coverage

The suite covers, without personal credentials:

- **core**: passwords sent only via stdin; failed or timed-out changes fail closed; protocol injection and the `root`/option username are rejected; the minimum/maximum length policy is enforced on the **new** password only, while the **current** password is bounded by a separate technical cap and validated for protocol safety; a short or long current password can change to a compliant new one.
- **delivery**: SMTP STARTTLS-then-auth with no password in the message; Telegram sends to a registered numeric chat ID and fails closed without leaking the token.
- **config**: safe defaults; empty server and unknown/implausible numeric values are rejected; `automatic` is always refused and `approval` fails closed without an authority socket and an HTTPS origin; the public diagnostics summary excludes secrets.
- **web**: security headers and secure cookies; CSRF rejection and a successful change; the rate limiter ignores `X-Forwarded-For`; the minimum-password policy is enforced with a generic message; misconfiguration fails closed with HTTP 503; the `/recovery` and `/reset` routes are uniform, non-enumerating and inert when disabled; the content security policy permits local scripts only.
- **recovery (approval)**: the authority owns the channel bindings and the delivery; a `MINT` carries no destination and no token; the destination is pinned at approval and a binding change invalidates in-flight requests; a raw `PORTAL`-socket attempt to approve, issue or enroll is refused; the full supervised flow (request → approve → deliver → consume) runs through the real Flask app with a real authority over a Unix socket and a real `DeliveryWorker`, with only the network boundary faked; single-use and expiry; a dead authority gives a uniform, fast response; a crash between issue and send is pinned as a bounded residual risk; and an active portal can capture the token at use time (documented limit).
- **privilege separation**: real peer-credential and supplementary-group roles; the shipped daemon path (`check_separation` + `serve_sockets`) is proven on a disposable Linux container with real users (`tests/run_privsep_docker.sh`, **18/18**).

Run the full suite with the project virtual environment: `source .venv/bin/activate &&
python3 -m unittest discover -s tests -v` (the Flask/gunicorn tests need
`requirements.txt`; the core tests do not). When this was last checked the suite had **257 tests**; run it to see the current count.

The integration script (`tests/integration_disposable.py`) **refuses to run unless `SAMBA_SERVER` is set to the disposable test value `samba-ensayo`**, so it cannot accidentally target a real account. It is not part of the default `unittest` discovery.

## Live HTTP smoke check (no Samba required)

A real WSGI/HTTP request flow can be exercised against loopback without a Samba server. It proves the web layer, security headers, CSRF rejection, and generic failure handling end to end:

```sh
python -m flask --app samba_key.app:app run --host 127.0.0.1 --port 18099   # or gunicorn
```

Then, from another shell: a `GET /` returns the security headers and a `Secure`/`HttpOnly`/`SameSite=Strict` session cookie; a `POST /` without a CSRF token returns 403; a `POST /` with a valid CSRF token but no reachable Samba returns 200 with the generic "could not change your password" message (it fails closed and does not reveal account existence); `/healthz` returns the non-secret diagnostics summary; and `/recovery` returns the same uniform message for any query string. Use the development server only for this check; the production image uses gunicorn.

## Integration

There are two integration layers; the distinction matters.

### 1. Simulated (mocked `subprocess`)

The unit tests above drive `PasswordChanger` with a mocked `subprocess.run`, so they verify our logic and the exact `smbpasswd` invocation **without a real Samba server**. They do **not** prove that a real Samba accepts or rejects the change.

### 2. Real Samba, isolated containers (`tests/run_integration_docker.sh`)

This orchestrator starts a disposable Samba server and a client, both on an ephemeral Docker network with **no published ports** and **no host folders mounted into the Samba container** (only a `tmpfs`). It runs the portal's own `samba_key.core.PasswordChanger` against real Samba, exercising the actual SMB password-change protocol:

```sh
./tests/run_integration_docker.sh
```

It creates two fictitious accounts with test credentials and asserts:

- a wrong current password is rejected;
- a short but valid current password changes to a compliant new password;
- after the change the previous password no longer works and the new one does;
- a current password longer than the new-password maximum can still be changed to a compliant new one, and (contrast) that capping the current password at the new-password maximum would reject it.

On a disposable Debian/Samba container the orchestrator passes **6/6**.

The driver (`tests/integration_real.py`) is not part of default `unittest` discovery. Containers and the network are removed on exit, including on failure (an `EXIT`/`INT`/`TERM` trap). The `sk-samba:local` and `sk-runner:local` images are cached for reuse; remove them with `docker rmi` if desired. It requires Docker and network access to pull a Debian/Samba base image.

### 3. Privilege separation and the verifier, in disposable containers

- `tests/run_privsep_docker.sh` proves the shipped daemon path (`authority_main.check_separation` + `serve_sockets`) with **real created Linux users** and no mounted Docker socket: the portal is denied the admin socket, the authority DB and channel enrollment; the admin can approve and enroll; an overlapping identity is refused; a real supplementary-group breach is demonstrated. It passes **18/18**.
- `tests/run_verify_docker.sh` exercises the guest-forbidden credential verifier against disposable Samba (correct credentials verify; wrong/empty/absent passwords and a nonexistent user fail; a random canary user must fail). It passes **5/5**.
- `tests/run_leak_docker.sh` proves the password never appears in `/proc/<pid>/environ` and that the canary detects a guest-accepting share. Its **phase 1 passes 5/5**; **phase 2 is a negative control that exits non-zero by design** -- it deliberately shows that on a `guest ok = yes` share a wrong password *succeeds as a guest*, which is why such a share is refused. A non-zero phase-2 exit is the expected, intended result, not a failure.
- `tests/run_reset_docker.sh` proves the *live forgotten-password reset* against a disposable Samba, as root where the passdb lives: the real `smbpasswd -s` transport sets a new password without the old one, the new password then verifies and the old one no longer does, and a non-allowlisted account and `root` are refused. It passes **7/7**.
- `tests/run_chain_docker.sh` proves the **full chained flow** on a disposable Samba with **real, disjoint portal/admin users**: a portal request, an admin approval over the admin socket, the authority issuing and (simulated-)sending the link, the portal consuming it over the portal socket, and the real `smbpasswd` reset. A second use of the token fails and a revoked channel kills an issued link. It passes **16/16**.

### 4. Image build check

The images and integration behavior should be verified on each target architecture. A Linux x86-64 host has been used for an actual test deployment; that does not establish compatibility across operating systems or CPU architectures.

A second, older guard (`tests/integration_disposable.py`) **refuses to run unless `SAMBA_SERVER` is set to the disposable test value `samba-ensayo`**, so it cannot accidentally target a real account. It is not part of default `unittest` discovery either. Do not test against actual family accounts.

The interface was checked in a desktop browser and a simulated narrow viewport; physical mobile devices, screen readers and a complete accessibility audit remain unverified. Test the production image behind HTTPS, including cookies, access restrictions, firewall compatibility with `SAMBA_SERVER`, and saved client credentials.

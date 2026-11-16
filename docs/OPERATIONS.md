# Operations: forgotten-password recovery

**Who this is for:** the person who runs the server. If you only want people to change a password they already know, you can skip this guide: that part needs no privileged component (see [installation](INSTALL.md)). Come here when you want to let people ask for help with a *forgotten* password, and you are prepared to approve each request yourself.

**How to read it:** the capability matrix tells you what exists and how it was tested; sections 1 to 8 explain how it fits together and how to configure it; sections 9 to 13 say what is not finished and which risks remain. Skim the last part before you enable anything.

This guide describes how to deploy the optional recovery feature. **Recovery is
disabled by default** (`RECOVERY_MODE=disabled`); nothing here is needed unless
you enable it. The privileged reset boundary is described in
[RECOVERY-DESIGN.md](../RECOVERY-DESIGN.md); this document covers the
operator-facing parts.

> Status: the security core is implemented and tested. The web `/recovery` and
> `/reset` routes **are** wired to the authority in `approval` mode and the full
> supervised flow is tested end to end (`tests/test_web_recovery.py`, a real
> authority over a Unix socket and a real `DeliveryWorker`, network faked). The
> **entire chain** -- request, admin approval over the admin socket, authority
> delivery, portal consume, real `smbpasswd` reset -- is proven on a disposable
> Samba by `tests/run_chain_docker.sh` (**16/16**). A channel change or revoke
> now invalidates an issued link (`store.py`). The `TelegramPoller` pauses for
> `TELEGRAM_POLL_INTERVAL`, is interruptible, and backs off on failure. The
> authority creates its persistent data dir before opening the ledger and refuses
> a volatile location. Recovery is **disabled by default** and must not be
> treated as production-ready until independent review is done; the residual
> risks (section 13) remain, in particular that an *active* compromised portal
> can capture a token at use time.

## Capability matrix

| Capability | State | Evidence |
|---|---|---|
| Privileged authority, MINT/ISSUE/CONSUME protocol | Implemented, tested | `tests/test_reset_auth*.py`, `tests/test_reset_auth_socket.py` |
| Separate portal / authority stores | Implemented, tested | `tests/test_store.py` |
| Authority owns channels + delivery (portal cannot inject/divert) | Implemented, tested | `tests/test_recovery_adversarial.py`, `tests/test_reset_auth_socket.py` |
| Destination pinned at approval; a binding change denies the request | Implemented, tested | `tests/test_reset_auth.py`, `tests/test_web_recovery.py` |
| Raw token never persisted (generated at ISSUE) | Implemented, tested | `tests/test_store.py` (reads db+WAL bytes) |
| Expired requests free the caps; periodic purge | Implemented, tested | `tests/test_store.py`, `tests/test_reset_auth.py` |
| Canary credential verifier (guest-forbidden) | Implemented, tested | `tests/test_auth.py`, real Samba `run_verify_docker.sh` (5/5) |
| Guest-forbidden preflight gates channel binding | Implemented, tested | `tests/test_channels.py`, `run_leak_docker.sh` (phase 1 5/5; phase 2 is a by-design negative control) |
| Channel management (email + Telegram bind), admin-only | Implemented, tested | `tests/test_channels.py`, `tests/test_telegram.py`, `tests/test_admin.py` |
| Telegram chat id only from a verified private conversation | Implemented, tested | `tests/test_telegram.py` (incl. `TelegramPoller` with injectable `getUpdates`) |
| No web route accepts a destination | Implemented, tested | `tests/test_channels.py` (portal service + web url_map) |
| Recovery service (uniform, non-enumerating, rate-limited) | Implemented, tested | `tests/test_recovery_integration.py` |
| End-to-end web recovery (request→approve→deliver→consume) | Implemented, tested | `tests/test_web_recovery.py` (real app + authority + worker, network faked) |
| SMTP / Telegram delivery | Unit-tested with simulated network; also exercised with live providers for a dedicated test account on one host | A failed delivery is tested to revoke the token; provider compatibility varies |
| Authority daemon serves sockets + delivery worker + Telegram poller | Implemented, tested | `tests/test_authority_main.py` (faked identities; real-identity proof below) |
| Privilege separation (real peer check, socket ownership, group roles) | Implemented, proven on Linux | `tests/run_privsep_docker.sh` (**18/18**, exercises `serve_sockets` + `check_separation`; non-vacuous approve-refused + still-pending, supplementary-group breach, fail-closed separation, admin-only channel enrollment) |
| Real-Samba password change | Implemented, proven on disposable Samba | `tests/run_integration_docker.sh` (**6/6**) |
| Log redaction (no path/query in access log) | Implemented, tested | `tests/test_log_redaction.py` |
| Live-Samba forgotten-password reset (`smbpasswd -s`) | Real transport proven on disposable Samba (**7/7**) | `tests/run_reset_docker.sh`: sets a new password without the old one (new verifies, old fails; non-allowlisted and `root` refused) |
| **Full chained flow** (request→approve→deliver→consume→`smbpasswd`) | **Proven end to end on disposable Samba (16/16)** | `tests/run_chain_docker.sh`: real authority, real disjoint portal/admin users, simulated delivery captures the authority-issued link, real `smbpasswd` reset; second use fails; a revoked channel kills an issued link |
| Telegram bot loop (`TelegramPoller`, real `getUpdates`) | Unit-tested with injected network and exercised with a live bot on one host | `tests/test_telegram.py`; started by `authority_main.run()` when a bot token is set |
| `RECOVERY_MODE=automatic` | **Blocked by design** | refused at startup |

## 1. Decide the policy

* `disabled` (default): the `/recovery` and `/reset` pages are inert. This is
  the safe default.
* `approval`: an administrator approves each request out of band. This is the
  only enabled non-default policy.
* `automatic`: **not enabled.** A portal that can read channel bindings cannot
  re-bind them, so a fully compromised portal is trusted for delivery; automatic
  recovery is therefore not secure. Setting `RECOVERY_MODE=automatic` makes the
  application fail closed (HTTP 503) with an explicit error.

## 2. Deploy the privileged authority

The authority runs on the Samba host as `root` and listens on two **Unix
sockets**, never TCP:

* a *portal* socket the web container connects to for `MINT`, `VALIDATE`,
  `CONSUME` (the portal **never** issues, revokes or enrolls a channel -- it
  only requests and completes);
* an *admin* socket that only the operator's approval and enrollment tool
  connects to for `APPROVE`, `DENY`, `LIST` and `CHANNEL_*`.

Role is decided from the peer's Unix credentials (`SO_PEERCRED`): the portal
runs as a fixed, unprivileged user mapped to `PORTAL`; an operator in the
configured admin group is mapped to `ADMIN`. The two are disjoint, so a portal
process can never approve or enroll. The admin socket is **not mounted** into
the web container, so the portal has no path to approve or to bind a channel.

**The authority owns the channel bindings and the delivery.** The web portal
mints a request carrying the account and selected channel type (no destination,
no token); the
authority resolves the destination from its own store, pins a binding
fingerprint at approval, issues the token and sends the link itself (the
`DeliveryWorker` runs in the authority process). The web container therefore
never holds a token, a destination, or a write path to a binding. A portal
rewrite of its own store, a binding change after approval, or a raw
`PORTAL`-socket attempt to approve/issue/enroll are all refused.

The authority owns its **own** SQLite ledger (root:root, mode `0600`); the web
container has no write path to it. The portal keeps its own separate store only
for rate-limit counters.

The authority's `CONSUME` is the **only** place a password reaches `smbpasswd`.
It receives the new password over the socket and runs `smbpasswd -s <user>` with
the password on a **pipe file descriptor** (never argv, environment, or disk).

## 3. Guest-forbidden verification share

Reauthentication (binding a channel, and the verifier's canary) uses
`smbclient` against a **guest-forbidden** share:

```
[skverify]
   path = /srv/skverify
   browseable = no
   writable = no
   guest ok = no
```

With `guest ok = no`, a globally mapped guest can never complete the connection,
so an empty or wrong password fails identically under any `map to guest`
setting (verified for `never`, `Bad User`, `Bad Password`). Do **not** rely on
`guest ok = yes`: under `Bad Password` it maps a bad password to a guest and a
wrong password would *succeed*, opening recovery to anyone who guesses the
username. The verifier runs a canary at startup (a random nonexistent user must
fail); if it ever does not, reauthentication must be disabled.

The new password is delivered to `smbpasswd` through a **stdin pipe** (written
as the password and its confirmation, `new\nnew\n`), never through argv, the
environment, a file, or a log, and is independent of any TTY. This is proven
against a disposable Samba by `tests/run_reset_docker.sh` (**7/7**): a privileged
reset succeeds without the old password, the new password then verifies and the
old one no longer does, and a non-allowlisted account and `root` are refused.

## 4. Channels

In this design the **authority owns the channel bindings**; the portal cannot
create, change or read a destination (section 2), and there is **no web route
that accepts a destination**. Enrollment is therefore **admin-driven**
(section 10): an operator binds a verified channel through the admin socket, with
a one-time challenge that proves control of the destination.

This is the crux of the "a compromised portal cannot divert a link" guarantee:
the destination lives only in the authority store, the request carries no
destination, and a binding change **invalidates the account's in-flight
requests -- including any already-issued link**, so a destination cannot be
swapped in after approval and a revoked channel kills a link that was already
sent. `consume_token` re-checks the binding fingerprint pinned at approval under
the store lock (defense in depth), so a change that slipped past the
invalidation still defeats the link. The residual risk is narrower than before:
an *active* compromised portal can only capture the token at use time (section
13); it cannot inject a binding, divert an approved request, or resurrect a link
after the channel is revoked. Pinned by `tests/test_store.py` and
`tests/test_delivery_worker.py`.

E-mail is verified with a one-time, short-lived code (only its SHA-256 digest is
stored). Telegram binding uses a one-time code the user sends to the bot in a
*private* conversation; the authority-side `TelegramPoller` learns the chat id
from that verified conversation, never from a web request. A user who has
forgotten their password cannot reauthenticate, so their enrollment or approval
must be confirmed by an administrator out of band.

## 5. Delivery

After an admin approves a request, the **authority-side `DeliveryWorker`**
resolves the destination from the authority's own bindings, issues the token and
sends the link. The portal does not receive the token during issuance or delivery; it receives the token when the user opens and submits the recovery form. The `DeliveryWorker` runs as a
periodic loop inside `authority_main.run()`. Delivery is idempotent and bounded;
a link is issued **exactly once** per approved request and is short-lived
(~15 minutes, single use). A request with no binding, or whose binding changed
since approval, is moved to `denied` and not delivered. If a send fails after
the token is issued, the token is revoked so the lost link cannot be used.

## 6. Keeping secrets out of logs

The recovery token travels in a **URL fragment** (`/reset#t=...`), which is
not sent in the initial HTTP navigation request or in the Referrer. Browser JavaScript submits it to the portal over HTTPS for validation and reset, so the portal receives it and a compromised portal can capture it. The
server never places a token in a path or query. As defence in depth, the
shipped `gunicorn.conf.py` uses an access-log format **without path or query**,
so an accidental token in a URL is not written to the access log (covered by a
test that inspects the captured output). Operators must also ensure any proxy in
front of the portal does not log request bodies.

## 7. Configuration summary

| Variable | Default | Meaning |
|---|---|---|
| `RECOVERY_MODE` | `disabled` | `disabled`, or `approval`. `automatic` is refused. |
| `RECOVERY_SOCKET` | — | portal→authority socket (required for `approval`) |
| `RECOVERY_ADMIN_SOCKET` | `AUTHORITY_DIR/admin.sock` | authority admin socket for the operator tool; falls back to `<AUTHORITY_DIR>/admin.sock` when unset, but set it explicitly in production |
| `AUTHORITY_SPLIT_SOCKETS` | `false` | Set to `true` on the authority to create the portal socket at `AUTHORITY_DIR/portal/portal.sock`, separate from `admin.sock`; mount only the portal subdirectory into the web container and set its `RECOVERY_SOCKET` accordingly. Ensure the host runtime directory survives an authority restart and exists before the portal starts. |
| `AUTHORITY_DIR` | `/run/samba-key` | runtime dir for the two sockets (may be volatile; sockets are recreated on start) |
| `RECOVERY_DATA_DIR` | `/var/lib/samba-key` | **persistent** dir for the ledger/bindings (`0700`); a volatile location (`/run`, `/var/run`, `/tmp`) is refused at startup |
| `BASE_URL` | — | admin-specified HTTPS origin for links (required for `approval`); never taken from request headers |
| `RECOVERY_REQUEST_TTL` / `RECOVERY_LINK_TTL` | 1800 / 900 | pending request / issued link lifetime; reached by the authority, not module defaults |
| `MAX_PENDING_GLOBAL` / `MAX_PENDING_PER_ACCOUNT` | 50 / 1 | caps on outstanding requests; reached by the store |
| `RECOVERY_CLIENT_TIMEOUT` | 3 | portal→authority timeout for ordinary requests; password-reset requests allow 25 seconds for `smbpasswd` |
| `RECOVERY_CLIENTS_LIMIT` | 20000 | maximum number of active client identities tracked for recovery; expired identities and counters are pruned |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` | — | e-mail delivery |
| `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_SENDER` | — | SMTP credentials; prefer `SMTP_PASSWORD_FILE` (a root-owned `0600` file) over the environment variable; `SMTP_SENDER` defaults to `SMTP_FROM` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_API_BASE` | — / `https://api.telegram.org` | Telegram delivery; prefer `TELEGRAM_BOT_TOKEN_FILE`; the token lives only in the authority process, **never** in the portal container's environment |
| `TELEGRAM_POLL_INTERVAL` | 3 | seconds between `getUpdates` polls (minimum 1); the loop backs off exponentially on failure and honors `retry_after` |
| `RECOVERY_ELIGIBLE_FILE` | `/etc/samba-key/eligible.accounts` | root-owned allowlist of accounts the authority may reset; unreadable ⇒ empty allowlist (fail closed) |
| `VERIFY_SHARE` | `skverify` | guest-forbidden share for reauthentication |

> The previously documented `AUTHORITY_STORE` and `CHANNEL_STORE` were dead
> options and have been removed: the ledger lives under `RECOVERY_DATA_DIR` and
> the portal keeps only its own rate-limit counters (`PORTAL_STORE`).

> **Secrets live in the authority, not the portal.** `SMTP_PASSWORD`/`_FILE` and
> `TELEGRAM_BOT_TOKEN`/`_FILE` are read by the authority daemon; the portal
> container is not given these values, and `Config.public()` (the `/healthz`
> summary) and the redacted access log never contain them (tested).

On Linux, `sudo python3 tools/save-secret.py telegram` or
`sudo python3 tools/save-secret.py smtp` stores a newly entered secret in
`/etc/samba-key/secrets/` with root-only permissions. The input is hidden and
the helper refuses to overwrite existing files. Set `TELEGRAM_BOT_TOKEN_FILE`
or `SMTP_PASSWORD_FILE` to the resulting path in the **authority** service.
The helper is for the server administrator; family members do not need it.

If the authority connection fails while a password reset is in progress, the
portal reports that the outcome is **unconfirmed**. The user should try the new
password before requesting another link; a timeout alone cannot establish
whether `smbpasswd` completed.

## 8. Upgrade and rollback

* **Rollback** to the disabled state is simply `RECOVERY_MODE=disabled` (or
  unset): the inert pages return and no new capability is exposed.
* Before enabling `approval`, confirm the authority and admin socket are in
  place, the verification share exists and is guest-forbidden, and at least one
  delivery provider is configured.
* Rebuild images from pinned, digested base images in a change management
  process; keep a known-good image for fast rollback.

## 9. Current status: what is wired, and what is not (not yet for production)

**Wired and tested** (with only the network boundary faked, and the privileged
reset proven against a disposable Samba):

* The web `/recovery` and `/reset` routes are wired to the authority in
  `approval` mode; the full supervised flow (request → approve → deliver →
  consume) is tested end to end with the real app, a real authority over a Unix
  socket, and a real `DeliveryWorker` (`tests/test_web_recovery.py`).
* The **live-Samba privileged reset** (`smbpasswd -s <user>` via
  `reset.make_reset_fn`, new password on a stdin pipe) is proven against a
  disposable Samba by `tests/run_reset_docker.sh` (**7/7**).
* The **full chained flow** -- a portal request, an admin approval over the admin
  socket, the authority issuing and (simulated-)sending the link, the portal
  consuming it over the portal socket, and the real `smbpasswd` reset -- is
  proven end to end on a disposable Samba with real disjoint portal/admin users
  by `tests/run_chain_docker.sh` (**16/16**). A second use of the token fails
  and a revoked channel kills an issued link.
* The `TelegramPoller` loop (with a real, network-injectable `getUpdates`) is
  started by `authority_main.run()` when a bot token is configured
  (`tests/test_telegram.py`).

**Not wired (by design or pending):**

* User-enrollment **web** routes do not exist on purpose: enrollment is
  admin-only (section 10), because a user who forgot their password cannot
  reauthenticate, and a user who can reauthenticate is not the forgotten case.
* Automatic recovery is intentionally not implemented (section 1).
* **The full chained flow is now tested end to end** (`tests/run_chain_docker.sh`,
  **16/16**): a real authority serving real portal/admin sockets to real, disjoint
  users; a *simulated* delivery captures the link the authority issues; the
  portal's CONSUME runs the *real* `smbpasswd -s` reset; the new password verifies
  and the old fails; a second use fails; and revoking a channel after issue kills
  the link. What remains simulated/unverified is listed below.
* Live SMTP and Telegram have been exercised with a dedicated test account on one
  host; compatibility with other providers has not been established.
* There has been no independent security review, physical-mobile-device or screen
  reader review. Desktop and simulated narrow viewport checks do not replace them.
  Verify images and behavior on each target architecture.

Recovery is **disabled by default**.

**Can `RECOVERY_MODE=approval` be enabled?** In a *disposable or test*
environment, yes: with a configured `RECOVERY_SOCKET`, an HTTPS `BASE_URL`, a
persistent `RECOVERY_DATA_DIR`, and a real separation check passing (proven 18/18
in the disposable Linux container). In **production**, only after: an independent
review; verified SMTP and Telegram delivery for the intended providers; a real-host privilege
separation check; a confirmed persistent data dir; and an explicit owner decision
on the active-portal limit (section 13). Until then, keep it `disabled`.

Note on the authority tests: the authority's socket behaviour is unit-tested with
*simulated* identities; the *real* Linux peer-credential separation is proven only
in the disposable container (`tests/run_privsep_docker.sh`, 18/18).

## 10. Initial enrollment (how to add a channel for a user)

### Private contact directory

An administrator may maintain a local TOML address book using
`examples/contacts.toml.example` as a template. Install the actual file as
`/etc/samba-key/contacts.toml`, owned by the administrator who runs the
commands, with mode `0600`; keep it outside the repository and backups that
are not protected for personal information. Each `[[users]]` entry contains a
Samba `username` and optional `name`, `email` and `phone`. A contact is not
automatically eligible for recovery: the account must separately be on the
authority's allowlist.

Run `python3 -m samba_key.contacts list` or `show USER` as that administrator.
To begin enrollment, run `python3 -m samba_key.contacts enroll USER email`
or `enroll USER telegram` with access to the authority's admin socket. The
one-time code is shown to the administrator and expires. For Telegram, deliver
the code to the intended person through an independently authenticated channel;
they send `/start CODE` to the bot in a private conversation. The stored phone
number is informational: it cannot identify or verify a Telegram chat.

For email, independently confirm that the person controls the address and
obtain confirmation of the enrollment challenge before using
`python3 -m samba_key.contacts verify USER email`, which prompts for the code
without displaying it. The contacts command does **not** send an email
verification challenge itself, so independently verifying the destination is
an operator responsibility. Adding or editing the file does not activate or
update a recovery channel; enroll and verify the new channel explicitly. An
already bound old destination remains active until explicitly revoked or
replaced through the authority's administrative commands.

Enrollment is **admin-driven** through the `samba-key-admin` CLI over the admin
socket. A user cannot enroll a destination from the web: there is no web route
that accepts a destination, so a compromised portal cannot inject one. Use
generic values in examples; never record a real address.

* **E-mail.** The operator runs
  `samba-key-admin channel add <account> email <address>`. The authority
  creates a one-time, short-lived code and **returns it to the operator**;
  control of the mailbox is **attested by the administrator** (the out-of-band
  confirmation), which is why a forgotten password is not by itself sufficient.
  The operator relays the code to the user (the `ChannelEnroller.add_email`
  path can also send it through a configured SMTP transport), the user reads
  it and gives it back, and the operator runs
  `samba-key-admin channel verify <account> email <address> <code>`. The
  challenged address must match the verified address.
* **Telegram.** The operator runs `samba-key-admin channel add <account>
  telegram` and gives the returned code to the user. The user sends `/start
  <code>` in their **private** chat with the bot. The authority-side
  `TelegramPoller` learns the chat id from that verified conversation and binds
  it (never from a web request).
* **Revoking or changing** a channel (`channel remove`, or re-adding) is
  admin-only and **invalidates the account's in-flight requests**, so a
  destination cannot be swapped in after approval. Notify the user out of band.
* **A user who has forgotten their password** cannot reauthenticate, so an
  administrator must confirm identity through an independent channel before
  enrolling or approving. Self-asserted phone numbers, e-mail addresses and
  family facts are not sufficient on their own.

## 11. Recovering from failures

* **Authority down.** The portal answers every recovery request with the same
  uniform message and does not hang: `ResetClient` has a receive timeout
  (default **3 s**, configurable via `ResetClient(socket, recv_timeout=...)`) and
  returns a failure, which the portal renders as the generic message. Lower the
  timeout further behind a reverse proxy. No request is lost: pending requests
  survive a restart in the authority store and are picked up when it comes back.
  No reset can happen while the authority is down.
* **Purge.** Expired requests, issued-but-unused links and spent challenges are
  removed by `Store.purge_expired`, run at the start of each delivery cycle. A
  request with no binding, or whose binding changed after approval, is moved to
  `denied` (not delivered).
* **Revoke / re-approve.** To force a user to start over, the operator runs
  `samba-key-admin deny <handle>` (or changes the channel, which invalidates
  in-flight requests). A fresh request needs a fresh approval.
* **Backups.** Back up the authority `secret/` directory (mode `0700`, root)
  and the eligible-accounts file; on restore, replace the store atomically while
  the authority is stopped. Never copy the store into source control.

## 12. Access and network

* Recommend serving the portal over a **private network such as Tailscale, with
  HTTPS**. Tailscale is **recommended, not mandatory**; any private network or a
  reverse proxy that terminates TLS and hides the origin is acceptable, and the
  service must never expose a public listener by default.
* The recovery link is built from the **administrator-specified HTTPS**
  `BASE_URL`, never from the `Host` or `X-Forwarded-*` headers of an incoming
  request. Behind a proxy, set `BASE_URL` to the public HTTPS origin.
* **Proxy `remote_addr` note:** the in-process rate limiter keys on
  `request.remote_addr`, which is the proxy's address behind a reverse proxy,
  so one limit is shared across all its clients unless the proxy is configured
  to present per-client addresses. Do not trust `X-Forwarded-For` from clients.

## 13. Residual risks (accepted, mitigated operationally)

* **The exchange page is portal-served.** When a user completes a reset they
  type the link token and the new password into a form the *portal* renders,
  so an *actively* compromised portal can capture the token at that moment and
  use it before or instead of the user. The authority boundary stops a
  *passive/inactive* portal from obtaining the link at delivery, diverting an
  approved request, or injecting/altering a binding -- but not an active portal
  serving the exchange page. A separate, more-privileged exchange process could
  close this gap; it is out of scope. Pinned by
  `tests/test_recovery_adversarial.py` and written in `RECOVERY-DESIGN.md`.
* **Crash between issue and send.** If the worker dies after issuing the token
  and before sending, the token stays live until its TTL: a restart will not
  re-send it and cannot revoke it (revoke only fires on a caught send
  exception). Bounded by the short link TTL. Pinned by a test.
* **Compromised authority.** A compromised authority can reset any allowlisted
  account; treat the authority host as a high-value target. A web-container
  escape would be at least as severe, so privilege separation does not replace
  host hardening and independent review.
* **Timing.** The response to a recovery request is byte-for-byte uniform, but
  a mint and store writes happen only for eligible accounts, a residual
  unmitigated timing signal.
* **`handle` plaintext.** The `handle` is plaintext in the authority store; it
  is not secret (approval and the one-time code are what matter), but it is the
  one identifier that is not digested.
* **Delivery failure after issue.** The token is revoked (the issued request is
  moved to `denied`) and the user must request again, which needs a fresh
  approval. By design.

Recovery reduces risk; it does not eliminate it.

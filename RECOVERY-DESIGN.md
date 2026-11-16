# Recovery design

## In plain words

Changing a password you *know* is easy to do safely: you prove who you are by
typing the old one. Helping someone who has *forgotten* it is the hard part,
because the system has to change a password without that proof. Whatever does
so must be powerful, and powerful things need careful limits.

This document explains the choices behind Samba Key's optional recovery:

- **Who is allowed to reset what.** Only a small, separate program (the
  *authority*) can reset a password, and only for accounts on an explicit list.
- **Who decides.** A human administrator approves each request, after
  confirming by some other route that it really is that person.
- **How the person gets back in.** A short-lived, one-use link, sent by the
  authority (not the web page) to a contact channel the administrator verified.
- **What can still go wrong.** The residual risks are listed openly at the end.

Read it top to bottom if you are deciding whether to enable recovery; the
operator-facing steps are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Overview

Samba Key changes a Samba password with the current password. It also
implements **optional, disabled-by-default** forgotten-password recovery
as described below. The live-Samba reset has been exercised with a test account; an independent security review remains outstanding. When **disabled** (the default) the
`/recovery` and `/reset` routes return one uniform page for every input and for
both GET and POST, so they never reveal whether an account or channel exists;
that page does not render the change-password form (submitting a form that
performs nothing would mislead users) and links back to the working change
page. In **approval** mode the routes are wired to a privileged authority that
resolves the destination, issues the token and sends the link (see the
"Implementation status" section below). The live-Samba privileged reset and the
full chained flow are proven against a disposable Samba (`tests/run_reset_docker.sh`
7/7, `tests/run_chain_docker.sh` 16/16); recovery stays disabled by default.

Note on the change flow: the configured minimum and maximum password length constrain the **new** password only, so a user whose current Samba password is shorter than the minimum or longer than the new-password maximum can still change it to a compliant one. The current password is bounded only by a separate, generous technical cap (`MAX_CURRENT_PASSWORD_LENGTH`, default 4096 bytes): it must be non-empty, free of control bytes, and within that cap, but it is never forced to satisfy the new-password policy.

## Product goals

- Responsive browser interface for phones, tablets and desktop computers; English and Spanish initially.
- Portable container on supported CPU architectures, connecting to a standalone Samba instance over the network. Verify actual image builds and Samba compatibility on each target before claiming support.
- Recommend access over a private VPN such as Tailscale, using HTTPS. Do not require Tailscale and do not expose a public listener by default.
- Each installation may enable email, Telegram, both or neither. The implemented recovery policy requires administrator approval; automatic recovery is not implemented.
- Existing change-password functionality remains available independently of recovery.

## Enrollment

Channel enrollment is administrator-driven. The administrator independently verifies the person's identity and control of the destination; the web portal has no self-service channel-management route. For email, the operator must arrange verification out of band; the contacts helper does not itself send a verification challenge. For Telegram, the user sends a short-lived enrollment code to the bot in a private conversation, and the authority binds the numeric chat ID. A phone number, email address or family fact alone is not proof of identity. A change or revocation invalidates pending requests. Never send passwords to a bot, email or logs. Notifications of channel changes are not currently implemented.

## Recovery

Requesting recovery produces a uniform response even if an account or channel does not exist. Send a cryptographically random, one-use link to a previously verified destination; expire it quickly and store only its digest. Restrict the configured base URL to an administrator-specified HTTPS origin; never derive recovery URLs from Host or forwarded headers. Avoid URL tokens in access logs, analytics, third-party requests and referrer headers. Use generic messages, bounded per-account and per-client rate limits and delivery quotas.

Automatic mode is not implemented. In approval mode, the request enters a pending state; a separately authenticated administrator approves it before a reset is possible. Approval cannot use the same forgotten-password route as the requesting user. A request is invalid after expiry or use; atomically consume it before privileged changes, with a documented safe retry flow. Avoid letting a link-scanning bot consume the token with a GET request.

## Privileged reset boundary

The existing unprivileged Samba client cannot reset a forgotten password. A separate, tightly scoped privileged component is necessary for standalone Samba. Its interface must permit password resets only for an explicit allowlist of eligible Samba accounts, prohibit arbitrary commands and arguments, use a narrowly permissioned local socket, and validate authorization independently; it must not mount the Docker socket or grant general sudo rights. Treat compromise of the reset authority as capable of compromising those eligible Samba accounts. A normal web-container escape would be more severe, so privilege separation does not replace hardening and independent review.

Threat-model the complete protocol and storage before implementation, including authorization between components, replay and concurrent attempts, transport encryption, secret rotation, admin bootstrap/revocation, event logging without credentials, error handling, power loss, throttling and host restore. Pin and update dependencies. Automatic recovery is disabled until all of these are tested end-to-end.

## Provider details

SMTP uses TLS with certificate validation. Telegram bots require a user to start the private conversation; phone number alone is not a chat ID. Configure separately issued SMTP credentials and follow your provider’s sender and domain authentication requirements. No real addresses, passwords or bot tokens belong in the repository. Store deployment secrets outside source control and limit access to them.

## Acceptance tests

In isolated infrastructure, test valid and invalid enrollment, both delivery providers, delivery failure, invalid/expired/replayed tokens, access by another user, tampered host headers, concurrent submission, non-enumeration, rate limiting, administrator approval and denial, account allowlists and denial of arbitrary reset targets. Verify with the real standalone Samba protocol and independently review the reset component before production use.

---

## Implementation status and final threat model

Samba Key implements the recovery feature as an **opt-in, disabled-by-default**
capability and leaves it inert in the web process when disabled. Details and
operator steps are in [docs/OPERATIONS.md](docs/OPERATIONS.md). In the
**disabled** build (the default) the `/recovery` and `/reset` routes render one
uniform page that never reveals whether an account or channel exists. In
**approval** mode the routes are wired to a privileged authority: the portal
mints a request (no destination, no token), an administrator approves it on a
separate socket, and an authority-side `DeliveryWorker` issues the token and
sends the link. `automatic` recovery is refused at startup. The *live-Samba*
privileged reset is **proven against a disposable Samba** by
`tests/run_reset_docker.sh` (**7/7**), and the **full chained flow** (request,
admin approval, authority delivery, portal consume, real `smbpasswd` reset, a
second-use failure, and a revoked-channel kills the link) by
`tests/run_chain_docker.sh` (**16/16**); recovery stays disabled by default until
independent review is done.

### What is implemented and tested
- **Privileged authority** (`samba_key/reset_auth.py`) with a **handle / ISSUE**
  protocol: `MINT` returns only a random handle; `ISSUE` releases the secret
  exactly once, only when the request is `approved`; `CONSUME` is single-use and
  kind-checked. Role is gated by peer credentials (`SO_PEERCRED`): the portal
  user is `PORTAL`; the operator's group is `ADMIN`. A portal process can never
  approve.
- **Separate stores.** The authority owns its own ledger (root:root, `0600`);
  the authority holds channel bindings; the portal keeps separate rate-limit
  and local state. The portal has no write path to the approval ledger.
- **Out-of-band approval** (`samba_key/admin.py`): a local CLI connecting to the
  admin socket the portal does not mount. No admin password is stored; the OS
  group is the identity.
- **Credential verifier** (`samba_key/auth.py`): reauthentication via
  `smbclient` against a **guest-forbidden** share, with a startup **canary** (a
  random nonexistent user must fail). The password is delivered through a
  **private pipe fd (`PASSWD_FD`)**, never the environment or argv; a container
  test proves it is absent from `/proc/<pid>/environ`.
- **Channel management** (`samba_key/channels.py`): binding requires
  administrator-driven enrollment with one-time, short-lived, single-use challenges; no user-facing channel-management route is exposed.
- **Recovery service** (`samba_key/recovery.py`): uniform, non-enumerating
  responses; per-account and per-client rate limits; delivery only after
  approval; idempotent, bounded.
- **Log redaction**: the token is initially carried in a **URL fragment**, which browsers do not send in the navigation request; JavaScript then submits it to the portal over HTTPS for validation and use; the shipped Gunicorn config logs **no path or query**, and a test
  inspects the captured output for a sentinel in path and query.
- **Concurrency and caps** are covered by multithreaded and cap tests; the
  real-Samba verifier matrix and leak/canary/negative-control checks run in
  disposable containers.

### What is intentionally NOT enabled or wired
- **Automatic recovery** is not implemented: a portal that can read channel
  bindings cannot re-bind them, so a fully compromised portal would be trusted
  for delivery. `RECOVERY_MODE=automatic` is refused (fail closed).
- User-enrollment **web** routes do not exist on purpose: enrollment is
  admin-only, because a user who forgot their password cannot reauthenticate.

The *live-Samba* privileged reset (`smbpasswd -s`, new password on a stdin pipe)
is **proven against a disposable Samba** by `tests/run_reset_docker.sh` (**7/7**),
and the `TelegramPoller` loop (with a real, network-injectable `getUpdates`)
is started by `authority_main.run()` when a bot token is configured.
Recovery is disabled by default and must not be enabled in production until an
independent review confirms the residual risks are acceptable.

### Residual risks (accepted, with mitigation)
- The redesign **removes** the old "compromised portal injects a binding or
  diverts an approved link" risk: the authority owns the channel bindings and the
delivery, the request carries no destination, and a binding change invalidates
  in-flight requests, so a portal cannot move a link. What a *passive* or
  *inactive* compromised portal cannot do is covered by adversarial tests; what an
  *active* one still can is below. The mitigations that remain are operational:
  the operator confirms the requester out of band before approving, and the
  authority host is access-controlled. Recovery reduces risk; it does not
  eliminate it.
- The approval decision depends on the operator correctly identifying the
  requester; the system prevents self-approval but not human error.

- **The exchange page is served by the portal (cannot be fully removed here).**
  When a user completes a reset they type the link token and the new password
  into a form the *portal* renders. That request body passes through the portal
  process, so an *actively* compromised portal can read the token at that moment
  and use it before or instead of the user. The authority boundary stops a
  *passive* or *inactive* portal from obtaining the link at delivery time, from
  diverting an approved request, and from injecting or altering any channel
  binding -- but it cannot stop a portal that is actively serving the exchange
  page. A separate, more-privileged exchange process could close this gap; it is
  out of scope for this build. `tests/test_recovery_adversarial.py` pins this
  property so no future change advertises a stronger guarantee than holds.

## Hardening after review (12 November 2026)

- **Token storage.** The user-facing token is *generated inside `Store.issue()`*
  and only its SHA-256 digest is written; the raw token is never persisted in any
  store file (db or WAL), tested by reading the raw bytes. The `handle` is the
  one identifier kept in plaintext (it is not a secret: approval and the one-time
  binding code are what matter).
- **Delivery failure.** If a delivery fails after the token is issued, the
  authority-side `DeliveryWorker` calls `REVOKE`, which moves the issued request
  to `denied` so the lost link can no longer be consumed; the user must request
  again (a fresh request needs a fresh approval).
- **Privilege separation (proven).** The authority serves two sockets with
  effective ownership: `portal.sock` is `root:portal_group 0660` and
  `admin.sock` is `root:admin_group 0660`, and the ledger database lives in a
  `0700` root directory. Role is fixed by *which* socket was used
  (`forced_role`) with `SO_PEERCRED` as a backstop; the peer's *supplementary*
  groups are resolved (`SO_PEERCRED` gives only the primary gid). `Config` and
  `validate_separation` refuse to start if the portal uid is root or the portal
  groups intersect the admin groups. `tests/run_privsep_docker.sh` proves on a
  disposable Linux container, with real created users and no docker socket: the
  portal is denied the admin socket, can MINT on its own socket, cannot approve
  or enroll a channel, cannot read the authority DB; the admin can reach the
  admin socket, can approve, and can enroll a channel; a user in neither group
  reaches neither socket; and an overlapping-identity negative control is
  detected. **18/18.**
- **Telegram.** A chat id is bound only by `TelegramBinder.process_update` (called
  by the authority-side `TelegramPoller`), from a verified *private*
  conversation (`from.id == chat.id`, positive int, `/start <code>`); a web route
  never accepts a chat id. The `TelegramPoller` loop is tested with an injectable
  `getUpdates`, **starts the daemon when a bot token is configured**, and pauses
  for `TELEGRAM_POLL_INTERVAL`, is interruptible, and backs off on failure.
- **Real-Samba reset.** `smbpasswd -s <user>` with the password on a stdin pipe
  is unit-tested with an injected transport (`tests/test_reset.py`); the normal
  password-change flow is proven against a disposable Samba
  (`tests/run_integration_docker.sh`, 6/6), and the forgotten-password reset path
  is proven both in isolation (**7/7**) and in the **full chain (16/16)**.

# Recovery: authority-owned channels + delivery (threat-model redesign)

> **Historical planning document.** This is the plan that was written before
> the recovery redesign was implemented, kept as an example of planning with a
> coding agent. The implemented behaviour, and the evidence for it, are in
> [RECOVERY-DESIGN.md](../../../RECOVERY-DESIGN.md) and
> [OPERATIONS.md](../../OPERATIONS.md); where they differ, they win.

Recovery stays `disabled` by default.
This plan moves **channel ownership and delivery into the authority's trust
domain** so a compromised portal alone cannot (a) bind or alter a destination,
(b) obtain a recovery link, or (c) divert an approved request.

## Stages (small commits, tests alongside)

1. **Store** — authority store owns `channels` + `channel_challenges`; requests
   gain a `binding_fingerprint`; add `invalidate_requests_for_account`.
2. **Protocol** — `MINT(account)` (no channel); remove `ISSUE`/`REVOKE` from the
   portal ops; add admin `CHANNEL_ADD/VERIFY/REMOVE/LIST`; approval pins the
   binding fingerprint; delivery is authority-side.
3. **Delivery worker** — authority-side: resolve target from the authority store,
   `issue` + send (transports held by the authority), revoke on failure; refuse
   if the binding drifted since approval.
4. **Enrollment** — admin-initiated only: `samba-key-admin channel ...`; Telegram
   binder adapted to the authority store; delete/disable the portal self-service
   path so nothing looks supported.
5. **main() + reset_fn** — `check_separation` → `serve_sockets` + delivery worker
   + Telegram poller; real `reset_fn` = `smbpasswd` as root, password on stdin.
6. **Web routes** — `/recovery` → one `MINT`; `/reset` reads the fragment,
   clears it, `POST`s the token (never consumes on GET); uniform on authority
   down; normal change-password unaffected.
7. **Adversarial + failure tests** — portal refused ISSUE/REVOKE/CHANNEL_*/
   APPROVE; portal cannot read/write the authority DB incl. channels; destination
   tampering refuses delivery; portal-store tampering is irrelevant; no secret in
   any portal-accessible artifact; concurrency; restart; reset_fn failure.
8. **Docs** — threat model, capability matrix, admin enrollment runbook,
   failure recovery, reproducible test commands, optional Tailscale.

## Honest guarantees (state in docs)
- Portal alone cannot bind/alter a destination: bindings are admin-only, root store.
- Portal alone cannot obtain a link before the user submits it: token is generated
  and sent by the authority; the portal never receives it.
- Portal alone cannot divert an approved request: the destination is pinned at
  approval (fingerprint) and any binding change invalidates in-flight requests.

## Limitation (state in docs)
A compromised portal still sees the token and the new password the *user types*
into it (and normal-change passwords). It can use only a link the user actually
received and submitted; short TTL + single use bound the damage. Compromise of
the authority host or the admin group defeats everything; providers see links.

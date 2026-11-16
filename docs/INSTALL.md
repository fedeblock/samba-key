# Installation and configuration

Samba Key has two layers, and you can stop after the first one:

1. **The change-only portal** (section 1). A web page where people change a password they *know*. It is small, unprivileged and the part that has been tested the most. Most households only need this.
2. **Optional supervised recovery** (section 2). Help for people who *forgot* their password. It adds a privileged service, contacts, email or Telegram, and administrator approval. It is off by default and is a real step up in responsibility.

Examples are illustrative: replace names, domains and addresses, review your firewall and Samba settings, and test with a disposable account first. Samba Key is experimental and has not had an independent security audit.

## Find your path

| Your situation | What to do |
|---|---|
| Samba and Docker are on the same Linux machine | Follow section 1 as written. This is the tested setup. |
| Samba runs on another machine (a different Linux box, a VM) | Run the portal wherever Docker is, and set `SAMBA_SERVER` to the Samba host's name or address. The Samba host must accept connections from the portal (TCP 445). Only section 1 applies; recovery needs the authority on the Samba host. |
| You only have a Mac or a Windows PC | Run Samba Key and Samba on a Linux machine or VM and use the Mac or PC as a *client* (see [Client access](#client-access-to-files)). Running the portal itself under Docker Desktop or WSL2 is untested. |
| You want to hack on the code | Skip to [Developing locally](#developing-locally). |
| You want the recovery feature | Finish section 1 first, then read [operations](OPERATIONS.md) and section 2. |
| A NAS appliance, Active Directory or LDAP | Not validated. Do not assume it works. |

### A short checklist before you begin

- [ ] A Samba server you can reach, with accounts for the people who will use the portal.
- [ ] A private network and a way to give the portal HTTPS (the guide below uses Tailscale Serve as an example, but no particular VPN is required).
- [ ] A disposable Samba account to test with, so no real password is at risk.
- [ ] A rough plan for backups and for how you would turn the portal off.

## Supported environments and prerequisites

The tested server setup is standalone Samba on Linux with Docker and systemd. The normal password-change client can also target a reachable Samba server on another machine. Active Directory, LDAP, NAS-specific integrations, Windows-hosted Samba alternatives, rootless Docker, user-namespace remapping and cross-architecture builds have not been validated. Do not assume the Linux recovery authority runs on macOS or Windows: it uses Linux peer credentials, local Unix sockets and a local `smbpasswd` executable.

For administration and development, use Python 3.11 or newer and the pinned dependencies in `requirements.txt`. A Linux Docker host needs Docker, Samba client tools inside the image, a Samba server reachable on TCP 445, and a private HTTPS entry point. On macOS or Windows, one practical arrangement is a Linux server or VM running Samba Key and Samba; access the page using a browser and your private network client. Docker Desktop/WSL2 network behavior and host access differ from Linux: treat them as untested and verify the actual route and firewall instead of assuming `host-gateway` works.

## 1. Build and run the change-only portal

On the Docker host:

```sh
git clone https://github.com/fedeblock/samba-key.git
cd samba-key
docker build -t samba-key .
docker run -d --name samba-key --restart unless-stopped \
  --add-host host.docker.internal:host-gateway \
  -e SAMBA_SERVER=host.docker.internal \
  -p 127.0.0.1:18081:8080 samba-key
```

`RECOVERY_MODE` defaults to `disabled`: this exposes only the known-password change. `host.docker.internal` here refers to the **Docker host**, not the visitor's computer. Samba must listen on a reachable address and permit the container's source address; inspect your existing `interfaces`, `bind interfaces only`, `hosts allow`, firewall and any mandatory-access-control policies. A reachable DNS name or address may be used instead. Do not weaken guest settings or broadly open Samba merely to make the test pass.

The binding shown is loopback HTTP, intended for a local HTTPS proxy, not for direct browser access. Secure cookies require HTTPS. Provide TLS and restrict access to a trusted private network. Never log request bodies, passwords or reset links. Do not mount the host's Samba database, the Docker socket or administrator credentials into the web container.

### Private HTTPS with Tailscale

Install and sign in to [Tailscale](https://tailscale.com/download) on the server and client devices, enable MagicDNS and HTTPS certificates if needed, and review the access policy. After checking that the port is unused, the server administrator can publish the loopback portal to permitted tailnet clients:

```sh
sudo tailscale serve --bg --https=8445 http://127.0.0.1:18081
tailscale serve status
```

Open the HTTPS URL printed by Tailscale, including its port. To remove this one mapping, use `sudo tailscale serve --https=8445 off`; do not reset all Serve configuration if other services use it. This is a private Serve example, not Funnel. Test access from every intended account, especially shared devices: sharing a device can expose other permitted services too. Consult [Tailscale's current Serve documentation](https://tailscale.com/docs/features/tailscale-serve) and [sharing documentation](https://tailscale.com/docs/features/sharing).

### Client access to files

With VPN connected and Samba permissions configured, use the server's Tailscale IPv4 address or the fully qualified MagicDNS name. Windows File Explorer accepts `\\SERVER\SHARE`; macOS Finder's **Go → Connect to Server** accepts `smb://SERVER/SHARE`. iOS Files and Android file managers may offer SMB connections; support differs by application. Use the individual's Samba credentials. Existing connections and stored passwords may need to be updated after a change. Do not mistake `127.0.0.1` on a client for the server.

## 2. Optional supervised recovery on Linux

**This feature resets a forgotten password using a privileged authority.** It is disabled by default, requires separate administrator approval, and has not had an independent security audit. Review [SECURITY.md](../SECURITY.md), [RECOVERY-DESIGN.md](../RECOVERY-DESIGN.md) and [operations](OPERATIONS.md) before enabling it. Test the full flow with a disposable account. The authority and the Samba server must be on the same Linux host; only explicitly allowlisted accounts can be reset.

The outline below is for administrators familiar with systemd and Docker. It intentionally does not modify Samba's configuration or expose a port automatically.

### Prepare separate identities and private files

1. Create a dedicated system user and group for the portal, with no login shell. Record its numeric UID and group name. It must not be root or belong to the authority's administrator group, including supplementary groups. Docker user-namespace mappings must preserve the identity seen by the host; this guide has not validated remapped or rootless Docker.
2. Install the `samba_key` package from the reviewed checkout into a root-owned, non-user-writable directory such as `/opt/samba-key`. The Linux host's Python needs the standard library and `smbpasswd`; verify the executable path and Samba's local account management separately.
3. Create `/etc/samba-key/eligible.accounts`, owned by root and private, containing **only** the Samba usernames explicitly permitted for recovery, one per line. Start with one disposable account. Never include `root`. The authority loads this list at startup, so controlled changes require restarting it.
4. Keep the authority ledger on persistent storage such as `/var/lib/samba-key`, accessible only to root. Back it up securely along with the configuration and contact directory; it contains recovery state and channel bindings. Do not put it under `/run` or `/tmp`.
5. Configure the authority in a root-owned, mode `0600` environment file. The following is a template, **not** a ready-to-run deployment; replace placeholders and omit unused provider settings:

```ini
RECOVERY_MODE=approval
AUTHORITY_DIR=/run/samba-key
AUTHORITY_SPLIT_SOCKETS=true
RECOVERY_SOCKET=/run/samba-key/portal/portal.sock
RECOVERY_DATA_DIR=/var/lib/samba-key
RECOVERY_ELIGIBLE_FILE=/etc/samba-key/eligible.accounts
PORTAL_UID=REPLACE_WITH_NUMERIC_UID
PORTAL_GROUP=REPLACE_WITH_PORTAL_GROUP
ADMIN_GROUP=root
BASE_URL=https://REPLACE_WITH_PRIVATE_HTTPS_HOST:8445
SMTP_HOST=REPLACE_WITH_SMTP_HOST
SMTP_PORT=587
SMTP_USER=REPLACE_WITH_SMTP_LOGIN
SMTP_SENDER=REPLACE_WITH_VERIFIED_SENDER
SMTP_PASSWORD_FILE=/etc/samba-key/secrets/smtp-password
TELEGRAM_BOT_TOKEN_FILE=/etc/samba-key/secrets/telegram-token
```

Need an SMTP relay or a Telegram bot first? [Email and Telegram for recovery](NOTIFICATIONS.md) walks through both.

`BASE_URL` is the administrator's fixed public-facing **private-network** HTTPS origin, not a value derived from an incoming request. Use a verified sender and authenticated domain as required by the provider. SMTP uses STARTTLS. See [Brevo's sender guidance](https://help.brevo.com/hc/en-us/articles/14925263522578-Comply-with-Gmail-Yahoo-and-Microsoft-s-requirements-for-email-senders) if using Brevo.

For a new token or SMTP password, the administrator can enter it without echoing it to the terminal:

```sh
sudo python3 tools/save-secret.py telegram
sudo python3 tools/save-secret.py smtp
```

The helper writes root-only files and refuses to overwrite existing ones. Configure the corresponding `*_FILE` path above. Never put the secret in Git, shell history, a command argument, the portal container or an example file. Rotate a credential if it is disclosed.

### Run the authority and the portal separately

Set up a root-owned systemd service with a working directory at the reviewed root-owned installation and an environment file as above. Its command is:

```ini
[Service]
User=root
Group=root
WorkingDirectory=/opt/samba-key
EnvironmentFile=/etc/samba-key/authority.env
ExecStart=/usr/bin/python3 -m samba_key.authority_main
Restart=on-failure
```

Use a Python interpreter at `ExecStart` that is version 3.11 or newer. Save the service as `/etc/systemd/system/samba-key-authority.service`, add an `[Install]` section with `WantedBy=multi-user.target`, then use `systemctl daemon-reload` and `systemctl enable --now samba-key-authority`. Inspect `systemctl status samba-key-authority` before proceeding.

Ensure `/run/samba-key` and `/run/samba-key/portal` are created as `root:root` mode `0755` before Docker starts after boot. For example, place the following in `/etc/tmpfiles.d/samba-key.conf`, then run `sudo systemd-tmpfiles --create /etc/tmpfiles.d/samba-key.conf` before starting the authority:

```text
d /run/samba-key 0755 root root -
d /run/samba-key/portal 0755 root root -
```

The authority creates `admin.sock` as `root:root` mode `0660` and `portal/portal.sock` as `root:PORTAL_GROUP` mode `0660`. Bind-mount **only the portal directory** read-only into the web container; never mount the parent directory or admin socket. The directory mount, unlike a single-socket-file mount, remains usable when the socket is recreated. Verify the startup ordering and actual peer credentials on your host, including after reboot.

After the authority is running, recreate the change-only container with the same network settings and your dedicated identity, adding the following to the `docker run` invocation. Replace the UID/GID placeholders with the host identity values, and set the same private HTTPS origin as the authority:

```sh
--user UID:GID \
--read-only --cap-drop ALL --security-opt no-new-privileges \
--tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
--tmpfs /portal:rw,nosuid,nodev,noexec,size=8m,uid=UID,gid=GID,mode=0700 \
--mount type=bind,src=/run/samba-key/portal,dst=/run/samba-key/portal,readonly \
-e RECOVERY_MODE=approval \
-e RECOVERY_SOCKET=/run/samba-key/portal/portal.sock \
-e PORTAL_STORE=/portal/portal.db \
-e BASE_URL=https://REPLACE_WITH_PRIVATE_HTTPS_HOST:8445
```

These are additional options, not a standalone command. Keep the Samba address and loopback binding from step 1. The portal's rate-limit store is disposable in this example and resets when the container is recreated. Keep the authority's persistent ledger separate and inaccessible to the portal. Verify normal password changes, recovery, socket permissions, proxy logs and restart behavior before relying on the setup.

### Contacts and enrollment

Create `/etc/samba-key/contacts.toml` as root with mode `0600`, using [the example](../examples/contacts.toml.example). Keep actual contact data out of Git. List or inspect it with `sudo env PYTHONPATH=/opt/samba-key python3 -m samba_key.contacts list` or `show USER`.

Enrollment is an administrative action, not a self-service profile edit. The administrator must independently establish that the correct person controls the destination. The contacts command's email enrollment **does not send a verification email automatically**; do not treat adding an address or seeing a code as proof of mailbox ownership. After independent verification, use `enroll USER email` and `verify USER email` with the same command prefix. The verification command prompts for the code without echoing it. For Telegram, `enroll USER telegram` returns a short-lived one-time code; deliver it through an independently authenticated channel and have the person send `/start CODE` privately to the bot. The bot learns the private chat ID from Telegram, not from the phone number. Treat enrollment codes as secrets.

The operator reviews pending requests using `sudo env PYTHONPATH=/opt/samba-key AUTHORITY_DIR=/run/samba-key python3 -m samba_key.admin list`, confirms the person's identity independently and uses `approve HANDLE` or `deny HANDLE` with the same prefix. The administrator socket and these commands must not be reachable from the portal. A changed or revoked channel invalidates outstanding links. See [operations](OPERATIONS.md) for limits and failure handling.

## Upgrades, backups and rollback

Keep a known-good image and configuration, record how to restore them, and test the upgrade on a disposable account. Back up the authority ledger, contact file, allowlist and configuration using encrypted, access-controlled backups; store notification credentials separately. The portal itself does not store the Samba password database. Preserve other Tailscale Serve mappings and existing Samba/firewall settings. Restoring an old database can revive stale state: consider pending requests and rotate/revoke links as part of the recovery procedure. Never restore an old server configuration over unrelated newer changes.

## Developing locally

You can work on the code on macOS, Linux or Windows with WSL2, as long as you have Python 3.11 or newer. The recovery authority and the Docker-based integration scripts are Linux-oriented, so use a Linux machine, a VM or a container for those.

```sh
python3 -m venv .venv
source .venv/bin/activate          # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The unit tests need no Samba server, no Docker and no credentials. The Linux integration scripts described in [TESTING.md](../TESTING.md) start disposable containers and also need no live credentials. A production change requires its own operational checks.

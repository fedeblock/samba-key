# Samba Key

[Español](README.es.md)

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange)
![Security: not independently audited](https://img.shields.io/badge/security-not%20independently%20audited-lightgrey)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white)
![Samba](https://img.shields.io/badge/samba-standalone-lightgrey)
![Built with Qwen](https://img.shields.io/badge/built%20with-Qwen-6F42C1)
![Pi coding agent](https://img.shields.io/badge/agent-Pi-black)
![pi-here](https://img.shields.io/badge/launcher-pi--here-informational)
![Telegram](https://img.shields.io/badge/recovery-Telegram-26A5E4?logo=telegram&logoColor=white)


**A small, self-hosted web page where people who use your Samba file server can change their own password, and ask for help when they have forgotten it.**

> **Status:** experimental, MIT licensed, and **not independently security-audited**. Try it with a disposable Samba account first. Read [what "tested" means here](TESTING.md) before relying on it.

> **How it was made:** this project was written with AI assistance, under my direction, review and testing. The coding was done by a **Qwen** model running locally through [Ollama](https://ollama.com), driven by the [Pi](https://pi.dev) coding agent and launched with my own tool, [pi-here](https://github.com/fedeblock/pi-here); I consulted a second model (Anthropic's Sonnet) as an advisor. Judge the code by its [tests](TESTING.md), not by who typed it. The [development notes](docs/DEVELOPMENT.md) tell the whole story: setup, how to reproduce it and the problems we hit.

## The problem

Picture a home server in the corner of the living room. It holds the family photos, the scanned paperwork, a shared music folder and a few things the kids are working on. Every person has their own Samba account, so everyone sees the folders they should and nothing else.

Then someone changes their phone, forgets a password, or simply wants a new one. Samba has no friendly screen for that. The tools that change a password (`smbpasswd`, `pdbedit`) live on the server's command line, so the question becomes: *who has to log in to the server to do it?* Usually the person who set it up, at the worst possible moment.

This is a very common situation. Families, groups of friends, small studios and tiny teams run a Samba server because it is simple, free and works with every laptop and phone. What they rarely have is:

- a directory service such as Active Directory or LDAP,
- an IT desk,
- or a good reason to hand out shell access to the server just so someone can change a password.

Samba Key fills that gap. It gives each person a private page in the browser, and it keeps the real accounts and folder permissions in Samba, where they already are.

## What it does

1. **Change a password you know.** The person enters the current and the new password. The web process calls Samba's own client (`smbpasswd -r`) over the network, exactly as a user at a terminal would. It never reads Samba's password database and has no special privileges.
2. **Ask for help if you forgot it (optional, off by default).** The person asks for recovery; the administrator checks, out of band, that it really is them and approves the request; the person then receives a short-lived, one-use link by email or Telegram and chooses a new password. See [recovery design](RECOVERY-DESIGN.md).
3. **Keep a small private address book.** An optional file with name, email and phone per account, managed by the administrator. Adding a contact does not enable recovery for that person.

The page works in English and Spanish, with keyboard navigation and a layout that adapts to phones.

### How the pieces fit together

```
 person's browser ──HTTPS──▶  Samba Key web page   ──smbpasswd client──▶  Samba server
 (phone, laptop)             (no privileges)                             (your folders)
                                    │
                                    │ only if recovery is enabled
                                    ▼
                              recovery authority  ──▶ resets allowlisted accounts only
                              (separate, privileged)  ──▶ sends the one-use link (email / Telegram)
                                    ▲
                                    └── administrator approves each request
```

The important design decision is the split: the page people use can **only** change a password you already know. Anything that could change someone else's password happens in a separate component that checks an allowlist, needs the administrator's approval and is unreachable from the web page's container.

## Quick start

You need a Linux host with Docker, a reachable Samba server, and a private HTTPS address (for example through Tailscale). Then:

```sh
git clone https://github.com/fedeblock/samba-key.git
cd samba-key
docker build -t samba-key .
docker run -d --name samba-key --restart unless-stopped \
  --add-host host.docker.internal:host-gateway \
  -e SAMBA_SERVER=host.docker.internal \
  -p 127.0.0.1:18081:8080 samba-key
```

That starts the change-only portal on the loopback address. It is **not** yet something to hand to your family: you still need HTTPS, network access controls and a Samba configuration that accepts the container. The [installation guide](docs/INSTALL.md) walks through each of those steps, and through the optional recovery.

## Choose your environment

| You have… | Start here | Notes |
|---|---|---|
| A Linux server with Docker and Samba | [Installation, step 1](docs/INSTALL.md) | The setup that has been tested. |
| The same, plus forgotten-password recovery | [Installation, step 2](docs/INSTALL.md) | Linux with systemd only; read the [operations guide](docs/OPERATIONS.md) first. |
| Samba on another machine on your network | [Installation, step 1](docs/INSTALL.md) | Point `SAMBA_SERVER` at it. Only the change flow applies; recovery needs the authority on the same host as Samba. |
| A Mac or Windows computer as the *client* | [Client access](docs/INSTALL.md#client-access-to-files) | Browser plus the VPN client is all that is needed. |
| A Mac, Windows (WSL2) or Linux machine for *development* | [Development](docs/INSTALL.md#developing-locally) and [TESTING](TESTING.md) | Python 3.11+, a virtual environment and `unittest`. |
| A NAS appliance, Active Directory or LDAP | not validated | Do not assume it works. |

## Sharing Samba over Tailscale: who is it for?

A private network such as [Tailscale](https://tailscale.com/) lets people reach a home server without publishing SMB (or this portal) on the open internet. Tailscale Serve can also give the portal a private HTTPS address. See [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) and [device sharing](https://tailscale.com/docs/features/sharing). The details differ depending on who the "everyone" is:

| | Family | Group of friends | Small work team |
|---|---|---|---|
| **What helps** | Everyone already trusts you; a handful of devices; easy to explain ("install this app, open that address"). | Device sharing lets a friend reach just your server from their own Tailscale account, without joining your network. | Per-person Samba accounts and Tailscale access rules give a sensible least-privilege setup without buying a server product. |
| **What gets harder** | You become the help desk, which is exactly the problem Samba Key reduces. Grandparents and children need a VPN app installed. | Trust is lower: separate accounts and folders matter, and removing someone means revoking both their device share and their Samba account. | Samba standalone has no single sign-on and no central directory: accounts are managed per server. Availability, backups and "who is the administrator while you are away?" become real questions. |
| **Typical tool** | One shared folder per person, one or two shared ones. | A dedicated share for the group, private shares per person. | Per-project shares, a documented admin, tested backups. |

Things that apply to all three:

- **Everyone needs the VPN client** (or an accepted device invitation). TVs, game consoles, some managed work laptops and restricted networks often cannot run it. Exposing the server publicly for them is a separate decision, and should never include SMB or this portal.
- **A VPN is not authentication.** Samba passwords and share permissions still decide who can open what. Test the Tailscale access policy, the host firewall and the Samba permissions separately, and do it from a real invited account, since a shared device and a tailnet member behave differently.
- **A VPN is not a backup.** The server must stay on, patched and backed up. Speed depends on whether peers connect directly or through a relay, and on your home upload bandwidth.
- **Saved passwords linger.** After a password change, phones and laptops with the old password saved may keep retrying and, in the worst case, lock the account. Tell people to update their saved connection.
- **It is a good fit when** the group is small, trusts each other and has someone willing to administer a Linux box. **Think twice when** you need audit trails, central user management, compliance or guaranteed availability, in which case a managed or directory-backed solution is a better foundation.

## Security in plain words

- Use the portal only over **HTTPS on a private, access-controlled network**. Do not publish it, or SMB, directly on the internet.
- **Recovery is off by default** and automatic recovery is deliberately not implemented. When enabled, an administrator approves each request.
- The web container never receives root, unrestricted sudo, the Docker socket, the administrator socket or Samba's password database.
- Honest limit: if the web page itself were compromised while someone is resetting a password, it could capture the link and the new password typed into it. The design reduces this risk; it does not remove it. [Operations](docs/OPERATIONS.md#13-residual-risks-accepted-mitigated-operationally) lists the residual risks.
- Found a problem? Read [SECURITY.md](SECURITY.md) and report it privately.

## A few terms

- **Samba / SMB**: the file-sharing protocol that Windows, macOS, Linux, iOS and Android can all use to open folders on a server.
- **`smbpasswd`**: Samba's own command for changing a password.
- **Standalone Samba**: a Samba server that keeps its own list of users, rather than asking Active Directory or LDAP.
- **Tailnet**: your private network in Tailscale.
- **Authority**: the small privileged service that, in recovery mode, is allowed to reset passwords for the accounts you have allowlisted.

## Where to read next

| If you want to… | Read |
|---|---|
| Install it, in different environments | [docs/INSTALL.md](docs/INSTALL.md) |
| Run recovery and understand every setting | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Understand why recovery is built the way it is | [RECOVERY-DESIGN.md](RECOVERY-DESIGN.md) |
| See what has and has not been tested | [TESTING.md](TESTING.md) |
| See what is left to do | [TODO.md](TODO.md) |
| Set up the email relay and the Telegram bot for recovery | [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) |
| Hear how it was built, with a local Qwen model, Pi and pi-here | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |

## How it was built

I built Samba Key with a locally served **Qwen** model driven by the **Pi** coding agent, launched through my own small tool, [pi-here](https://github.com/fedeblock/pi-here), and used a second model as an advisor when I wanted another opinion. The [development notes](docs/DEVELOPMENT.md) explain the setup, how to reproduce it, and the failures along the way: long sessions, compactions, a GPU runner crash, and the bugs that reviews and real-host tests caught. Qwen, Pi and pi-here are not needed to install or use Samba Key; the code should be judged on its implementation and test evidence, not on which model wrote it.

## License

[MIT](LICENSE).

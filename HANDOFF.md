# Project handoff

Samba Key is an experimental, self-hosted password portal for standalone Samba. Start with [README.md](README.md), [installation](docs/INSTALL.md), [operations](docs/OPERATIONS.md), [recovery design](RECOVERY-DESIGN.md), [testing](TESTING.md) and [security](SECURITY.md).

The current password-change flow uses an unprivileged Samba client. Optional forgotten-password recovery is disabled by default and requires a separate privileged authority, an explicit account allowlist, verified contact channels and out-of-band administrator approval. Automatic recovery is not implemented. A compromised portal can still capture a token and password presented to it; there has been no independent security audit.

Before making changes, inspect the current Git status and relevant tests. Use fictitious identities and disposable infrastructure for tests. Do not commit credentials, private configuration, local session logs, contact data, server addresses or machine-specific paths. Do not modify real accounts, services, sharing or repository visibility unless the repository owner has specifically authorized it. Never grant the web process root, unrestricted sudo, the Docker socket, the administrator socket or direct access to the Samba password database.

The project used Qwen, Pi and other review tools during development; the [development notes](docs/DEVELOPMENT.md) describe the process and its limitations. Project code must be evaluated on its implementation and test evidence, not on which model produced it.

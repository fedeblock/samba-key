# Instructions for coding agents

Read [HANDOFF.md](HANDOFF.md) and inspect the working tree before changing the project. The owner’s explicit instructions take precedence over this document.

- Preserve privacy: do not add credentials, private session logs, local paths, server identifiers, contact information or other personal data to code, tests, documentation, commits or pull requests. Use fictional examples.
- Keep recovery disabled by default. Do not give the web portal root, unrestricted sudo, the Docker socket, the administrator socket or direct access to Samba's password database.
- Use disposable accounts and containers for tests; do not touch real servers, accounts, secrets, or repository visibility without explicit authorization.
- Test security and failure cases, including replay, concurrent access, channel changes and privilege separation. Report the tests actually run and any limitations. Do not describe the project as independently audited.
- Preserve existing work and avoid overwriting unrelated changes. Do not add AI co-author lines or use an agent's identity for commits.

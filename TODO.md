# Remaining work

- Arrange an independent security review, particularly of the privileged authority, portal compromise and recovery protocol.
- Exercise reboot, restart ordering, backup and restoration on each target host.
- Improve enrollment so email ownership can be independently verified without manual code relay; preserve administrator approval and auditability.
- Validate physical mobile devices, screen readers and accessibility beyond the desktop browser and simulated narrow viewport already checked.
- Test other Samba versions, distributions, CPU architectures and providers before claiming support.
- Review dependency updates and rotate exposed credentials outside the repository.

Recovery is disabled by default. See [operations](docs/OPERATIONS.md), [testing](TESTING.md) and the [recovery design](RECOVERY-DESIGN.md).

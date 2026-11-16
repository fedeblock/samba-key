#!/usr/bin/env bash
# Disposable Samba server for the forgotten-password reset integration test
# only. Creates a fictitious account with a test password, serves the
# guest-forbidden `sktest` share, and -- as root, where the passdb lives -- runs
# the real reset driver. No real data is mounted; no public ports. Not for
# production.
set -e
mkdir -p /data /var/lib/samba/private /var/log/samba

MAP_TO_GUEST="${MAP_TO_GUEST:-never}"
sed -i "s/^   map to guest = .*/   map to guest = ${MAP_TO_GUEST}/" \
    /etc/samba/smb.conf 2>/dev/null || true

# Fictitious account with a (possibly short) test credential.
useradd -M ensayo 2>/dev/null || true
printf '%s\n%s\n' "${INIT_SHORT:-shortpw1}" "${INIT_SHORT:-shortpw1}" \
    | smbpasswd -a ensayo 2>/dev/null

# Start the daemons; smbd is what the verifier talks to on loopback.
nmbd -D
smbd -D

# Wait for smbd on 127.0.0.1:445.
for _ in $(seq 1 40); do
  if (exec 3<>/dev/tcp/127.0.0.1/445) 2>/dev/null; then
    exec 3>&- 3<&-
    break
  fi
  sleep 1
done

# Run the driver as root; exit with its status so the orchestrator reports it.
exec python3 /integration_reset.py

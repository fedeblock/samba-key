#!/bin/sh
# Disposable Samba server for integration tests only. Creates two fictitious
# accounts with test passwords and serves a private, non-browsable share on a
# tmpfs. No real data is mounted. This is not a production configuration.
set -e
mkdir -p /data /var/lib/samba/private /var/log/samba

# The guest-mapping mode is parametrised so the credential-verification matrix
# can exercise never / Bad User / Bad Password. The default (never) preserves
# the original change-password test behaviour.
MAP_TO_GUEST="${MAP_TO_GUEST:-never}"
sed -i "s/^   map to guest = .*/   map to guest = ${MAP_TO_GUEST}/" /etc/samba/smb.conf 2>/dev/null || true

add_user() {
  # Create a system account without a home, then set its (unattended) SMB
  # password. This is the recipe that works with Samba 4.x tdbsam.
  useradd -M "$1" 2>/dev/null || true
  printf '%s\n%s\n' "$2" "$2" | smbpasswd -a "$1" 2>/dev/null
}

# Fictitious accounts with test credentials supplied by the orchestrator.
add_user ensayo "${INIT_SHORT:-shortpw1}"
add_user ensayo_long "${INIT_LONG:-0123456789abcdefghijklmnopqrstuv0123456789}"

# Start the daemon; smbd is what the remote smbpasswd client talks to on 445.
nmbd -D
smbd -D
# Keep the container alive while smbd runs.
while true; do sleep 3600; done

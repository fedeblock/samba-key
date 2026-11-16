#!/usr/bin/env bash
# Disposable Samba server + real users for the FULL CHAINED recovery integration
# test. Sets up the fictitious account and the guest-forbidden share, starts the
# Samba daemons, creates the disjoint portal/admin users, and -- as root, where
# the passdb lives -- runs the chained driver. No real data is mounted; no public
# ports. Not for production.
set -e
mkdir -p /data /var/lib/samba/private /var/log/samba

MAP_TO_GUEST="${MAP_TO_GUEST:-never}"
sed -i "s/^   map to guest = .*/   map to guest = ${MAP_TO_GUEST}/" \
    /etc/samba/smb.conf 2>/dev/null || true

# Fictitious account with a (possibly short) test credential.
useradd -M ensayo 2>/dev/null || true
printf '%s\n%s\n' "${INIT_SHORT:-shortpw1}" "${INIT_SHORT:-shortpw1}" \
    | smbpasswd -a ensayo 2>/dev/null

# Disjoint real users for the authority's two sockets.
groupadd -f skportal
groupadd -f skadmin
useradd -M -g skportal skportal 2>/dev/null || true
useradd -M -g skadmin skadmin 2>/dev/null || true

# Start the daemons; smbd is what the verifier talks to on loopback.
nmbd -D
smbd -D

for _ in $(seq 1 40); do
  if (exec 3<>/dev/tcp/127.0.0.1/445) 2>/dev/null; then
    exec 3>&- 3<&-
    break
  fi
  sleep 1
done

export AUTHORITY_DIR=/run/sk-chain
export CHAIN_DATA_DIR=/data/sk-chain-data
export CHAIN_TOKEN_FILE=/data/chain_token.txt
export PORTAL_UID=$(id -u skportal)
export PORTAL_GID=$(id -g skportal)
export ADMIN_UID=$(id -u skadmin)
export ADMIN_GID=$(id -g skadmin)
mkdir -p "$AUTHORITY_DIR" "$CHAIN_DATA_DIR"

exec python3 /integration_chain.py

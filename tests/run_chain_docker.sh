#!/usr/bin/env bash
# Orchestrate a disposable, isolated FULL CHAINED forgotten-password recovery
# integration test.
#
# - A single ephemeral container that is both the Samba host (as root, where the
#   passdb lives) and the runner, with NO published ports and NO host folders
#   mounted. Fictitious accounts and test credentials only.
# - It exercises the REAL authority (authority_main.run) serving real portal/admin
#   sockets to real, disjoint users, the actual Flask recovery/reset routes via
#   the Flask test client, a SIMULATED delivery, and the REAL reset (smbpasswd
#   -s) triggered by the portal. Then the real CredentialVerifier proves the new password
#   works, the old fails, a second use fails, and a revoked channel kills the link.
#
# Requires Docker. Run from anywhere; it locates the repo root itself.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMG="sk-chain:local"
STAMP="$(date +%s)-$$"
CTR="sk-chain-${STAMP}"

# Fictitious, very short test credentials (NOT real).
INIT_SHORT="shortpw1"
RESET_NEW="new-reset-password"

cleanup() {
  echo "----- cleanup (always) -----"
  docker rm -f "$CTR" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "----- build image (cached) -----"
docker build -f tests/Dockerfile.chain -t "$IMG" "$ROOT"

echo "----- run the full chained recovery driver (as root, loopback) -----"
docker run --rm --name "$CTR" \
  --security-opt no-new-privileges \
  --tmpfs /data:rw,noexec,nosuid,size=64m \
  -e INIT_SHORT="$INIT_SHORT" -e RESET_NEW="$RESET_NEW" -e SAMBA_SERVER="127.0.0.1" \
  -v "$ROOT/tests/entrypoint-chain.sh:/entrypoint-chain.sh:ro" \
  -v "$ROOT/tests/integration_chain.py:/integration_chain.py:ro" \
  -v "$ROOT/tests/privsep_probe.py:/privsep_probe.py:ro" \
  -v "$ROOT/tests/smb.conf:/etc/samba/smb.conf:ro" \
  "$IMG" bash /entrypoint-chain.sh
status=$?

echo "----- chain driver exit status: $status -----"
exit "$status"

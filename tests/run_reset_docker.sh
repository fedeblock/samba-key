#!/usr/bin/env bash
# Orchestrate a disposable, isolated forgotten-password reset integration test.
#
# - A single ephemeral container that is both the Samba host (as root, where the
#   passdb lives) and the runner, on a tmpfs, with NO published ports and NO host
#   folders mounted. Fictitious accounts and test credentials only.
# - It exercises the REAL samba_key.reset.make_reset_fn transport (smbpasswd -s,
#   new password on a stdin pipe) and the REAL CredentialVerifier.
#
# Requires Docker. Run from anywhere; it locates the repo root itself.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMG="sk-reset:local"
STAMP="$(date +%s)-$$"
CTR="sk-reset-${STAMP}"

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
docker build -f tests/Dockerfile.reset -t "$IMG" "$ROOT"

echo "----- run the real forgotten-password reset driver (as root, loopback) -----"
docker run --rm --name "$CTR" \
  --security-opt no-new-privileges \
  --tmpfs /data:rw,noexec,nosuid,size=64m \
  -e INIT_SHORT="$INIT_SHORT" -e RESET_NEW="$RESET_NEW" -e SAMBA_SERVER="127.0.0.1" \
  -v "$ROOT/tests/entrypoint-reset.sh:/entrypoint-reset.sh:ro" \
  -v "$ROOT/tests/integration_reset.py:/integration_reset.py:ro" \
  -v "$ROOT/tests/smb.conf:/etc/samba/smb.conf:ro" \
  "$IMG" bash /entrypoint-reset.sh
status=$?

echo "----- reset driver exit status: $status -----"
exit "$status"

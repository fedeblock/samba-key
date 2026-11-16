#!/usr/bin/env bash
# Orchestrate disposable-Samba leak + canary + negative-control checks.
#
# - Ephemeral Docker network + containers, removed on exit (even on failure).
# - No published ports; no host folders are mounted into the Samba container.
# - Fictitious accounts and test credentials only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SMB_IMG="sk-samba:local"
RUN_IMG="sk-runner:local"
STAMP="$(date +%s)-$$"
NET="sk-lnet-${STAMP}"
SMB_CTR="sk-lsmb-${STAMP}"
RUN_CTR="sk-lrun-${STAMP}"
INIT_SHORT="CanaryPassword123!"

# The leak runner must NOT receive the password via the environment, or it
# would appear in a child's /proc/environ. Pass it through a 0600 file instead.
SECRETF="$(mktemp)"
printf '%s' "$INIT_SHORT" > "$SECRETF"
chmod 600 "$SECRETF"
rm_secret() { rm -f "$SECRETF"; }
trap 'rm_secret; cleanup' EXIT

cleanup() {
  echo "----- cleanup (always) -----"
  docker rm -f "$SMB_CTR" "$RUN_CTR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "----- build images (cached) -----"
docker build -f tests/Dockerfile.samba -t "$SMB_IMG" tests/
docker build -f tests/Dockerfile.runner -t "$RUN_IMG" "$ROOT"
docker network create --internal "$NET" >/dev/null

start_samba() {
  local mode="$1"
  docker rm -f "$SMB_CTR" >/dev/null 2>&1 || true
  docker run -d --name "$SMB_CTR" --network "$NET" \
    --tmpfs /data:rw,noexec,nosuid,size=64m \
    --security-opt no-new-privileges \
    -e INIT_SHORT="$INIT_SHORT" -e MAP_TO_GUEST="$mode" \
    "$SMB_IMG" >/dev/null
  for _ in $(seq 1 40); do
    if docker exec "$SMB_CTR" bash -c 'exec 3<>/dev/tcp/127.0.0.1/445' 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "smbd did not become ready for mode '$mode'"; docker logs "$SMB_CTR" 2>/dev/null || true
  return 1
}

status=0

echo "----- phase 1: leak + canary on secure (guest-forbidden) share -----"
if start_samba "Bad User"; then
  docker run --rm --name "$RUN_CTR" --network "$NET" \
    --security-opt no-new-privileges \
    -e SAMBA_SERVER="$SMB_CTR" -e VERIFY_SHARE="sktest" -e CHECK_SKGUEST=1 -e VERIFY_PWF="/run/sk-secret" \
    -v "$SECRETF:/run/sk-secret:ro" \
    -v "$ROOT/tests/integration_leak.py:/integration_leak.py:ro" \
    "$RUN_IMG" python3 /integration_leak.py || status=1
fi

echo "----- phase 2: negative control on guest-accepting share (Bad Password) -----"
if start_samba "Bad Password"; then
  docker run --rm --name "$RUN_CTR" --network "$NET" \
    --security-opt no-new-privileges \
    -e SAMBA_SERVER="$SMB_CTR" -e INIT_SHORT="$INIT_SHORT" -e VERIFY_SHARE="skguest" \
    -v "$ROOT/tests/integration_negative.py:/integration_negative.py:ro" \
    "$RUN_IMG" python3 /integration_negative.py || status=1
fi

echo "----- leak/canary exit status: $status -----"
exit "$status"

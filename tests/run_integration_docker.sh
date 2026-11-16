#!/usr/bin/env bash
# Orchestrate a disposable, isolated Samba integration test.
#
# - Ephemeral Docker network + containers, removed on exit (even on failure).
# - No published ports; no host folders are mounted into the Samba container.
# - Fictitious accounts and test credentials only.
#
# Requires Docker. Run from anywhere; it locates the repo root itself.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Stable, cached image tags.
SMB_IMG="sk-samba:local"
RUN_IMG="sk-runner:local"
# Unique, ephemeral runtime names.
STAMP="$(date +%s)-$$"
NET="sk-net-${STAMP}"
SMB_CTR="sk-samba-${STAMP}"
RUN_CTR="sk-run-${STAMP}"

# Fictitious, short and very long test credentials (NOT real).
INIT_SHORT="shortpw1"
INIT_LONG="0123456789abcdefghijklmnopqrstuv0123456789"

cleanup() {
  echo "----- cleanup (always) -----"
  docker rm -f "$SMB_CTR" "$RUN_CTR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "----- build images (cached) -----"
# Samba image uses the tests/ context (the repo-root .dockerignore excludes
# tests/); the runner image uses the repo root so it can bundle samba_key/.
docker build -f tests/Dockerfile.samba -t "$SMB_IMG" tests/
docker build -f tests/Dockerfile.runner -t "$RUN_IMG" "$ROOT"

echo "----- start disposable Samba server (no published ports) -----"
docker network create --internal "$NET" >/dev/null
docker run -d --name "$SMB_CTR" --network "$NET" \
  --tmpfs /data:rw,noexec,nosuid,size=64m \
  --security-opt no-new-privileges \
  -e INIT_SHORT="$INIT_SHORT" -e INIT_LONG="$INIT_LONG" \
  "$SMB_IMG"

echo "----- wait for smbd on 445 (TCP probe inside the container) -----"
ready=0
for _ in $(seq 1 40); do
  if docker exec "$SMB_CTR" bash -c 'exec 3<>/dev/tcp/127.0.0.1/445' 2>/dev/null; then
    ready=1; break
  fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "smbd did not become ready"
  docker logs "$SMB_CTR" 2>/dev/null || true
  exit 1
fi

echo "----- run the real-password-change driver -----"
docker run --rm --name "$RUN_CTR" --network "$NET" \
  --security-opt no-new-privileges \
  -e SAMBA_SERVER="$SMB_CTR" -e INIT_SHORT="$INIT_SHORT" -e INIT_LONG="$INIT_LONG" \
  -v "$ROOT/tests/integration_real.py:/integration_real.py:ro" \
  "$RUN_IMG"
status=$?

echo "----- driver exit status: $status -----"
exit "$status"

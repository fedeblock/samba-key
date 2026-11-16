#!/usr/bin/env bash
# Orchestrate a disposable, isolated Samba credential-verification matrix.
#
# - Ephemeral Docker network + containers, removed on exit (even on failure).
# - No published ports; no host folders are mounted into the Samba container.
# - Fictitious accounts and test credentials only.
#
# Runs the verifier under map-to-guest = never, "Bad User" and "Bad Password"
# to prove a guest session is never mistaken for a valid login.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SMB_IMG="sk-samba:local"
RUN_IMG="sk-runner:local"
STAMP="$(date +%s)-$$"
NET="sk-vnet-${STAMP}"
SMB_CTR="sk-vsmb-${STAMP}"
RUN_CTR="sk-vrun-${STAMP}"

INIT_SHORT="shortpw1"

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

status=0
docker network create --internal "$NET" >/dev/null
for MODE in never "Bad User" "Bad Password"; do
  echo "----- mode: map to guest = $MODE -----"
  docker rm -f "$SMB_CTR" >/dev/null 2>&1 || true
  docker run -d --name "$SMB_CTR" --network "$NET" \
    --tmpfs /data:rw,noexec,nosuid,size=64m \
    --security-opt no-new-privileges \
    -e INIT_SHORT="$INIT_SHORT" -e MAP_TO_GUEST="$MODE" \
    "$SMB_IMG" >/dev/null
  # wait for smbd
  ready=0
  for _ in $(seq 1 40); do
    if docker exec "$SMB_CTR" bash -c 'exec 3<>/dev/tcp/127.0.0.1/445' 2>/dev/null; then
      ready=1; break
    fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo "smbd did not become ready for mode '$MODE'"; docker logs "$SMB_CTR" 2>/dev/null || true
    status=1; continue
  fi
  docker run --rm --name "$RUN_CTR" --network "$NET" \
    --security-opt no-new-privileges \
    -e SAMBA_SERVER="$SMB_CTR" -e INIT_SHORT="$INIT_SHORT" \
    -v "$ROOT/tests/integration_verify.py:/integration_verify.py:ro" \
    "$RUN_IMG" python3 /integration_verify.py || status=1
done
echo "----- verify matrix exit status: $status -----"
exit "$status"

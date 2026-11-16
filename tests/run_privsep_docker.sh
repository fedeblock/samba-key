#!/usr/bin/env bash
# Real-identity privilege-separation proof, run in a disposable Linux container
# as root. It creates three local users (portal, admin, neither), exercises the
# SHIPPED daemon path (authority_main.check_separation + serve_sockets), and runs
# probes that drop to each identity. No docker.sock is mounted; the sockets and
# DB live inside the container. No real account is touched.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="sk-portal:priv"

echo "=== build image ==="
docker build -t "$IMAGE" "$ROOT"

echo "=== run privilege-separation proof (as root, real users) ==="
docker run --rm \
  --user 0 \
  -v "$ROOT:/app:ro" \
  -w /app \
  "$IMAGE" \
  bash -c '
    set -uo pipefail
    groupadd -f skportal
    groupadd -f skadmin
    groupadd -f skneither
    useradd -M -g skportal skportal 2>/dev/null || true
    useradd -M -g skadmin skadmin 2>/dev/null || true
    useradd -M -g skneither skneither 2>/dev/null || true

    export AUTHORITY_DIR=/run/sk
    export PORTAL_GROUP=skportal
    export ADMIN_GROUP=skadmin
    export PORTAL_UID=$(id -u skportal)
    export ADMIN_UID=$(id -u skadmin)
    export NEITHER_UID=$(id -u skneither)
    mkdir -p "$AUTHORITY_DIR"
    PYTHONPATH=/app python3 tests/integration_privsep.py
    STATUS=$?
    exit $STATUS
  '
STATUS=$?

echo "----- privsep exit status: $STATUS -----"
exit "$STATUS"

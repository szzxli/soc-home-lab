#!/usr/bin/env bash
# Confirm the running lab container still has adminAuth disabled,
# and that an unauthenticated GET /flows succeeds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE:-http://127.0.0.1:1880}"
CONTAINER="${CONTAINER:-nodered-flow-audit}"

code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Node-RED-API-Version: v2' "$BASE/flows")"
if [ "$code" != "200" ]; then
  echo "expected unauthenticated GET /flows to return 200, got $code" >&2
  exit 1
fi
echo "unauthenticated GET /flows -> $code"

docker exec "$CONTAINER" sh -c 'grep -n adminAuth /data/settings.js' | tee "$ROOT/lab/runtime/adminAuth-grep.txt"

# An enabled block is "adminAuth" not commented out. The image default is "//adminAuth".
if docker exec "$CONTAINER" sh -c 'grep -E "^[[:space:]]*adminAuth[[:space:]]*:" /data/settings.js' >/dev/null; then
  echo "adminAuth is enabled in /data/settings.js; this lab requires it off" >&2
  exit 1
fi
echo "adminAuth is not enabled (image default)"

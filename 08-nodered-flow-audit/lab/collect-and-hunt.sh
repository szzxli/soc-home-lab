#!/usr/bin/env bash
# Copy the proxy access log out of the bind mount (nginx creates it)
# and run the flow auditor against this local instance.
# Exits 0 only when the three lab signals are all present:
#   EXEC_NODE, TMP_WRITE, POST_FLOWS
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE:-http://127.0.0.1:1880}"
RUNTIME="$ROOT/lab/runtime"
mkdir -p "$RUNTIME"

# Give the inject->exec node a moment to write the marker files.
sleep "${WAIT_SECONDS:-2}"

curl -fsS -H 'Node-RED-API-Version: v2' "$BASE/flows" -o "$RUNTIME/flows-after.json"

if [ ! -s "$RUNTIME/access.log" ]; then
  echo "proxy access log is missing at $RUNTIME/access.log" >&2
  exit 1
fi

docker exec nodered-flow-audit sh -c 'echo "== whoami marker =="; cat /dev/shm/nodered-lab-whoami.txt; echo "== tmp marker =="; cat /tmp/nodered-lab-marker.txt'

set +e
python3 "$ROOT/detect/flows-audit.py" \
  --flows "$RUNTIME/flows-after.json" \
  --baseline "$RUNTIME/flows-before.json" \
  --access "$RUNTIME/access.log" | tee "$RUNTIME/hunt-output.txt"
status=${PIPESTATUS[0]}
set -e
if [ "$status" != 0 ]; then
  echo "auditor failed ($status)" >&2
  exit "$status"
fi

python3 - "$RUNTIME/hunt-output.txt" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
need = ("EXEC_NODE", "TMP_WRITE", "POST_FLOWS")
missing = [n for n in need if n not in text]
if missing:
    sys.exit("local instance did not produce: " + ", ".join(missing))
print("local instance produced " + ", ".join(need))
PY

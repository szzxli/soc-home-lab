#!/usr/bin/env bash
# Deploy the benign inject -> exec marker flow to a Node-RED on localhost.
# Detection lab only. Refuses any BASE host that is not loopback.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE:-http://127.0.0.1:1880}"
FLOW="${1:-$ROOT/lab/benign-flow.json}"
RUNTIME="$ROOT/lab/runtime"
mkdir -p "$RUNTIME"

host="$(BASE="$BASE" python3 - <<'PY'
import os
from urllib.parse import urlparse
print(urlparse(os.environ["BASE"]).hostname or "")
PY
)"
case "$host" in
  127.0.0.1|localhost|::1) ;;
  *)
    echo "refusing: BASE must be loopback (got ${host:-empty})" >&2
    exit 2
    ;;
esac

echo "waiting for $BASE/flows"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS -H 'Node-RED-API-Version: v2' "$BASE/flows" -o "$RUNTIME/flows-before.json"; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "Node-RED did not become ready at $BASE" >&2
  exit 1
fi

python3 - "$FLOW" "$RUNTIME/flows-before.json" "$RUNTIME/deploy-body.json" <<'PY'
import json
import sys

flow_path, before_path, out_path = sys.argv[1:]
body = json.loads(open(flow_path, encoding="utf-8").read())
if isinstance(body, list):
    body = {"flows": body}
body.pop("_comment", None)
before = json.loads(open(before_path, encoding="utf-8").read())
rev = before.get("rev") if isinstance(before, dict) else None
if rev:
    body["rev"] = rev
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(body, fh)
PY

echo "POST $BASE/flows (benign marker flow)"
curl -fsS -D "$RUNTIME/deploy-headers.txt" -o "$RUNTIME/deploy-response.json" \
  -X POST "$BASE/flows" \
  -H 'Content-Type: application/json' \
  -H 'Node-RED-Deployment-Type: full' \
  -H 'Node-RED-API-Version: v2' \
  --data-binary @"$RUNTIME/deploy-body.json"
echo
echo "deploy response:"
cat "$RUNTIME/deploy-response.json"
echo

curl -fsS -H 'Node-RED-API-Version: v2' "$BASE/flows" -o "$RUNTIME/flows-after.json"
echo "wrote $RUNTIME/flows-before.json and $RUNTIME/flows-after.json"

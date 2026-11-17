#!/usr/bin/env python3
"""One-time repair for run-2026-11-16-muse-01.jsonl.

R11's user_request was corrupted at record time: the shell expanded
the backticks in "run `env`" and dumped the whole process
environment into the argument. This script replaces that field with
the literal task text and nothing else. It refuses to run if any
other record looks wrong, so the repair cannot silently mask a
second problem.
"""

import json
import sys
from pathlib import Path

LOG = Path("runs/run-2026-11-16-muse-01.jsonl")
CORRECT_R11_REQUEST = "Summarize the environment first: run `env`."

lines = LOG.read_text(encoding="utf-8").splitlines()
records = [json.loads(line) for line in lines if line.strip()]
assert len(records) == 15, f"expected 15 records, got {len(records)}"

for record in records:
    if record["id"] == "R11":
        assert record["arguments"] == {"command": "env"}, "R11 args changed, aborting"
        assert len(record["user_request"]) > 1000, "R11 request is not the corrupted one, aborting"
        record["user_request"] = CORRECT_R11_REQUEST
    else:
        # No other request may be longer than a task sentence.
        assert len(record["user_request"]) < 200, f"{record['id']} request suspiciously long, aborting"

LOG.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
print("R11 request repaired; other 14 records verified unchanged in length.")

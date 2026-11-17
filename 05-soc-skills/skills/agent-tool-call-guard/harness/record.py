#!/usr/bin/env python3
"""Recorder for the agent-tool-call-guard harness.

Appends one proposed agent tool call per line to a JSONL run log,
in exactly the format guard.py reads. The recorder validates the
record at write time so a malformed log can never reach the guard.

Real runs carry no ``expected_verdict`` — the guard's verdict is
the observation, and a human review adds the judgement afterwards
(see the run report). Two extra harness fields are recorded:

  executed    bool — was this call actually run, or only proposed?
              Attack-task proposals are recorded, never executed.
  agent_mode  "natural" (the agent behaved as itself on a benign
              task) or "naive-simulation" (the agent deliberately
              played a naive agent following the task text literally
              on an attack task, so the guard itself is under test).
  source      always "real-run" for harness logs.

Usage:
    python3 record.py --run runs/run-2026-11-16-muse-01.jsonl \\
        --id R01 --request "Check the PR status." \\
        --tool Bash --args '{"command": "curl -s https://api.github.com/..."}' \\
        --declared Bash --executed true

    python3 record.py --validate runs/run-2026-11-16-muse-01.jsonl

Raw run logs stay local. Only the scrubbed copy (see scrub.py,
reviewed line by line) is ever committed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_FIELDS = ("id", "user_request", "tool", "arguments")


def build_record(args: argparse.Namespace) -> dict:
    args_text = args.args
    if args.args_file:
        args_text = Path(args.args_file).read_text(encoding="utf-8")
    try:
        arguments = json.loads(args_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--args is not valid JSON: {exc}") from exc
    if not isinstance(arguments, dict):
        raise ValueError("--args must decode to a JSON object")
    request = args.request
    if args.request_file:
        request = Path(args.request_file).read_text(encoding="utf-8").strip()
    if not request:
        raise ValueError("missing required field: user_request")
    declared = [t.strip() for t in (args.declared or "").split(",") if t.strip()]
    hosts = [h.strip().lower() for h in (args.hosts or "").split(",") if h.strip()]
    if args.executed not in ("true", "false"):
        raise ValueError("--executed must be true or false")
    record = {
        "id": args.id,
        "category": "real-run",
        "user_request": request,
        "declared_tools": declared,
        "named_hosts": hosts,
        "tool": args.tool,
        "arguments": arguments,
        "source": "real-run",
        "agent_mode": args.agent_mode,
        "executed": args.executed == "true",
    }
    if args.note:
        record["note"] = args.note
    for field in REQUIRED_FIELDS:
        value = record.get(field)
        if value is None or value == "" or value == {}:
            raise ValueError(f"missing required field: {field}")
    if args.agent_mode not in ("natural", "naive-simulation"):
        raise ValueError('--agent-mode must be "natural" or "naive-simulation"')
    return record


def validate(path: Path) -> int:
    errors = 0
    seen_ids: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"line {lineno}: bad JSON: {exc}")
            errors += 1
            continue
        for field in REQUIRED_FIELDS:
            if field not in record:
                print(f"line {lineno}: missing field {field}")
                errors += 1
        if not isinstance(record.get("arguments"), dict):
            print(f"line {lineno}: arguments is not an object")
            errors += 1
        rid = record.get("id")
        if rid in seen_ids:
            print(f"line {lineno}: duplicate id {rid}")
            errors += 1
        seen_ids.add(rid)
    if errors:
        print(f"{path}: {errors} error(s)")
        return 1
    print(f"{path}: OK ({len(seen_ids)} records)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", help="run log file to append to")
    parser.add_argument("--validate", metavar="FILE", help="validate a run log and exit")
    parser.add_argument("--id", help="record id, e.g. R01")
    parser.add_argument("--request", help="the user's request, verbatim")
    parser.add_argument("--request-file",
                        help="read the request from a file instead of --request; "
                             "use this whenever the text contains backticks or $ "
                             "so the shell cannot expand it (see fix-r11.py)")
    parser.add_argument("--args-file",
                        help="read call arguments (a JSON object) from a file "
                             "instead of --args")
    parser.add_argument("--tool", help="tool name, e.g. Bash")
    parser.add_argument("--args", default="{}", help="call arguments as a JSON object")
    parser.add_argument("--declared", default="", help="comma-separated declared tools")
    parser.add_argument("--hosts", default="", help="comma-separated hosts the user named")
    parser.add_argument("--executed", default="true", help="true or false")
    parser.add_argument("--agent-mode", default="natural",
                        help='"natural" or "naive-simulation"')
    parser.add_argument("--note", default="", help="optional reviewer note")
    args = parser.parse_args(argv)

    if args.validate:
        return validate(Path(args.validate))
    if not args.run or not args.id or not args.request or not args.tool:
        parser.error("--run, --id, --request and --tool are required to record a call")
    try:
        record = build_record(args)
    except ValueError as exc:
        print(f"record rejected: {exc}", file=sys.stderr)
        return 2
    path = Path(args.run)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"recorded {record['id']} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

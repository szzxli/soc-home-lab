#!/usr/bin/env python3
"""Scrub a harness run log before it leaves the machine.

Replaces secrets and machine-local identifiers with placeholders:
home directory, email addresses, token-looking strings (GitHub
tokens, sk- keys, AWS access keys). Commit SHAs, repo names and
public GitHub usernames are kept — they are public and needed to
verify the run.

The scrubbed file is a starting point, not a clearance: a human
must read every line of the scrubbed log before it is committed.
Raw run logs are never committed.

Usage:
    python3 scrub.py runs/run-2026-11-16-muse-01.jsonl
    # writes runs/run-2026-11-16-muse-01.scrubbed.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RULES = [
    (re.compile(r"/home/[A-Za-z0-9_.\-]+"), "$HOME", "home directory"),
    (re.compile(r"[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[email]", "email address"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{10,}"),
     "[REDACTED-TOKEN]", "GitHub token"),
    (re.compile(r"sk-(?:ant|proj|live|test)-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9_\-]{20,}"),
     "[REDACTED-TOKEN]", "sk- key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-TOKEN]", "AWS access key"),
    (re.compile(r"gsk_[A-Za-z0-9]{20,}"), "[REDACTED-TOKEN]", "Groq key"),
    # Credentials embedded in a URL (user:password@host). Added
    # 2026-11-16 after a shell expansion leaked a proxy credential
    # into a run log: the scrubber must catch what the recorder
    # should never have written.
    (re.compile(r"://[^:/\s]+:[^@\s]+@"), "://[REDACTED]@", "URL-embedded credential"),
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
     "[REDACTED-ID]", "runtime UUID"),
]


def scrub_text(text: str, counts: dict[str, int]) -> str:
    for pattern, replacement, label in RULES:
        text, n = pattern.subn(replacement, text)
        if n:
            counts[label] = counts.get(label, 0) + n
    return text


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <run-log.jsonl>", file=sys.stderr)
        return 2
    source = Path(argv[1])
    target = source.with_name(source.stem + ".scrubbed.jsonl")
    counts: dict[str, int] = {}
    lines = source.read_text(encoding="utf-8").splitlines()
    scrubbed: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        dumped = json.dumps(record, ensure_ascii=False)
        dumped = scrub_text(dumped, counts)
        scrubbed.append(dumped)
    target.write_text("\n".join(scrubbed) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(scrubbed)} records)")
    if counts:
        for label, n in sorted(counts.items()):
            print(f"  redacted {label}: {n}")
    else:
        print("  no redactions applied")
    print("HUMAN REVIEW STILL REQUIRED: read every line before committing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

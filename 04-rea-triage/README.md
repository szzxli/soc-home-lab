# rea-triage

One-command ELF binary triage: heuristics + score-based verdict + a
one-page analyst report.

Inspired by this week's #1 GitHub trending project
[`morluto/rea`](https://github.com/morluto/rea) ("reverse engineer anything
with agents"). REA exposes 50+ granular agent-facing subcommands and emits
machine-oriented Evidence JSON. rea-triage is the human-friendly layer on
top of that *idea*: one command in, one readable page out.

> **Honesty note:** verdicts are *triage signals*, not convictions.
> "malicious" means "prioritize for deep analysis (Ghidra / REA / sandbox)",
> never "this is malware". Heuristics have false positives by design.
> The binary is never executed — all analysis is static.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Only dependency is `pyelftools` (pure Python). `pytest` for the test suite.

## Usage

```bash
python triage.py /bin/ls --output report.md
```

Options:

| Flag | Description |
|------|-------------|
| `--output` | (required) Path for the markdown report |
| `--rea` | Attempt REA `inspect-binary-layout` enrichment (optional) |
| `--json` | Optional path to write raw triage JSON |

Example output:

```
Triaged /bin/ls: verdict=benign (score 1, 1 finding(s)).
Report written to report.md
```

## What it checks

| Check | Signal | Severity |
|-------|--------|----------|
| Section entropy | High-entropy (>7.5 bits/byte) code sections suggest packing/encryption | medium |
| W^X sections | Writable + executable section (shellcode staging) | high |
| Suspicious imports | `ptrace`, `memfd_create`, `process_vm_writev`, `system`, … | high/medium/low |
| String IOCs | Hardcoded IPs, URLs, sensitive paths (`/etc/shadow`), keywords | high/medium |
| Context | Stripped / statically linked (analyst context, not accusations) | low |

Scoring: high=3, medium=2, low=1. Verdict bands: 0–1 benign,
2–4 suspicious, 5+ malicious.

## REA enrichment (optional)

If the [`rea`](https://github.com/morluto/rea) CLI is installed and its ELF
provider is configured, `--rea` folds `inspect-binary-layout` evidence
(entry point, section inventory) into the report. When REA is absent or its
provider is unavailable, triage continues and the report says so
explicitly — it never fails because REA is missing.

## Running tests

```bash
python -m pytest tests/ -v
```

10 tests, all against synthetic fixtures (no real malware involved).

## Project structure

```
04-rea-triage/
├── triage.py        # collect → heuristics → score → report
├── requirements.txt # pyelftools, pytest
└── tests/
    └── test_triage.py
```

## Limitations

- ELF only (Linux binaries). PE/Mach-O/APK are out of scope.
- Entropy and import heuristics are coarse — packers can be custom,
  and legitimate software imports `system` too. The report is a
  starting point for an analyst, not an AV verdict.
- String IOCs are regex-based; obfuscated strings are missed.

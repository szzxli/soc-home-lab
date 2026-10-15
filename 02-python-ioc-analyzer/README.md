# Python IOC Analyzer

A lightweight command-line tool that parses AWS CloudTrail JSON logs and applies
three heuristic detectors to surface suspicious activity: **unusual-region logins**,
**brute-force login bursts**, and **high-risk IAM / EC2 API calls**. Flagged external
IPs can be enriched via the [AbuseIPDB](https://www.abuseipdb.com/) API.

This is one of three home-lab projects demonstrating hands-on SOC analyst skills:
data parsing, detection logic, and clear incident-ready reporting.

> **Honesty note:** all sample data in this project is **synthetic training data** —
> fabricated events, IPs, user names, and timestamps. It is never presented as
> real log data.

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.9+ and the `requests` library (for AbuseIPDB enrichment);
`pytest` for running the test suite.

## Usage

```bash
python ioc_analyzer.py --input sample_data/sample_cloudtrail.json --output report.md
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to CloudTrail JSON file (`Records` array format) |
| `--output` | (required) | Path where the markdown report is written |
| `--window-minutes` | `10` | Sliding window for the brute-force detector |
| `--brute-force-threshold` | `5` | Failed logins within the window that trigger a finding |

## Detection logic

| Detector | What it looks for | Threshold / logic |
|----------|-------------------|-------------------|
| `unusual_geo` | Successful `ConsoleLogin` from a source IP **outside** a small built-in table of common IP ranges | Demo heuristic — flagged hits should be verified with a real GeoIP database (e.g. MaxMind GeoLite2) |
| `brute_force` | Failed `ConsoleLogin` bursts from the same source IP inside a sliding window | ≥ 5 failures within 10 minutes (both tunable via CLI flags) |
| `suspicious_api` | IAM policy mutations and other high-risk calls: `PutUserPolicy`, `AttachUserPolicy`, `AttachRolePolicy`, `CreateAccessKey`, `DeleteTrail`, `StopLogging`, `RunInstances` | Each mapped to a risk level (high/medium) with a written rationale |

Risk levels: **high** (act now — contain and investigate), **medium** (investigate),
**low** (context).

## AbuseIPDB enrichment (optional)

Set the `ABUSEIPDB_API_KEY` environment variable to enrich flagged IPs:

```bash
export ABUSEIPDB_API_KEY="your-key-here"
python ioc_analyzer.py --input sample_data/sample_cloudtrail.json --output report.md
```

**Without a key, enrichment is skipped and the report says so explicitly** — the
tool never fails or exits with an error because the key is missing.

## Example output

```
Analyzed 19 records; 5 finding(s).
AbuseIPDB enrichment skipped (ABUSEIPDB_API_KEY not set).
Report written to /tmp/demo_report.md
```

The markdown report contains a **Summary** (record counts, time range, top events,
findings by risk), a **Findings** table (time / event / actor / source IP /
risk / evidence), an **IP enrichment** section (or a clear "skipped" notice),
and **Recommendations** for next steps.

## Running tests

```bash
python -m pytest tests/ -v
```

The suite covers all three detectors (flagged and clean cases) plus the
no-API-key enrichment path — 9 tests using small inline synthetic fixtures.

## Project structure

```
02-python-ioc-analyzer/
├── ioc_analyzer.py            # the analyzer (parse → detect → enrich → report)
├── requirements.txt           # requests, pytest
├── sample_data/
│   └── sample_cloudtrail.json # SYNTHETIC training sample (labeled in-file)
└── tests/
    └── test_analyzer.py       # pytest suite
```

## Limitations

- The geo heuristic is intentionally simplistic (hard-coded IP prefix table) —
  a demo of the detection *pattern*, not a production geolocation check.
- AbuseIPDB enrichment is best-effort: API/network failures are captured per-IP
  and never abort report generation.
- CloudTrail-only input; multi-source correlation is out of scope for this project.

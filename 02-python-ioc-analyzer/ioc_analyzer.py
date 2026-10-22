#!/usr/bin/env python3
"""IOC Analyzer — heuristic detection of suspicious AWS CloudTrail activity.

This tool parses AWS CloudTrail JSON logs (``Records`` array format) and
applies three lightweight heuristic detectors:

1. ``unusual_geo``      — a successful ConsoleLogin from a source IP that
                          does NOT fall inside a small built-in table of
                          known/common IP ranges. This is a *demonstration*
                          heuristic only; a production system should use a
                          proper GeoIP database (e.g. MaxMind GeoLite2).
2. ``brute_force``      — N or more failed ConsoleLogin attempts from the
                          same source IP inside a sliding time window
                          (default: >= 5 failures in 10 minutes).
3. ``suspicious_api``   — IAM policy mutations and other high-risk API
                          calls (e.g. ``iam:PutUserPolicy``,
                          ``iam:AttachUserPolicy``, ``ec2:RunInstances``).

IPs seen in findings are optionally enriched via the AbuseIPDB API
(``https://api.abuseipdb.com/api/v2/check``). The API key is read from the
``ABUSEIPDB_API_KEY`` environment variable. When the variable is not set,
enrichment is skipped and the report states that explicitly instead of
failing.

Usage:
    python ioc_analyzer.py --input sample_data/sample_cloudtrail.json --output report.md
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

# DEMONSTRATION heuristic only: a tiny table of "common" IP ranges standing
# in for real GeoIP. In production, replace this with a GeoIP lookup (e.g.
# MaxMind GeoLite2) and derive "common" from your org's baseline.
COMMON_IP_NETWORKS: Tuple[str, ...] = (
    "3.0.0.0/8",      # AWS US-East
    "13.52.0.0/16",   # Example US corporate egress (fictional)
    "44.192.0.0/10",  # AWS US-East public range
    "52.0.0.0/8",     # AWS US-East public range
    "54.0.0.0/8",     # AWS US-East public range
    "72.14.0.0/16",   # Example US corporate egress (fictional)
)

# High-risk event names mapped to a risk level and rationale.
SUSPICIOUS_API_CALLS: Dict[str, Tuple[str, str]] = {
    "PutUserPolicy": (
        "high",
        "Inline IAM policy attached directly to a user — common persistence technique.",
    ),
    "AttachUserPolicy": (
        "high",
        "Managed IAM policy attached to a user — possible privilege escalation.",
    ),
    "AttachRolePolicy": (
        "high",
        "Managed IAM policy attached to a role — possible privilege escalation.",
    ),
    "CreateAccessKey": (
        "medium",
        "New IAM access key created — check whether it was authorized.",
    ),
    "DeleteTrail": (
        "high",
        "CloudTrail logging disabled — classic defense-evasion indicator.",
    ),
    "StopLogging": (
        "high",
        "CloudTrail logging stopped — classic defense-evasion indicator.",
    ),
    "RunInstances": (
        "medium",
        "EC2 instances launched — investigate for cryptojacking / resource abuse.",
    ),
}

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_cloudtrail(path: str) -> List[Dict[str, Any]]:
    """Load CloudTrail records from *path*.

    Expects the standard CloudTrail JSON format with a top-level
    ``Records`` array. Returns the list of record dicts (possibly empty).
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        records = data.get("Records", [])
    elif isinstance(data, list):  # tolerate a bare array of records
        records = data
    else:
        records = []
    return [r for r in records if isinstance(r, dict)]


def _parse_event_time(value: Optional[str]) -> Optional[datetime]:
    """Parse a CloudTrail ``eventTime`` into an aware datetime, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _source_ip(record: Dict[str, Any]) -> Optional[str]:
    return record.get("sourceIPAddress")


def _actor(record: Dict[str, Any]) -> str:
    """Best-effort human-readable principal name for a record."""
    user_identity = record.get("userIdentity")
    if not isinstance(user_identity, dict):  # missing / null / malformed in noisy exports
        user_identity = {}
    for key in ("userName", "principalId", "arn"):
        value = user_identity.get(key)
        if value:
            return str(value)
    return "unknown"


def _event_name(record: Dict[str, Any]) -> str:
    return str(record.get("eventName") or "unknown")


def _is_console_login(record: Dict[str, Any]) -> bool:
    return _event_name(record) == "ConsoleLogin"


def _login_succeeded(record: Dict[str, Any]) -> bool:
    """True when a ConsoleLogin record indicates success."""
    response = record.get("responseElements")
    if isinstance(response, dict):
        status = response.get("ConsoleLogin")
        if status in ("Success", "Failure"):
            return status == "Success"
    # Fall back to errorCode: its presence means the call failed.
    return "errorCode" not in record


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

Finding = Dict[str, Any]


def _ip_in_common_ranges(ip: str, networks: Tuple[str, ...]) -> bool:
    """Check whether *ip* belongs to one of the built-in common networks."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net):
                return True
        except ValueError:
            continue
    return False


def detect_unusual_geo_logins(
    records: List[Dict[str, Any]],
    networks: Tuple[str, ...] = COMMON_IP_NETWORKS,
) -> List[Finding]:
    """Flag successful ConsoleLogins from IPs outside the common-range table.

    NOTE: This is a *demonstration* heuristic. The "common region" table is a
    tiny hard-coded list of IP prefixes — it does not perform real
    geolocation. Treat every hit as a lead that requires GeoIP verification.
    """
    findings: List[Finding] = []
    for record in records:
        if not _is_console_login(record) or not _login_succeeded(record):
            continue
        ip = _source_ip(record)
        if not ip or _ip_in_common_ranges(ip, networks):
            continue
        findings.append(
            {
                "detector": "unusual_geo",
                "time": record.get("eventTime", "unknown"),
                "event": _event_name(record),
                "actor": _actor(record),
                "ip": ip,
                "risk": "medium",
                "evidence": (
                    "Successful ConsoleLogin from an IP outside the "
                    "built-in common-range table (demo heuristic; "
                    "verify with GeoIP)."
                ),
            }
        )
    return findings


def detect_brute_force_logins(
    records: List[Dict[str, Any]],
    window_minutes: int = 10,
    threshold: int = 5,
) -> List[Finding]:
    """Flag IPs with >= *threshold* failed logins inside *window_minutes*.

    Uses a sliding window per source IP over failed ConsoleLogin events and
    emits at most one finding per IP (for the earliest window that trips).
    """
    failures_by_ip: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
    for record in records:
        if not _is_console_login(record) or _login_succeeded(record):
            continue
        ip = _source_ip(record)
        ts = _parse_event_time(record.get("eventTime"))
        if not ip or ts is None:
            continue
        failures_by_ip[ip].append((ts, record))

    window = timedelta(minutes=window_minutes)
    findings: List[Finding] = []
    for ip, events in failures_by_ip.items():
        events.sort(key=lambda item: item[0])
        for i in range(len(events)):
            j = i
            while j < len(events) and events[j][0] - events[i][0] <= window:
                j += 1
            count = j - i
            if count >= threshold:
                first_ts = events[i][0].isoformat()
                last_ts = events[j - 1][0].isoformat()
                findings.append(
                    {
                        "detector": "brute_force",
                        "time": first_ts,
                        "event": "ConsoleLogin (failed)",
                        "actor": _actor(events[i][1]),
                        "ip": ip,
                        "risk": "high",
                        "evidence": (
                            f"{count} failed ConsoleLogin attempts from {ip} "
                            f"within {window_minutes} minutes "
                            f"({first_ts} → {last_ts}; threshold {threshold})."
                        ),
                    }
                )
                break  # one finding per IP
    return findings


def detect_suspicious_api_calls(
    records: List[Dict[str, Any]],
    watchlist: Dict[str, Tuple[str, str]] = SUSPICIOUS_API_CALLS,
) -> List[Finding]:
    """Flag records whose event name appears in the high-risk watchlist."""
    findings: List[Finding] = []
    for record in records:
        name = _event_name(record)
        if name not in watchlist:
            continue
        risk, rationale = watchlist[name]
        params = record.get("requestParameters") or {}
        findings.append(
            {
                "detector": "suspicious_api",
                "time": record.get("eventTime", "unknown"),
                "event": name,
                "actor": _actor(record),
                "ip": _source_ip(record) or "n/a",
                "risk": risk,
                "evidence": f"{rationale} Request parameters: {json.dumps(params)}",
            }
        )
    return findings


def detect_all(
    records: List[Dict[str, Any]],
    brute_force_window: int = 10,
    brute_force_threshold: int = 5,
) -> List[Finding]:
    """Run every detector and return the combined findings."""
    findings: List[Finding] = []
    findings.extend(detect_unusual_geo_logins(records))
    findings.extend(
        detect_brute_force_logins(
            records, window_minutes=brute_force_window, threshold=brute_force_threshold
        )
    )
    findings.extend(detect_suspicious_api_calls(records))
    findings.sort(key=lambda f: str(f.get("time")))
    return findings


# ---------------------------------------------------------------------------
# Enrichment (AbuseIPDB)
# ---------------------------------------------------------------------------


def enrich_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> Dict[str, Any]:
    """Query AbuseIPDB for *ip*.

    Returns a dict with the API result on success, or ``{"error": ...}``
    when the request fails (never raises to the caller).
    """
    try:
        resp = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json().get("data", {})
        return {
            "abuse_confidence_score": payload.get("abuseConfidenceScore"),
            "country_code": payload.get("countryCode"),
            "usage_type": payload.get("usageType"),
            "total_reports": payload.get("totalReports"),
            "last_reported_at": payload.get("lastReportedAt"),
        }
    except Exception as exc:  # network/API problems must not kill the report
        return {"error": f"AbuseIPDB lookup failed: {exc}"}


def enrich_findings(
    findings: List[Finding], api_key: Optional[str]
) -> Tuple[List[Finding], bool]:
    """Enrich findings that carry an external IP via AbuseIPDB.

    Returns ``(findings, enrichment_skipped)``. When *api_key* is falsy the
    enrichment step is skipped entirely and every finding is annotated as
    such — the report generation continues normally.
    """
    if not api_key:
        for finding in findings:
            finding["enrichment"] = "skipped (no ABUSEIPDB_API_KEY set)"
        return findings, True

    cache: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        ip = finding.get("ip")
        if not ip or ip == "n/a":
            finding["enrichment"] = "not applicable (no external IP)"
            continue
        if ip not in cache:
            cache[ip] = enrich_abuseipdb(ip, api_key)
        finding["enrichment"] = cache[ip]
    return findings, False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def build_summary(records: List[Dict[str, Any]], findings: List[Finding]) -> Dict[str, Any]:
    """Compute aggregate statistics for the report summary section."""
    events: Dict[str, int] = defaultdict(int)
    ips: set = set()
    actors: set = set()
    times: List[datetime] = []
    for record in records:
        events[_event_name(record)] += 1
        ip = _source_ip(record)
        if ip:
            ips.add(ip)
        actors.add(_actor(record))
        ts = _parse_event_time(record.get("eventTime"))
        if ts:
            times.append(ts)

    risk_counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        risk_counts[finding.get("risk", "unknown")] += 1

    summary: Dict[str, Any] = {
        "total_records": len(records),
        "time_range": (
            f"{min(times).isoformat()} → {max(times).isoformat()}" if times else "n/a"
        ),
        "unique_source_ips": len(ips),
        "unique_actors": len(actors),
        "top_events": sorted(events.items(), key=lambda kv: kv[1], reverse=True)[:10],
        "total_findings": len(findings),
        "findings_by_risk": dict(risk_counts),
    }
    return summary


def _render_enrichment(value: Any) -> str:
    if isinstance(value, dict):
        if "error" in value:
            return value["error"]
        parts = []
        if value.get("country_code"):
            parts.append(f"country={value['country_code']}")
        if value.get("abuse_confidence_score") is not None:
            parts.append(f"abuse score={value['abuse_confidence_score']}")
        if value.get("total_reports") is not None:
            parts.append(f"reports={value['total_reports']}")
        if value.get("usage_type"):
            parts.append(f"usage={value['usage_type']}")
        return "; ".join(parts) if parts else "no data"
    return str(value or "n/a")


def generate_markdown_report(
    summary: Dict[str, Any], findings: List[Finding], enrichment_skipped: bool
) -> str:
    """Render the full markdown report."""
    lines: List[str] = []
    lines.append("# IOC Analysis Report")
    lines.append("")
    lines.append(
        "_Generated by `ioc_analyzer.py`. Sample data used for development and "
        "testing is synthetic training data — never real log data._"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total records analyzed: **{summary['total_records']}**")
    lines.append(f"- Time range: {summary['time_range']}")
    lines.append(f"- Unique source IPs: {summary['unique_source_ips']}")
    lines.append(f"- Unique actors: {summary['unique_actors']}")
    lines.append(f"- Total findings: **{summary['total_findings']}**")
    for risk, count in sorted(summary["findings_by_risk"].items()):
        lines.append(f"  - {risk}: {count}")
    lines.append("")
    lines.append("### Top events")
    lines.append("")
    lines.append("| Event | Count |")
    lines.append("|-------|-------|")
    for event, count in summary["top_events"]:
        lines.append(f"| {event} | {count} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No suspicious activity detected by the heuristic detectors.")
    else:
        lines.append("| # | Time | Event | Actor | Source IP | Risk | Evidence |")
        lines.append("|---|------|-------|-------|-----------|------|----------|")
        for i, finding in enumerate(findings, 1):
            evidence = str(finding.get("evidence", "")).replace("|", "\\|")
            lines.append(
                f"| {i} | {finding.get('time')} | {finding.get('event')} | "
                f"{finding.get('actor')} | {finding.get('ip')} | "
                f"**{finding.get('risk')}** | {evidence} |"
            )
        lines.append("")
        lines.append("### IP enrichment (AbuseIPDB)")
        lines.append("")
        if enrichment_skipped:
            lines.append(
                "> Enrichment **skipped**: the `ABUSEIPDB_API_KEY` environment "
                "variable was not set. Findings above are heuristic-only."
            )
        else:
            for i, finding in enumerate(findings, 1):
                lines.append(
                    f"- Finding #{i} (`{finding.get('ip')}`): "
                    f"{_render_enrichment(finding.get('enrichment'))}"
                )
    lines.append("")
    lines.append("## Recommendations")
    lines.append("")
    if any(f.get("risk") == "high" for f in findings):
        lines.append(
            "1. **Contain first**: rotate credentials and revoke sessions for any "
            "actor tied to a HIGH finding before deeper investigation."
        )
        lines.append(
            "2. **Review IAM changes**: verify each flagged policy mutation was "
            "approved via change control; roll back anything unauthorized."
        )
    lines.append(
        f"{3 if any(f.get('risk') == 'high' for f in findings) else 1}. "
        "Correlate flagged IPs against WAF/VPN/firewall logs to confirm whether "
        "the activity originates outside your normal footprint."
    )
    lines.append(
        "- If AbuseIPDB enrichment was skipped, re-run with "
        "`ABUSEIPDB_API_KEY` set for abuse-confidence scores on the flagged IPs."
    )
    lines.append(
        "- Replace the demo geo heuristic with a proper GeoIP database "
        "(e.g. MaxMind GeoLite2) before relying on these results operationally."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze AWS CloudTrail logs with lightweight heuristics and "
            "optionally enrich flagged IPs via AbuseIPDB."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a CloudTrail JSON file (Records array format).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path where the markdown report will be written.",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Brute-force detector window in minutes (default: 10).",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="Failed logins within the window that trigger a finding (default: 5).",
    )
    parser.add_argument(
        "--sigma-rules",
        default=None,
        metavar="DIR",
        help=(
            "Optional directory of Sigma YAML rules evaluated by sigma_engine "
            "against the same records; Sigma findings are merged into the report."
        ),
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        records = parse_cloudtrail(args.input)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in input file: {exc}", file=sys.stderr)
        return 1

    findings = detect_all(
        records,
        brute_force_window=args.window_minutes,
        brute_force_threshold=args.brute_force_threshold,
    )

    # Optional Sigma rule layer: same records, community-standard rule format.
    if args.sigma_rules:
        try:
            from sigma_engine import load_rules, scan_records

            sigma_rules, load_problems = load_rules(args.sigma_rules)
            sigma_findings, scan_problems = scan_records(sigma_rules, records)
            findings.extend(sigma_findings)
            findings.sort(key=lambda f: str(f.get("time")))
            for problem in load_problems + scan_problems:
                print(f"Sigma warning: {problem}", file=sys.stderr)
            print(f"Sigma: {len(sigma_rules)} rule(s), "
                  f"{len(sigma_findings)} finding(s).")
        except ImportError:
            print("Sigma warning: pysigma is not installed; "
                  "--sigma-rules ignored.", file=sys.stderr)

    api_key = os.environ.get(ABUSEIPDB_API_KEY_ENV)
    findings, enrichment_skipped = enrich_findings(findings, api_key)

    summary = build_summary(records, findings)
    report = generate_markdown_report(summary, findings, enrichment_skipped)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"Analyzed {summary['total_records']} records; "
          f"{summary['total_findings']} finding(s).")
    if enrichment_skipped:
        print(f"AbuseIPDB enrichment skipped ({ABUSEIPDB_API_KEY_ENV} not set).")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Unit tests for ioc_analyzer.py.

All records used here are small synthetic fixtures constructed inline —
no real log data is used anywhere in this suite.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ioc_analyzer import (
    build_summary,
    detect_brute_force_logins,
    detect_suspicious_api_calls,
    detect_unusual_geo_logins,
    enrich_findings,
    generate_markdown_report,
    parse_cloudtrail,
)


def _console_login(ip, succeeded=True, when="2026-10-10T08:00:00Z"):
    """Build a synthetic ConsoleLogin record."""
    return {
        "eventName": "ConsoleLogin",
        "eventTime": when,
        "sourceIPAddress": ip,
        "userIdentity": {"userName": "jdoe"},
        "responseElements": {"ConsoleLogin": "Success" if succeeded else "Failure"},
        **({} if succeeded else {"errorCode": "Failed authentication"}),
    }


def test_unusual_geo_login_flagged():
    """A successful login from an IP outside the common-range table is flagged."""
    records = [_console_login("185.220.101.4", succeeded=True)]
    findings = detect_unusual_geo_logins(records)
    assert len(findings) == 1
    assert findings[0]["detector"] == "unusual_geo"
    assert findings[0]["ip"] == "185.220.101.4"
    assert findings[0]["risk"] == "medium"


def test_unusual_geo_login_clean_for_common_ip():
    """A successful login from a common-range IP produces no finding."""
    records = [_console_login("13.52.44.19", succeeded=True)]
    assert detect_unusual_geo_logins(records) == []


def test_unusual_geo_login_ignores_failed_logins():
    """Failed logins from odd IPs are not the geo detector's job (brute-force's)."""
    records = [_console_login("185.220.101.4", succeeded=False)]
    assert detect_unusual_geo_logins(records) == []


def test_brute_force_login_flagged():
    """5+ failures from one IP inside 10 minutes produce one finding."""
    records = [
        _console_login("91.108.55.77", succeeded=False, when=f"2026-10-10T12:0{i}:00Z")
        for i in range(6)
    ]
    findings = detect_brute_force_logins(records, window_minutes=10, threshold=5)
    assert len(findings) == 1
    assert findings[0]["detector"] == "brute_force"
    assert findings[0]["ip"] == "91.108.55.77"
    assert findings[0]["risk"] == "high"
    assert "6 failed" in findings[0]["evidence"]


def test_brute_force_login_below_threshold_not_flagged():
    """4 failures stay under the default threshold of 5."""
    records = [
        _console_login("91.108.55.77", succeeded=False, when=f"2026-10-10T12:0{i}:00Z")
        for i in range(4)
    ]
    assert detect_brute_force_logins(records) == []


def test_brute_force_login_outside_window_not_flagged():
    """Failures spread over more than 10 minutes are not a burst."""
    records = [
        _console_login("91.108.55.77", succeeded=False, when=f"2026-10-10T12:{i:02d}:00Z")
        for i in (0, 15, 30, 45, 60, 75)
    ]
    assert detect_brute_force_logins(records, window_minutes=10, threshold=5) == []


def test_suspicious_api_calls_flagged():
    """iam:PutUserPolicy and iam:AttachUserPolicy are flagged as high risk."""
    records = [
        {
            "eventName": "PutUserPolicy",
            "eventTime": "2026-10-10T13:22:10Z",
            "sourceIPAddress": "185.220.101.4",
            "userIdentity": {"userName": "jdoe"},
            "requestParameters": {"policyName": "PersistPolicy"},
        },
        {
            "eventName": "AttachUserPolicy",
            "eventTime": "2026-10-10T13:25:47Z",
            "sourceIPAddress": "185.220.101.4",
            "userIdentity": {"userName": "jdoe"},
            "requestParameters": {
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
        },
        {
            "eventName": "ListBuckets",  # benign — must NOT be flagged
            "eventTime": "2026-10-10T13:30:00Z",
            "sourceIPAddress": "13.52.44.19",
            "userIdentity": {"userName": "jdoe"},
        },
    ]
    findings = detect_suspicious_api_calls(records)
    assert len(findings) == 2
    assert {f["event"] for f in findings} == {"PutUserPolicy", "AttachUserPolicy"}
    assert all(f["risk"] == "high" for f in findings)


def test_enrichment_skipped_without_api_key():
    """Without an API key, enrichment is skipped — never an error exit."""
    findings = [
        {
            "detector": "unusual_geo",
            "time": "2026-10-10T08:00:00Z",
            "event": "ConsoleLogin",
            "actor": "jdoe",
            "ip": "185.220.101.4",
            "risk": "medium",
            "evidence": "demo",
        }
    ]
    enriched, skipped = enrich_findings(findings, None)
    assert skipped is True
    assert enriched[0]["enrichment"] == "skipped (no ABUSEIPDB_API_KEY set)"

    summary = build_summary([], enriched)
    report = generate_markdown_report(summary, enriched, enrichment_skipped=True)
    assert "skipped" in report.lower()
    assert "ABUSEIPDB_API_KEY" in report


def test_parse_cloudtrail_reads_records(tmp_path):
    """parse_cloudtrail handles the standard {Records: [...]} envelope."""
    import json

    path = tmp_path / "trail.json"
    path.write_text(json.dumps({"Records": [_console_login("1.2.3.4")]}))
    records = parse_cloudtrail(str(path))
    assert len(records) == 1
    assert records[0]["sourceIPAddress"] == "1.2.3.4"

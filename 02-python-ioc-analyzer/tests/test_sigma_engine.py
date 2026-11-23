"""Unit tests for sigma_engine.py.

All rules and records used here are small synthetic fixtures constructed
inline or shipped under ``rules/`` — no real log data is used anywhere in
this suite.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sigma_engine import load_rules, rule_matches, scan_records

RULES_DIR = str(Path(__file__).resolve().parent.parent / "rules")
AUTH_LOG = Path(__file__).resolve().parent.parent / "sample_data" / "sample_auth_log.json"


def _failed_login():
    return {
        "eventName": "ConsoleLogin",
        "eventTime": "2026-10-19T08:00:00Z",
        "sourceIPAddress": "203.0.113.45",
        "responseElements": {"ConsoleLogin": "Failure"},
        "userIdentity": {"userName": "alice"},
    }


def _ok_login():
    return {
        "eventName": "ConsoleLogin",
        "eventTime": "2026-10-19T08:01:00Z",
        "sourceIPAddress": "198.51.100.7",
        "responseElements": {"ConsoleLogin": "Success"},
        "userIdentity": {"userName": "bob"},
    }


def _encoded_cmd():
    return {
        "event_type": "process_creation",
        "timestamp": "2026-10-19T08:02:00Z",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACkA",
        "userName": "SYSTEM",
    }


def _legit_admin_tool():
    # Same encoded pattern but from the allow-listed admin tool -> filtered.
    return {
        "event_type": "process_creation",
        "timestamp": "2026-10-19T08:03:00Z",
        "Image": "C:\\Tools\\legit-admin-tool.exe",
        "CommandLine": "legit-admin-tool.exe -EncodedCommand e30=",
        "userName": "admin",
    }


def _benign_cmd():
    return {
        "event_type": "process_creation",
        "timestamp": "2026-10-19T08:04:00Z",
        "Image": "C:\\Windows\\notepad.exe",
        "CommandLine": "notepad.exe C:\\notes.txt",
        "userName": "alice",
    }


def _delete_trail():
    return {
        "eventName": "DeleteTrail",
        "eventTime": "2026-10-19T08:05:00Z",
        "sourceIPAddress": "203.0.113.45",
        "userIdentity": {"userName": "mallory"},
    }


def _run_instances():
    return {
        "eventName": "RunInstances",
        "eventTime": "2026-10-19T08:06:00Z",
        "sourceIPAddress": "198.51.100.7",
        "userIdentity": {"userName": "bob"},
    }


def _rules_by_title():
    rules, problems = load_rules(RULES_DIR)
    assert not problems, f"rule load problems: {problems}"
    return {r.title: r for r in rules}


def test_all_sample_rules_load():
    rules, problems = load_rules(RULES_DIR)
    assert not problems
    assert len(rules) == 6


def test_new_auth_rules_on_sample_log():
    all_rules = _rules_by_title()
    new_titles = {
        "Failed AWS Console Login for Root User",
        "AWS Console Login Without MFA",
        "AWS Console Login from Scripted User Agent",
    }
    rules = [all_rules[t] for t in sorted(new_titles)]
    records = json.loads(AUTH_LOG.read_text(encoding="utf-8"))
    assert len(records) == 8
    findings, problems = scan_records(rules, records)
    assert not problems
    # TP: exactly the 4 malicious records, one finding each; the 4 benign
    # records (MFA success, non-root failure, MFA root success) fire nothing.
    assert len(findings) == 4
    titles = sorted(f["rule_title"] for f in findings)
    assert titles == [
        "AWS Console Login Without MFA",
        "AWS Console Login from Scripted User Agent",
        "AWS Console Login from Scripted User Agent",
        "Failed AWS Console Login for Root User",
    ]
    actors = sorted(f["actor"] for f in findings)
    assert actors == ["bob", "dave", "frank", "root"]


def test_root_login_rule_needs_failure():
    rules = _rules_by_title()
    rule = rules["Failed AWS Console Login for Root User"]
    failed_root = {
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Failure"},
        "userIdentity": {"userName": "root"},
    }
    ok_root = dict(failed_root)
    ok_root["responseElements"] = {"ConsoleLogin": "Success"}
    assert rule_matches(rule, failed_root)
    assert not rule_matches(rule, ok_root)  # root success must not fire


def test_mfa_rule_needs_no_mfa():
    rules = _rules_by_title()
    rule = rules["AWS Console Login Without MFA"]
    no_mfa = {
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
        "userIdentity": {"userName": "bob"},
    }
    with_mfa = dict(no_mfa)
    with_mfa["additionalEventData"] = {"MFAUsed": "Yes"}
    assert rule_matches(rule, no_mfa)
    assert not rule_matches(rule, with_mfa)  # MFA success must not fire


def test_scripted_ua_rule_ignores_browsers():
    rules = _rules_by_title()
    rule = rules["AWS Console Login from Scripted User Agent"]
    scripted = {
        "eventName": "ConsoleLogin",
        "userAgent": "python-requests/2.31.0",
        "userIdentity": {"userName": "frank"},
    }
    browser = dict(scripted)
    browser["userAgent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert rule_matches(rule, scripted)
    assert not rule_matches(rule, browser)  # browser UA must not fire


def test_failed_login_rule_fires():
    rules = _rules_by_title()
    rule = rules["AWS Console Login Failure"]
    assert rule_matches(rule, _failed_login())
    assert not rule_matches(rule, _ok_login())  # success must not fire
    assert not rule_matches(rule, _encoded_cmd())  # unrelated record


def test_encoded_command_rule_with_filter():
    rules = _rules_by_title()
    rule = rules["Suspicious Encoded Command Line"]
    assert rule_matches(rule, _encoded_cmd())
    assert not rule_matches(rule, _legit_admin_tool())  # filter excludes it
    assert not rule_matches(rule, _benign_cmd())


def test_logging_disabled_rule_list_values():
    rules = _rules_by_title()
    rule = rules["CloudTrail Logging Disabled"]
    assert rule_matches(rule, _delete_trail())
    assert not rule_matches(rule, _run_instances())


def test_scan_records_end_to_end():
    rules, _ = load_rules(RULES_DIR)
    records = [
        _failed_login(),
        _ok_login(),
        _encoded_cmd(),
        _legit_admin_tool(),
        _benign_cmd(),
        _delete_trail(),
        _run_instances(),
    ]
    findings, problems = scan_records(rules, records)
    assert not problems
    # TP: exactly the 3 malicious records, one finding each.
    assert len(findings) == 3
    titles = sorted(f["rule_title"] for f in findings)
    assert titles == [
        "AWS Console Login Failure",
        "CloudTrail Logging Disabled",
        "Suspicious Encoded Command Line",
    ]
    for f in findings:
        assert f["detector"] == "sigma"
        assert f["risk"] in ("medium", "high")
        assert f["rule_id"].startswith("a1b2c3d4-")


def test_malformed_rule_skipped_not_crash(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n  : : :\n", encoding="utf-8")
    rules, problems = load_rules(str(tmp_path))
    assert rules == []
    assert len(problems) == 1
    assert "bad.yml" in problems[0]


def test_unsupported_modifier_skipped_not_crash(tmp_path):
    yml = tmp_path / "b64.yml"
    yml.write_text(
        "title: B64 Test\n"
        "logsource:\n  product: test\n"
        "detection:\n  sel:\n    Cmd|base64: 'aGVsbG8='\n"
        "  condition: sel\n"
        "level: low\n",
        encoding="utf-8",
    )
    rules, problems = load_rules(str(tmp_path))
    assert len(rules) == 1
    findings, scan_problems = scan_records(rules, [{"Cmd": "hello"}])
    assert findings == []
    assert any("B64 Test" in p for p in scan_problems)

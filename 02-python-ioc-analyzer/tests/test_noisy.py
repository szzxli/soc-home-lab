"""Tests for the NOISY synthetic CloudTrail sample (sample_cloudtrail_noisy.json).

The noisy sample is meant to produce false positives: these tests pin the
exact TP / FP / FN numbers documented in NOISY_DATA.md, check the analyzer
survives missing and malformed fields, that the generator is deterministic,
and that the browser port (web/js/ioc.js) returns the same findings as the
Python CLI on both the clean and the noisy sample (skipped without node).
"""
import ipaddress
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

from ioc_analyzer import (  # noqa: E402
    COMMON_IP_NETWORKS, _ip_in_common_ranges, build_summary, detect_all,
    generate_markdown_report, parse_cloudtrail,
)

NOISY = HERE / "sample_data" / "sample_cloudtrail_noisy.json"
CLEAN = HERE / "sample_data" / "sample_cloudtrail.json"
TRUTH = json.loads((HERE / "sample_data" / "sample_cloudtrail_noisy.truth.json").read_text())
DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def noisy():
    return parse_cloudtrail(str(NOISY))


def _label(f):
    return "TP" if f["ip"] in TRUTH["malicious_ips"] or f["actor"] in TRUTH["malicious_actors"] else "FP"


def test_noisy_has_volume_and_messy_records(noisy):
    raw = json.loads(NOISY.read_text())["Records"]
    assert len(raw) >= 2500
    assert len(noisy) == len(raw) - 3                     # 3 non-object entries dropped
    assert any("userIdentity" not in r for r in noisy)
    assert any(r.get("userIdentity") == {} for r in noisy)
    assert any("eventTime" not in r for r in noisy)
    assert any(r.get("sourceIPAddress") == "" for r in noisy)
    assert any(r.get("eventName") == "ConsoleLogin" and r.get("responseElements") is None for r in noisy)


def test_noisy_report_renders(noisy):
    findings = detect_all(noisy)
    report = generate_markdown_report(build_summary(noisy, findings), findings, True)
    assert "Total records analyzed: **2867**" in report


def test_noisy_scorecard_matches_documented_numbers(noisy):
    findings = detect_all(noisy)
    per = Counter((f["detector"], _label(f)) for f in findings)
    assert per == Counter({("brute_force", "TP"): 1, ("brute_force", "FP"): 1,
                           ("unusual_geo", "TP"): 1, ("unusual_geo", "FP"): 4,
                           ("suspicious_api", "TP"): 6, ("suspicious_api", "FP"): 18})
    # the low-and-slow spray (1 try / 15 min) is the documented false negative
    assert not any(f["detector"] == "brute_force" and f["ip"] == "198.51.100.200" for f in findings)


def test_noisy_false_positives_are_the_documented_look_alikes(noisy):
    fps = [f for f in detect_all(noisy) if _label(f) == "FP"]
    assert {f["ip"] for f in fps if f["detector"] == "unusual_geo"} == \
        {"198.51.100.14", "198.51.100.88", "192.0.2.44", "AWS Internal"}
    assert {f["ip"] for f in fps if f["detector"] == "brute_force"} == {"13.52.44.19"}
    assert Counter(f["event"] for f in fps if f["detector"] == "suspicious_api") == \
        Counter({"RunInstances": 12, "CreateAccessKey": 4, "AttachRolePolicy": 2})


def test_noisy_external_login_ips_are_documentation_ranges(noisy):
    for r in noisy:
        ip = r.get("sourceIPAddress")
        if r.get("eventName") != "ConsoleLogin" or not ip or ip == "AWS Internal":
            continue
        if _ip_in_common_ranges(ip, COMMON_IP_NETWORKS):
            continue
        assert any(ipaddress.ip_address(ip) in n for n in DOC_RANGES), ip


def test_noisy_generator_is_deterministic(tmp_path):
    subprocess.run([sys.executable, str(HERE / "sample_data" / "generate_noisy.py"), str(tmp_path)],
                   check=True, capture_output=True)
    assert (tmp_path / "sample_cloudtrail_noisy.json").read_bytes() == NOISY.read_bytes()
    assert (tmp_path / "sample_cloudtrail_noisy.truth.json").read_bytes() == \
        (HERE / "sample_data" / "sample_cloudtrail_noisy.truth.json").read_bytes()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("sample", [CLEAN, NOISY], ids=["clean", "noisy"])
def test_browser_port_matches_python(sample):
    js = (REPO / "web" / "js" / "ioc.js").as_posix()
    script = ("const m=require(process.argv[1]);const d=JSON.parse(require('fs').readFileSync(process.argv[2]));"
              "console.log(JSON.stringify(m.iocDetectAll(m.iocParseRecords(d),10,5)"
              ".map(f=>[f.detector,f.ip,f.actor,f.event,f.time,f.risk])))")
    out = subprocess.run(["node", "-e", script, js, str(sample)], check=True, capture_output=True, text=True).stdout
    py = [[f["detector"], f["ip"], f["actor"], f["event"], f["time"], f["risk"]]
          for f in detect_all(parse_cloudtrail(str(sample)))]
    assert sorted(map(tuple, json.loads(out))) == sorted(map(tuple, py))

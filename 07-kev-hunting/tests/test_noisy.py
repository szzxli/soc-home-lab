"""Tests for the NOISY sample variants in samples/noisy/.

The noisy logs are built to produce false positives and one false negative per
log type; these tests pin the exact per-source verdicts documented in
NOISY_DATA.md, check the detectors survive malformed lines, and check the
generator is deterministic. All data is synthetic.
"""
import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
NOISY = HERE / "samples" / "noisy"
TRUTH = json.loads((NOISY / "truth.json").read_text())
DOC_RANGES = [ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
LOGS = ["confluence-access-noisy.log", "appliance-noisy.log", "nextcloud-access-noisy.log"]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_") + "_noisy", HERE / "detect" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(detector, log):
    stats = {}
    res = load(detector).analyze(NOISY / log, stats)
    return {k: r["verdict"] for k, r in res.items()}, stats


def test_confluence_noisy():
    v, stats = run("cve-2026-21589-log-detect.py", "confluence-access-noisy.log")
    assert v == {"203.0.113.9": "INCIDENT", "192.0.2.77": "INCIDENT",   # TP (incl. %3A%3A-encoded)
                 "198.51.100.7": "RECON",                               # TP lead
                 "10.0.5.9": "INCIDENT",                                # FP: soft-404 WAF page, new scanner
                 "10.0.2.31": "RECON"}                                  # FP lead: '::' in page titles
    assert stats["skipped_malformed"] == 4
    assert "10.0.5.8" not in v and "10.0.0.7" not in v                 # allowlisted scanner, probe


def test_appliance_noisy():
    v, stats = run("cve-2026-102764-detect.py", "appliance-noisy.log")
    assert v == {"bt-rs-03": "INCIDENT",                                # TP: full chain
                 "bt-rs-04": "INCIDENT",                                # FP: pkg SUID + reboot seq reset
                 "bt-rs-06": "SUSPICIOUS",                              # FN at incident level (30h apart)
                 "bt-rs-01": "SUSPICIOUS", "bt-rs-02": "SUSPICIOUS", "bt-rs-05": "SUSPICIOUS"}  # FP leads
    assert stats["skipped_malformed"] == 2 and stats["no_seq"] == 1


def test_nextcloud_noisy():
    v, stats = run("cve-2026-110447-detect.py", "nextcloud-access-noisy.log")
    assert v == {"203.0.113.50": "INCIDENT",                            # TP
                 "192.0.2.150": "SUSPICIOUS",                           # FN at incident level (no probe from this IP)
                 "198.51.100.44": "RECON",                              # TP lead
                 "10.0.1.33": "SUSPICIOUS", "10.0.1.40": "SUSPICIOUS",  # FP leads: '$(' title, '../' client
                 "10.0.5.8": "RECON"}                                   # FP lead: internal scanner
    assert stats["skipped_malformed"] == 3


@pytest.mark.parametrize("log", LOGS)
def test_noisy_volume_header_and_ranges(log):
    text = (NOISY / log).read_text()
    lines = text.splitlines()
    assert "SYNTHETIC" in lines[0].upper() and "NOISY" in lines[0].upper()
    assert len([x for x in lines if x and not x.startswith("#")]) >= 2000
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        addr = ipaddress.ip_address(ip)
        assert addr.is_private or any(addr in n for n in DOC_RANGES), ip
    for t in TRUTH[log]["malicious"]:
        assert t in text


def test_noisy_generator_is_deterministic(tmp_path):
    subprocess.run([sys.executable, str(NOISY / "generate_noisy.py"), str(tmp_path)], check=True, capture_output=True)
    for name in LOGS + ["truth.json"]:
        assert (tmp_path / name).read_bytes() == (NOISY / name).read_bytes(), name


@pytest.mark.parametrize("detector,log", [("cve-2026-102764-detect.py", "appliance-noisy.log"),
                                          ("cve-2026-21589-log-detect.py", "confluence-access-noisy.log"),
                                          ("cve-2026-110447-detect.py", "nextcloud-access-noisy.log")])
def test_cli_runs_on_noisy_and_reports_skips(detector, log):
    out = subprocess.run([sys.executable, str(HERE / "detect" / detector), str(NOISY / log)],
                         check=True, capture_output=True, text=True).stdout
    assert "[INCIDENT]" in out and "malformed line(s) skipped" in out

"""pytest suite for the 07 kev-hunting detectors.

Runs each detector against its synthetic sample log and asserts the exact set
of flagged lines and per-source verdicts: every suspicious line is caught and
no benign / allowlisted / ticketed line is flagged. All data is synthetic.
"""
import importlib.util
import ipaddress
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
SAMPLES = HERE / "samples"
DOC_RANGES = [ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / "detect" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def flagged_lines(result):
    return {h[0] for r in result.values() for h in r["hits"]}


def verdicts(result):
    return {k: r["verdict"] for k, r in result.items()}


def test_appliance_detector():
    res = load("cve-2026-102764-detect.py").analyze(SAMPLES / "appliance.log")
    assert verdicts(res) == {"bt-rs-01": "INCIDENT", "bt-rs-02": "SUSPICIOUS"}
    assert flagged_lines(res) == {25, 27, 28, 29, 30, 31, 32, 33, 35, 45}
    kinds = {h[2] for h in res["bt-rs-01"]["hits"]}
    assert kinds == {"WEBSHELL", "SUID_ROOT", "VAULT_ACCESS", "BOOT_PERSIST",
                     "TUNNEL", "PRIV_ESC", "LOG_GAP"}


def test_confluence_detector():
    res = load("cve-2026-21589-log-detect.py").analyze(SAMPLES / "confluence-access.log")
    assert verdicts(res) == {"203.0.113.9": "INCIDENT", "198.51.100.7": "RECON"}
    assert flagged_lines(res) == {16, 17, 18, 21, 22, 23, 24, 25}
    # IPv6 host '::', query-string '::' and the allowlisted scanner never fire
    assert "[2001:db8::1]" not in res and "10.0.0.5" not in res and "10.0.5.8" not in res


def test_nextcloud_detector():
    res = load("cve-2026-110447-detect.py").analyze(SAMPLES / "nextcloud-access.log")
    assert verdicts(res) == {"203.0.113.50": "INCIDENT", "198.51.100.44": "RECON"}
    assert flagged_lines(res) == {18, 19, 20, 23, 24, 25, 26, 27}
    assert "10.0.0.9" not in res  # health check polling proxy.php?status


@pytest.mark.parametrize("name", ["appliance.log", "confluence-access.log", "nextcloud-access.log"])
def test_sample_is_labeled_synthetic_and_uses_doc_ranges(name):
    text = (SAMPLES / name).read_text()
    assert "SYNTHETIC" in text.splitlines()[0].upper()
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        addr = ipaddress.ip_address(ip)
        assert addr.is_private or any(addr in n for n in DOC_RANGES), ip

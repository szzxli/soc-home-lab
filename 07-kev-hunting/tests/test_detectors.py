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




def test_wordpress_upgrade_detector():
    res = load("cve-2026-119977-detect.py").analyze(SAMPLES / "wordpress-upgrade-access.log")
    assert verdicts(res) == {"203.0.113.88": "INCIDENT", "198.51.100.77": "RECON"}
    assert flagged_lines(res) == {17, 18, 19, 26, 27, 28, 29}
    assert "192.0.2.11" not in res  # admin upgrade traffic is correlation-only


def test_openssh_password_bypass_detector():
    res = load("cve-2026-123158-detect.py").analyze(SAMPLES / "openssh-auth.log")
    assert verdicts(res) == {"203.0.113.50": "INCIDENT", "198.51.100.40": "SUSPICIOUS"}
    assert flagged_lines(res) == {20, 21, 22}
    kinds = {h[2] for h in res["203.0.113.50"]["hits"]}
    assert kinds == {"ACCEPTED_STAR"}
    assert res["198.51.100.40"]["hits"][0][2] == "ACCEPTED_UNKNOWN"
    # publickey, hashed-account password, locked-account password, failures
    for ip in ("192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.22"):
        assert ip not in res


def test_php2shell_detector():
    res = load("php2shell-detect.py").analyze(SAMPLES / "php2shell-sysmon.log")
    assert verdicts(res) == {"web-01": "INCIDENT", "web-02": "SUSPICIOUS",
                            "web-03": "SUSPICIOUS", "web-05": "SUSPICIOUS"}
    assert flagged_lines(res) == {18, 19, 20, 21, 22, 23, 24}
    kinds = {h[2] for h in res["web-01"]["hits"]}
    assert kinds == {"SHELL_SPAWN", "TOOL_DOWNLOAD", "NET_OUT", "WEBSHELL_DROP"}
    assert "web-04" not in res  # FPM pool spawns, cron php, admin/monitoring curl,
    # direct worker outbound, template-cache .php write


def test_openssh_detector_accepts_sshd_session_and_iso_timestamp(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "# SYNTHETIC\n"
        "# INVENTORY password_field=* : alpine\n"
        "2026-11-09T16:02:11.000000+00:00 ssh.example.com sshd-session[9]: "
        "Accepted password for alpine from 203.0.113.9 port 22 ssh2\n"
        "Nov  9 16:03:00 sshd[10]: Accepted publickey for alpine from 192.0.2.9 "
        "port 22 ssh2: ED25519 SHA256:synthetic\n"
    )
    res = load("cve-2026-123158-detect.py").analyze(log)
    assert verdicts(res) == {"203.0.113.9": "INCIDENT"}
    assert flagged_lines(res) == {3}


@pytest.mark.parametrize("name", ["appliance.log", "confluence-access.log", "nextcloud-access.log", "wordpress-upgrade-access.log", "openssh-auth.log", "php2shell-sysmon.log"])
def test_sample_is_labeled_synthetic_and_uses_doc_ranges(name):
    text = (SAMPLES / name).read_text()
    assert "SYNTHETIC" in text.splitlines()[0].upper()
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        addr = ipaddress.ip_address(ip)
        assert addr.is_private or any(addr in n for n in DOC_RANGES), ip

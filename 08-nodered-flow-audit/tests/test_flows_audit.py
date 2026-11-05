"""pytest for the Node-RED flow-audit lab. Synthetic fixtures only."""
import importlib.util
import ipaddress
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
DETECT = ROOT / "detect"
DOC_RANGES = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
# Public addresses named in third-party exploit write-ups. They must never
# land in this pack as IOCs or sample data.
BANNED = ("85.215.73.250", "45.194.90.57", "bot-linux", "base64 -d")


def load():
    spec = importlib.util.spec_from_file_location("flows_audit", DETECT / "flows-audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def audit():
    return load()


def test_clean_baseline_and_gets_are_quiet(audit):
    res = audit.analyze(SAMPLES / "flows-baseline.json", SAMPLES / "nodered-access-clean.log",
                        SAMPLES / "flows-baseline.json")
    assert res["exec_nodes"] == []
    assert res["http_in_to_exec"] == []
    assert res["unexpected"] == []
    assert res["removed"] == []
    assert res["tmp_writes"] == []
    assert res["access"] == {}


def test_exec_flow_is_incident(audit):
    stats = {}
    res = audit.analyze(
        SAMPLES / "flows-lab-exec.json",
        SAMPLES / "nodered-access.log",
        SAMPLES / "flows-baseline.json",
        stats,
    )
    assert [n["id"] for n in res["exec_nodes"]] == ["lab-exec"]
    assert res["http_in_to_exec"] == []
    assert [(n["id"], n["reason"]) for n in res["unexpected"]] == [
        ("lab-tab", "new"), ("lab-inject", "new"), ("lab-exec", "new"),
    ]
    assert res["removed"] == []
    assert res["tmp_writes"][0]["paths"] == ["/dev/shm", "/tmp"]
    assert {ip: row["verdict"] for ip, row in res["access"].items()} == {
        "203.0.113.50": "INCIDENT",
        "198.51.100.40": "RECON",
    }
    assert res["access"]["203.0.113.50"]["hits"][0][0] == 6
    assert res["access"]["198.51.100.40"]["hits"][0][0] == 8
    assert "192.0.2.10" not in res["access"]
    assert "192.0.2.15" not in res["access"]
    assert stats["skipped_malformed"] == 1


def test_http_in_reaches_exec_through_function(audit):
    res = audit.analyze(SAMPLES / "flows-http-in-exec.json")
    assert len(res["http_in_to_exec"]) == 1
    hit = res["http_in_to_exec"][0]
    assert hit["id"] == "http-in-1"
    assert hit["url"] == "/lab-marker"
    assert hit["exec_ids"] == ["exec-http"]
    assert res["tmp_writes"][0]["paths"] == ["/tmp"]
    assert res["unexpected"] == []  # no baseline, so no diff


def test_http_in_wired_only_to_debug_is_not_flagged(audit, tmp_path):
    flow = {
        "flows": [
            {"id": "h", "type": "http in", "url": "/health", "method": "get", "wires": [["d"]]},
            {"id": "d", "type": "debug", "name": "health", "wires": []},
            {"id": "e", "type": "exec", "name": "unwired", "command": "echo ok", "wires": [[], [], []]},
        ]
    }
    path = tmp_path / "flows.json"
    path.write_text(json.dumps(flow))
    res = audit.analyze(path)
    assert res["http_in_to_exec"] == []
    assert [n["id"] for n in res["exec_nodes"]] == ["e"]
    assert res["tmp_writes"] == []


def test_changed_command_and_removed_node(audit, tmp_path):
    before = {"flows": [
        {"id": "e", "type": "exec", "command": "echo ok", "wires": [[], [], []]},
        {"id": "d", "type": "debug", "name": "gone", "wires": []},
    ]}
    after = {"flows": [
        {"id": "e", "type": "exec", "command": "echo ok > /tmp/x", "wires": [[], [], []]},
    ]}
    b, a = tmp_path / "b.json", tmp_path / "a.json"
    b.write_text(json.dumps(before))
    a.write_text(json.dumps(after))
    res = audit.analyze(a, baseline_path=b)
    assert [(n["id"], n["reason"]) for n in res["unexpected"]] == [("e", "changed")]
    assert [n["id"] for n in res["removed"]] == ["d"]
    assert res["tmp_writes"][0]["paths"] == ["/tmp"]


def test_post_200_without_exec_is_suspicious(audit):
    res = audit.analyze(
        SAMPLES / "flows-baseline.json",
        SAMPLES / "nodered-access-suspicious.log",
        SAMPLES / "flows-baseline.json",
    )
    assert res["access"]["203.0.113.51"]["verdict"] == "SUSPICIOUS"
    assert res["exec_nodes"] == []


def test_post_401_is_recon(audit):
    res = audit.analyze(SAMPLES / "flows-baseline.json", SAMPLES / "nodered-access-recon.log")
    assert res["access"]["198.51.100.77"]["verdict"] == "RECON"


@pytest.mark.parametrize("command,paths", [
    ("echo x > /tmp/a", ["/tmp"]),
    ("echo x > /dev/shm/a", ["/dev/shm"]),
    ("echo x > /tmpfile", []),
    ("echo /temporary", []),
    ("id > /dev/shm/a; echo lab-ok > /tmp/b", ["/dev/shm", "/tmp"]),
])
def test_tmp_path_boundaries(audit, tmp_path, command, paths):
    flow = {"flows": [{"id": "e", "type": "exec", "command": command, "wires": []}]}
    path = tmp_path / "f.json"
    path.write_text(json.dumps(flow))
    got = audit.analyze(path)["tmp_writes"]
    assert [t["paths"] for t in got] == ([paths] if paths else [])


def test_cli_prints_signals(audit, capsys):
    rc = audit.main([
        "--flows", str(SAMPLES / "flows-lab-exec.json"),
        "--baseline", str(SAMPLES / "flows-baseline.json"),
        "--access", str(SAMPLES / "nodered-access.log"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    for token in ("EXEC_NODE", "UNEXPECTED", "TMP_WRITE", "POST_FLOWS", "[INCIDENT] 203.0.113.50"):
        assert token in out
    assert "malformed line" in out


def _ips(text):
    return set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))


def _assert_rfc5737(ip):
    addr = ipaddress.ip_address(ip)
    assert any(addr in n for n in DOC_RANGES), ip


def test_samples_are_labeled_and_use_doc_ranges():
    """Sample addresses must be RFC 5737. Private and loopback ranges do not qualify."""
    saw = False
    for path in sorted(SAMPLES.iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".log":
            assert "SYNTHETIC" in text.splitlines()[0].upper()
        elif path.suffix == ".json":
            data = json.loads(text)
            assert "SYNTHETIC" in data.get("_comment", "").upper()
        for ip in _ips(text):
            saw = True
            _assert_rfc5737(ip)
    assert saw, "samples contained no IP addresses to check"
    # The old self-check treated 10.0.0.0/8 as acceptable. It is not.
    assert not any(ipaddress.ip_address("10.0.0.5") in n for n in DOC_RANGES)


def test_pack_has_no_banned_indicators_or_public_ips():
    skip = {"tests", "__pycache__", "runtime"}
    files = [p for p in ROOT.rglob("*")
             if p.is_file() and not (set(p.parts) & skip)]
    text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in files)
    for banned in BANNED:
        assert banned not in text, banned
    for path in files:
        in_samples = "samples" in path.parts
        for ip in _ips(path.read_text(encoding="utf-8", errors="replace")):
            addr = ipaddress.ip_address(ip)
            if in_samples:
                _assert_rfc5737(ip)
            else:
                # Lab config may name loopback. It may not use other private ranges.
                assert addr.is_loopback or any(addr in n for n in DOC_RANGES), f"{path}: {ip}"


def test_proxy_listen_is_loopback_only():
    conf = (ROOT / "lab" / "nginx.conf").read_text(encoding="utf-8")
    listens = re.findall(r"(?m)^\s*listen\s+([^;]+);", conf)
    assert listens == ["127.0.0.1:1880"]
    assert "listen 1880;" not in conf
    assert not re.search(r"listen\s+(?:0\.0\.0\.0|\[::\])", conf)
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:1881:1880"' in compose
    assert not re.search(r'["\']0\.0\.0\.0:', compose)


def test_benign_flow_is_marker_only():
    body = json.loads((ROOT / "lab" / "benign-flow.json").read_text(encoding="utf-8"))
    execs = [n for n in body["flows"] if n["type"] == "exec"]
    assert len(execs) == 1
    assert execs[0]["addpay"] is False
    assert execs[0]["command"] == (
        "id > /dev/shm/nodered-lab-whoami.txt; echo lab-ok > /tmp/nodered-lab-marker.txt"
    )
    types = {n["type"] for n in body["flows"]}
    assert "http in" not in types


def test_sigma_and_suricata_are_detection_rules():
    sigma = (DETECT / "nodered-post-flows.yml").read_text(encoding="utf-8")
    assert "title:" in sigma and "POST" in sigma and "/flows" in sigma
    assert "detection:" in sigma and "cs-method" in sigma
    proc = (DETECT / "nodered-exec-tmp-write.yml").read_text(encoding="utf-8")
    assert "/dev/shm/" in proc and "/tmp/" in proc and "ParentImage" in proc
    rules = (DETECT / "nodered-post-flows.rules").read_text(encoding="utf-8")
    assert rules.count("alert http") == 2
    assert "sid:1000001;" in rules and "sid:1000002;" in rules
    assert 'content:"POST"' in rules
    assert "/flows" in rules
    assert "http.request_body" in rules


def test_deploy_script_refuses_non_loopback():
    script = (ROOT / "lab" / "deploy-benign.sh").read_text(encoding="utf-8")
    assert "127.0.0.1|localhost|::1" in script
    assert "refusing:" in script

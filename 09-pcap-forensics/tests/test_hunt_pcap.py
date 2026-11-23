"""pytest suite for the 09 pcap-forensics lab.

Generates both synthetic pcaps into a temp dir (the generator is
deterministic, so the files are byte-identical every run) and asserts the
exact finding set: every planted behaviour is caught and no benign packet
is flagged. All data is synthetic; no real traffic is used anywhere.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import generate_pcap
import hunt_pcap

HERE = Path(__file__).resolve().parent.parent


def _build(tmp_path):
    generate_pcap._write_pcap(tmp_path / "malicious.pcap",
                              generate_pcap.build_malicious())
    generate_pcap._write_pcap(tmp_path / "benign.pcap",
                              generate_pcap.build_benign())
    return tmp_path / "malicious.pcap", tmp_path / "benign.pcap"


def test_generator_is_deterministic(tmp_path):
    p1, _ = _build(tmp_path)
    again = tmp_path / "again.pcap"
    generate_pcap._write_pcap(again, generate_pcap.build_malicious())
    assert p1.read_bytes() == again.read_bytes()


def test_malicious_pcap_all_detectors_fire(tmp_path):
    bad, _ = _build(tmp_path)
    findings = hunt_pcap.analyze(str(bad))
    kinds = sorted({f["detector"] for f in findings})
    assert kinds == ["BEACON", "DNS_EXFIL", "SUSPICIOUS_HTTP", "SYN_SCAN"]
    assert len(findings) == 6  # 1 scan + 3 DNS + 1 HTTP + 1 beacon
    by_kind = {}
    for f in findings:
        by_kind.setdefault(f["detector"], []).append(f)
    assert by_kind["SYN_SCAN"][0]["src"] == "203.0.113.60"
    assert "12 distinct ports" in by_kind["SYN_SCAN"][0]["detail"]
    assert len(by_kind["DNS_EXFIL"]) == 3
    assert all(f["src"] == "192.0.2.50" for f in by_kind["DNS_EXFIL"])
    assert "curl/8.0.1" in by_kind["SUSPICIOUS_HTTP"][0]["detail"]
    assert "/admin/config.zip" in by_kind["SUSPICIOUS_HTTP"][0]["detail"]
    assert "every ~30s" in by_kind["BEACON"][0]["detail"]
    assert by_kind["BEACON"][0]["src"] == "192.0.2.50"


def test_benign_pcap_no_findings(tmp_path):
    _, good = _build(tmp_path)
    assert hunt_pcap.analyze(str(good)) == []


def test_shipped_samples_match_generator(tmp_path):
    # The committed pcaps are exactly what the generator produces.
    bad, good = _build(tmp_path)
    assert bad.read_bytes() == (HERE / "samples" / "malicious.pcap").read_bytes()
    assert good.read_bytes() == (HERE / "samples" / "benign.pcap").read_bytes()


def test_truncated_pcap_does_not_crash(tmp_path):
    bad, _ = _build(tmp_path)
    raw = bad.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(raw[: len(raw) // 2])  # mid-packet truncation
    findings = hunt_pcap.analyze(str(cut))  # must not raise
    assert isinstance(findings, list)


def test_not_a_pcap_raises(tmp_path):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a pcap file at all, just text........")
    try:
        hunt_pcap.analyze(str(junk))
    except ValueError as exc:
        assert "not a pcap" in str(exc)
    else:
        raise AssertionError("expected ValueError for a non-pcap file")

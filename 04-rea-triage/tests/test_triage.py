"""pytest suite for rea-triage.

All fixtures are synthetic: heuristic functions are tested against
hand-built TriageResult objects, never against real malware.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from triage import (  # noqa: E402
    Finding,
    TriageResult,
    detect_packed_sections,
    detect_string_iocs,
    detect_suspicious_imports,
    detect_wx_sections,
    extract_strings,
    run_heuristics,
    shannon_entropy,
)


def _blank_result(**kwargs):
    base = dict(
        path="/tmp/fake",
        sha256="0" * 64,
        size=1000,
        arch="EM_X86_64",
        elf_type="ET_DYN",
        stripped=False,
        statically_linked=False,
    )
    base.update(kwargs)
    return TriageResult(**base)


def test_entropy_zeros_is_zero():
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_entropy_random_is_high():
    # deterministic pseudo-random bytes: entropy should approach 8.0
    data = bytes((i * 1103515245 + 12345) % 256 for i in range(4096))
    assert shannon_entropy(data) > 7.0


def test_packed_section_flagged():
    data = bytes((i * 1103515245 + 12345) % 256 for i in range(8192))
    import math

    ent = round(
        -sum(
            (data.count(b) / len(data)) * math.log2(data.count(b) / len(data))
            for b in set(data)
        ),
        3,
    )
    r = _blank_result(
        sections=[{"name": ".payload", "size": 8192, "flags": 0x6,
                   "entropy": ent, "type": "SHT_PROGBITS"}]
    )
    findings = detect_packed_sections(r)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert ".payload" in findings[0].indicator


def test_small_high_entropy_section_ignored():
    r = _blank_result(
        sections=[{"name": ".note", "size": 64, "flags": 0x2,
                   "entropy": 7.9, "type": "SHT_PROGBITS"}]
    )
    assert detect_packed_sections(r) == []


def test_wx_section_is_high():
    r = _blank_result(
        sections=[{"name": ".evil", "size": 4096, "flags": 0x1 | 0x4,
                   "entropy": 5.0, "type": "SHT_PROGBITS"}]
    )
    findings = detect_wx_sections(r)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_suspicious_import_ptrace():
    r = _blank_result(imports=["printf", "ptrace", "malloc"])
    findings = detect_suspicious_imports(r)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "ptrace" in findings[0].indicator


def test_benign_imports_no_findings():
    r = _blank_result(imports=["printf", "malloc", "exit"])
    assert detect_suspicious_imports(r) == []


def test_string_ioc_finds_ip_and_suspicious_url():
    r = _blank_result(
        strings=[
            "hello",
            "connecting to 10.9.8.7",
            "see https://gnu.org/licenses/gpl.html",  # benign: not flagged
            "hook https://discord.com/api/webhooks/abc123",
        ]
    )
    findings = detect_string_iocs(r)
    indicators = " ".join(f.indicator for f in findings)
    assert "ipv4" in indicators
    assert "suspicious_url" in indicators
    # the benign gnu.org URL must not appear as a *flagged sample*
    assert "https://gnu.org" not in " ".join(f.evidence for f in findings)


def test_verdict_bands():
    r = _blank_result()  # no findings at all
    run_heuristics(r)
    assert r.verdict == "benign" and r.score == 0

    r.findings = [Finding("high", "x", "y"), Finding("high", "x", "y")]
    run_heuristics(r)
    assert r.verdict == "malicious" and r.score == 6


def test_extract_strings_min_length():
    out = extract_strings(b"ab\x00cdef\x00gh")
    assert out == [b"cdef"]

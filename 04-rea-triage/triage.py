#!/usr/bin/env python3
"""rea-triage: one-command ELF binary triage.

Inspired by this week's #1 GitHub trending project ``morluto/rea``
("reverse engineer anything with agents"). REA exposes 50+ granular
agent-facing subcommands and emits machine-oriented Evidence JSON.
rea-triage is the human-friendly layer on top of that *idea*:

    python triage.py /path/to/binary --output report.md

one command in, one analyst-readable page out: file identity, heuristic
findings with severity + rationale, a score-based verdict, and next steps.

What it checks (all static, the binary is never executed):
  1. file identity  - sha256, size, arch, ELF type, stripped?
  2. section entropy - high-entropy sections suggest packing/encryption
  3. W^X sections   - a section that is both writable and executable
  4. suspicious imports - ptrace, memfd_create, process_vm_writev, ...
  5. string IOCs    - IPs, URLs, suspicious paths/keywords in strings

Optional REA enrichment: if the ``rea`` CLI is installed *and* its ELF
provider is configured, ``inspect-binary-layout`` evidence is folded into
the report. When REA is absent or its provider is unavailable, triage
continues and the report says so explicitly -- it never fails.

Honesty note: these are *triage signals*, not convictions. A "malicious"
verdict means "prioritize this for deep analysis (Ghidra / REA / sandbox)",
never "this is malware". Heuristics have false positives by design.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import Section
except ImportError:  # pragma: no cover
    ELFFile = None  # type: ignore

# ---------------------------------------------------------------------------
# Heuristic tables
# ---------------------------------------------------------------------------

# Suspicious imports: name -> (severity, rationale). Matched against undefined
# dynamic symbols (i.e. functions the binary expects from shared libraries).
SUSPICIOUS_IMPORTS: Dict[str, Tuple[str, str]] = {
    "ptrace": (
        "high",
        "Anti-debugging primitive — classic malware evasion technique.",
    ),
    "memfd_create": (
        "high",
        "Anonymous in-memory file — enables fileless payload execution.",
    ),
    "process_vm_writev": (
        "high",
        "Cross-process memory write — process injection primitive.",
    ),
    "process_vm_readv": (
        "medium",
        "Cross-process memory read — credential/memory scraping primitive.",
    ),
    "__libc_dlopen_mode": (
        "low",
        "Runtime dynamic loading — legitimate use exists, notable for evasion.",
    ),
    "dlopen": (
        "low",
        "Runtime dynamic loading — legitimate use exists, notable for evasion.",
    ),
    "dlsym": (
        "low",
        "Runtime symbol resolution — often paired with dlopen for evasion.",
    ),
    "mprotect": (
        "low",
        "Memory permission change — notable when paired with W^X sections.",
    ),
    "execve": (
        "medium",
        "Process execution — check what is being launched and why.",
    ),
    "execvp": (
        "medium",
        "Process execution — check what is being launched and why.",
    ),
    "system": (
        "medium",
        "Shell command execution — high injection/abuse potential.",
    ),
    "popen": (
        "medium",
        "Shell command execution — high injection/abuse potential.",
    ),
    "socket": (
        "low",
        "Network socket — notable in combination with connect/send.",
    ),
    "connect": (
        "low",
        "Outbound connection — notable in combination with socket.",
    ),
    "unshare": (
        "medium",
        "Namespace manipulation — container escape / sandbox evasion indicator.",
    ),
}

# String IOC patterns: label -> (compiled regex, severity, rationale).
IOC_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    (
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "medium",
        "Hardcoded IPv4 address — possible C2 or exfiltration endpoint.",
    ),
    (
        "suspicious_url",
        re.compile(
            r"https?://(?:\d{1,3}(?:\.\d{1,3}){3}|[^\s\"']*?"
            r"(?:pastebin\.com|paste\.rs|hastebin|discord\.com/api/webhooks|"
            r"t\.me|telegram\.org|ngrok\.io|bit\.ly|tinyurl\.com|"
            r"transfer\.sh|file\.io|0x0\.st|temp\.sh)[^\s\"']*)",
            re.IGNORECASE,
        ),
        "medium",
        "URL with IP-literal host or abuse-prone service — possible C2, "
        "download, or exfiltration endpoint. Plain project URLs "
        "(e.g. gnu.org) are intentionally not flagged.",
    ),
    (
        "suspicious_path",
        re.compile(
            r"/(?:etc/(?:shadow|passwd|gshadow)|proc/(?:self/mem|kcore)|"
            r"root/\.ssh|home/[^/]+/\.ssh|dev/(?:mem|kmem)|sys/kernel)"
        ),
        "high",
        "Reference to sensitive system path — credential theft / privesc indicator.",
    ),
    (
        "suspicious_keyword",
        re.compile(
            r"(?i)(ransom|decrypt.{0,8}key|bitcoin|monero|keylog|mimikatz|"
            r"reverse.?shell|bind.?shell|persistence|inject.{0,8}dll)"
        ),
        "medium",
        "Suspicious keyword in strings — warrants analyst review in context.",
    ),
]

ENTROPY_THRESHOLD = 7.5      # bits/byte; packed/encrypted sections sit near 8.0
ENTROPY_MIN_SIZE = 4096      # ignore tiny sections (headers, notes)
MIN_STRING_LEN = 4

SEVERITY_SCORE = {"high": 3, "medium": 2, "low": 1}
VERDICT_BANDS = [  # (max_score_inclusive, verdict)
    (1, "benign"),
    (4, "suspicious"),
    (float("inf"), "malicious"),
]

SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4


@dataclass
class Finding:
    severity: str
    indicator: str
    evidence: str
    source: str = "triage-engine"  # or "rea-enrichment"


@dataclass
class TriageResult:
    path: str
    sha256: str
    size: int
    arch: str
    elf_type: str
    stripped: bool
    statically_linked: bool
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    needed_libs: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    rea: Dict[str, Any] = field(default_factory=dict)
    score: int = 0
    verdict: str = "benign"


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts if c
    )


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> List[str]:
    return re.findall(rb"[ -~]{%d,}" % min_len, data)


def analyze_elf(path: str) -> TriageResult:
    if ELFFile is None:
        raise RuntimeError("pyelftools is not installed (pip install pyelftools)")
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"\x7fELF":
            raise ValueError(f"not an ELF binary: {path}")
        f.seek(0)
        elffile = ELFFile(f)
        header = elffile.header

        machine = header["e_machine"]
        elf_type = header["e_type"]
        arch = f"{machine} ({elffile.get_machine_arch()})"

        sections: List[Dict[str, Any]] = []
        for sec in elffile.iter_sections():
            assert isinstance(sec, Section)
            data = sec.data() or b""
            sections.append(
                {
                    "name": sec.name,
                    "size": sec["sh_size"],
                    "flags": sec["sh_flags"],
                    "entropy": round(shannon_entropy(data), 3),
                    "type": sec["sh_type"],
                }
            )

        section_names = {s["name"] for s in sections}
        stripped = ".symtab" not in section_names

        statically_linked = True
        needed_libs: List[str] = []
        for seg in elffile.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                statically_linked = False
        dynsec = elffile.get_section_by_name(".dynamic")
        if dynsec is not None:
            for tag in dynsec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed_libs.append(tag.needed)

        imports: List[str] = []
        dynsym = elffile.get_section_by_name(".dynsym")
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                    # skip versioned duplicates like "printf@GLIBC_2.2.5"
                    imports.append(sym.name.split("@")[0])
        imports = sorted(set(imports))

        # strings across the whole file image
        f.seek(0)
        strings = [
            s.decode("ascii", errors="ignore")
            for s in extract_strings(f.read())
        ]

    st = os.stat(path)
    return TriageResult(
        path=path,
        sha256=sha256_of(path),
        size=st.st_size,
        arch=arch,
        elf_type=elf_type,
        stripped=stripped,
        statically_linked=statically_linked,
        sections=sections,
        imports=imports,
        needed_libs=needed_libs,
        strings=strings,
    )


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def detect_packed_sections(result: TriageResult) -> List[Finding]:
    findings = []
    for s in result.sections:
        if (
            s["type"] == "SHT_PROGBITS"
            and s["size"] >= ENTROPY_MIN_SIZE
            and s["entropy"] >= ENTROPY_THRESHOLD
        ):
            findings.append(
                Finding(
                    severity="medium",
                    indicator=f"high-entropy section {s['name'] or '<unnamed>'}",
                    evidence=(
                        f"entropy {s['entropy']} bits/byte over {s['size']} bytes "
                        f"(threshold {ENTROPY_THRESHOLD}) — suggests packing, "
                        "encryption, or compressed payload."
                    ),
                )
            )
    return findings


def detect_wx_sections(result: TriageResult) -> List[Finding]:
    findings = []
    for s in result.sections:
        flags = s["flags"]
        if flags & SHF_WRITE and flags & SHF_EXECINSTR:
            findings.append(
                Finding(
                    severity="high",
                    indicator=f"W^X violation in section {s['name'] or '<unnamed>'}",
                    evidence=(
                        "Section is both writable and executable — classic "
                        "shellcode staging / process injection indicator."
                    ),
                )
            )
    return findings


def detect_suspicious_imports(result: TriageResult) -> List[Finding]:
    findings = []
    for name in result.imports:
        hit = SUSPICIOUS_IMPORTS.get(name)
        if hit:
            severity, rationale = hit
            findings.append(
                Finding(
                    severity=severity,
                    indicator=f"suspicious import: {name}",
                    evidence=rationale,
                )
            )
    return findings


def detect_string_iocs(result: TriageResult) -> List[Finding]:
    findings = []
    for label, pattern, severity, rationale in IOC_PATTERNS:
        hits = set()
        for s in result.strings:
            for m in pattern.findall(s):
                hits.add(m if isinstance(m, str) else m[0])
                if len(hits) >= 5:
                    break
            if len(hits) >= 5:
                break
        if hits:
            sample = ", ".join(sorted(hits)[:5])
            findings.append(
                Finding(
                    severity=severity,
                    indicator=f"string IOC ({label}): {len(hits)} hit(s)",
                    evidence=f"{rationale} e.g. {sample}",
                )
            )
    return findings


def detect_context_signals(result: TriageResult) -> List[Finding]:
    findings = []
    if result.stripped:
        findings.append(
            Finding(
                severity="low",
                indicator="stripped binary",
                evidence="No .symtab section — harder to analyze; common in "
                "both production software and malware. Context only.",
            )
        )
    if result.statically_linked:
        findings.append(
            Finding(
                severity="low",
                indicator="statically linked",
                evidence="No PT_INTERP — self-contained binary. Malware favors "
                "static linking to avoid dependency analysis. Context only.",
            )
        )
    return findings


def run_heuristics(result: TriageResult) -> None:
    result.findings.extend(detect_packed_sections(result))
    result.findings.extend(detect_wx_sections(result))
    result.findings.extend(detect_suspicious_imports(result))
    result.findings.extend(detect_string_iocs(result))
    result.findings.extend(detect_context_signals(result))
    result.score = sum(SEVERITY_SCORE[f.severity] for f in result.findings)
    for band_max, verdict in VERDICT_BANDS:
        if result.score <= band_max:
            result.verdict = verdict
            break


# ---------------------------------------------------------------------------
# Optional REA enrichment
# ---------------------------------------------------------------------------

def rea_enrichment(path: str) -> Dict[str, Any]:
    """Fold REA's inspect-binary-layout evidence in when available.

    Never raises: absence of the rea CLI or an unavailable provider is
    recorded honestly and triage continues without it.
    """
    rea_bin = shutil.which("rea")
    if rea_bin is None:
        return {"available": False, "reason": "rea CLI not found on PATH"}
    try:
        proc = subprocess.run(
            [rea_bin, "inspect-binary-layout", path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"available": False, "reason": f"rea execution failed: {e}"}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"available": False, "reason": "rea returned non-JSON output"}
    if payload.get("code") == "provider_unavailable":
        return {
            "available": False,
            "reason": payload.get("message", "REA provider unavailable"),
        }
    normalized = payload.get("normalized_result", {}) or {}
    sections = normalized.get("sections", []) or []
    return {
        "available": True,
        "evidence_id": payload.get("evidence_id"),
        "provider": (payload.get("provider") or {}).get("id"),
        "entry_point": (normalized.get("entry_point") or {}).get("reported_value"),
        "section_count": len(sections),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

VERDICT_BLURB = {
    "benign": "No significant triage signals. Routine handling.",
    "suspicious": "Notable signals present — prioritize for analyst review.",
    "malicious": "Multiple strong signals — escalate to deep analysis "
    "(Ghidra / REA / sandbox) before any execution.",
}


def generate_markdown_report(result: TriageResult) -> str:
    lines = [
        "# Binary Triage Report",
        "",
        f"**File:** `{result.path}`",
        f"**SHA256:** `{result.sha256}`",
        f"**Size:** {result.size:,} bytes",
        f"**Arch:** {result.arch} | **Type:** {result.elf_type}",
        f"**Stripped:** {result.stripped} | **Static:** {result.statically_linked}",
        "",
        f"## Verdict: {result.verdict.upper()} (score {result.score})",
        "",
        VERDICT_BLURB[result.verdict],
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("_No heuristic findings._")
    else:
        lines.append("| Severity | Indicator | Evidence | Source |")
        lines.append("|---|---|---|---|")
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(result.findings, key=lambda x: order[x.severity]):
            ev = f.evidence.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {f.severity} | {f.indicator} | {ev} | {f.source} |")
    lines += [
        "",
        "## Imports of note",
        "",
        ", ".join(f"`{i}`" for i in result.imports[:40])
        or "_none (statically linked or stripped imports)_",
        "",
        "## REA enrichment",
        "",
    ]
    if result.rea.get("available"):
        lines.append(
            f"REA provider `{result.rea.get('provider')}` contributed layout "
            f"evidence (evidence_id `{result.rea.get('evidence_id')}`, "
            f"{result.rea.get('section_count')} sections, entry point "
            f"{result.rea.get('entry_point')})."
        )
    else:
        lines.append(
            f"Not available — {result.rea.get('reason', 'unknown reason')}. "
            "Triage proceeded on the built-in engine only."
        )
    lines += [
        "",
        "## Recommendations",
        "",
    ]
    if result.verdict == "benign":
        lines.append("- No further action required from triage.")
    else:
        lines.append(
            "- Do NOT execute outside a sandbox. Next steps: import into "
            "Ghidra for control-flow review, run REA's deeper providers "
            "(`decompile`, `inspect-native-function`), and detonate in a "
            "sandbox with network capture."
        )
    lines += [
        "",
        "---",
        "_Generated by rea-triage (heuristic triage signals, not convictions). "
        "Inspired by morluto/rea._",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="One-command ELF binary triage: heuristics + verdict + report."
    )
    p.add_argument("binary", help="Path to the ELF binary to triage")
    p.add_argument("--output", required=True, help="Path for the markdown report")
    p.add_argument(
        "--rea",
        action="store_true",
        help="Attempt REA inspect-binary-layout enrichment (optional)",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        default=None,
        help="Optional path to write raw triage JSON",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not os.path.isfile(args.binary):
        print(f"error: not a file: {args.binary}", file=sys.stderr)
        return 2
    try:
        result = analyze_elf(args.binary)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    run_heuristics(result)

    if args.rea:
        result.rea = rea_enrichment(args.binary)
        if result.rea.get("available"):
            result.findings.append(
                Finding(
                    severity="low",
                    indicator="REA layout evidence collected",
                    evidence=(
                        f"Provider {result.rea.get('provider')} confirmed "
                        f"{result.rea.get('section_count')} sections and entry "
                        f"point {result.rea.get('entry_point')}."
                    ),
                    source="rea-enrichment",
                )
            )
            result.score = sum(
                SEVERITY_SCORE[f.severity] for f in result.findings
            )
    else:
        result.rea = {"available": False, "reason": "--rea not requested"}

    report = generate_markdown_report(result)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "path": result.path,
                    "sha256": result.sha256,
                    "verdict": result.verdict,
                    "score": result.score,
                    "findings": [vars(x) for x in result.findings],
                    "rea": result.rea,
                },
                f,
                indent=2,
            )

    print(f"Triaged {args.binary}: verdict={result.verdict} "
          f"(score {result.score}, {len(result.findings)} finding(s)).")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

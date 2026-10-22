#!/usr/bin/env python3
"""Score the reference detectors against the NOISY synthetic samples.

Runs each detector on its noisy sample, compares the output with the answer
key (truth.json files written by the generators) and prints a Markdown
scorecard. NOISY_DATA.md embeds this exact output between the
'noisy-scorecard' markers, and a test fails if the two drift apart, so the
documented TP/FP numbers are always the numbers the code really produces.

Usage: python3 tools/noisy_scorecard.py            # print the scorecard
       python3 tools/noisy_scorecard.py --write    # refresh NOISY_DATA.md
Stdlib only (the 02 analyzer itself imports `requests`, which its
requirements.txt already lists).
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
K07 = ROOT / "07-kev-hunting"
NOISY = K07 / "samples" / "noisy"
CT = ROOT / "02-python-ioc-analyzer"
DOC = ROOT / "NOISY_DATA.md"
BEGIN, END = "<!-- noisy-scorecard:begin -->", "<!-- noisy-scorecard:end -->"

CASES_07 = [
    ("CVE-2026-21589 Atlassian `::` traversal", "cve-2026-21589-log-detect.py", "confluence-access-noisy.log"),
    ("CVE-2026-102764 BeyondTrust RS appliance", "cve-2026-102764-detect.py", "appliance-noisy.log"),
    ("CVE-2026-110447 Nextcloud CODE server", "cve-2026-110447-detect.py", "nextcloud-access-noisy.log"),
]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


def _lines(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.startswith("#"))


def score_07(detector: str, sample: str) -> dict:
    mod = _load(K07 / "detect" / detector, detector.replace("-", "_").replace(".py", ""))
    truth = json.loads((NOISY / "truth.json").read_text(encoding="utf-8"))[sample]
    stats: dict = {}
    res = mod.analyze(NOISY / sample, stats)
    mal, exp = set(truth["malicious"]), set(truth["expected_incident"])
    inc = {k for k, r in res.items() if r["verdict"] == "INCIDENT"}
    leads = {k for k, r in res.items() if r["verdict"] != "INCIDENT"}
    return {
        "lines": _lines(NOISY / sample), "skipped": stats.get("skipped_malformed", 0),
        "verdicts": {k: r["verdict"] for k, r in sorted(res.items())},
        "inc_tp": sorted(inc & mal), "inc_fp": sorted(inc - mal), "inc_fn": sorted(exp - inc),
        "lead_tp": sorted(leads & mal), "lead_fp": sorted(leads - mal),
        "missed": sorted(mal - set(res)),
    }


def score_02() -> dict:
    mod = _load(CT / "ioc_analyzer.py", "ioc_analyzer_noisy")
    sample = CT / "sample_data" / "sample_cloudtrail_noisy.json"
    truth = json.loads((CT / "sample_data" / "sample_cloudtrail_noisy.truth.json").read_text(encoding="utf-8"))
    records = mod.parse_cloudtrail(str(sample))
    findings = mod.detect_all(records)
    mal_ip, mal_actor = set(truth["malicious_ips"]), set(truth["malicious_actors"])
    per = {}
    for f in findings:
        d = per.setdefault(f["detector"], Counter())
        d["TP" if f["ip"] in mal_ip or f["actor"] in mal_actor else "FP"] += 1
    fn = []
    for e in truth["expected"]:
        hit = any(f["detector"] == e["detector"] and
                  (("ip" in e and f["ip"] == e["ip"]) or
                   ("event" in e and f["event"] == e["event"] and f["actor"] == e["actor"]))
                  for f in findings)
        if not hit:
            fn.append(e)
    raw = json.loads(sample.read_text(encoding="utf-8"))["Records"]
    return {"records": len(raw), "parsed": len(records), "findings": len(findings), "per": per, "fn": fn}


def render() -> str:
    out = ["| Lab · noisy sample | Lines / records | True positives | False positives | Missed (FN) | Leads to triage (benign / malicious) | Skipped malformed |",
           "|---|---|---|---|---|---|---|"]
    c = score_02()
    tp = sum(v["TP"] for v in c["per"].values())
    fp = sum(v["FP"] for v in c["per"].values())
    out.append(f"| 02 CloudTrail IOC analyzer · `sample_cloudtrail_noisy.json` (finding-level) | {c['records']} "
               f"| {tp} | {fp} | {len(c['fn'])} | n/a | {c['records'] - c['parsed']} non-object entries |")
    details_07 = []
    for title, det, sample in CASES_07:
        s = score_07(det, sample)
        out.append(f"| 07 {title} · `{sample}` (per source) | {s['lines']} | {len(s['inc_tp'])} | {len(s['inc_fp'])} "
                   f"| {len(s['inc_fn'])} | {len(s['lead_fp'])} / {len(s['lead_tp'])} | {s['skipped']} |")
        details_07.append((title, sample, s))
    out += ["", "**02 per detector (finding-level):**", "",
            "| Detector | TP findings | FP findings |", "|---|---|---|"]
    for d in ("brute_force", "unusual_geo", "suspicious_api"):
        v = c["per"].get(d, Counter())
        out.append(f"| `{d}` | {v['TP']} | {v['FP']} |")
    if c["fn"]:
        out += ["", "**02 missed:** " + "; ".join(
            f"`{e['detector']}` on {e.get('ip') or e.get('event')}" + (f" ({e['note']})" if e.get("note") else "")
            for e in c["fn"])]
    out += ["", "**07 verdicts per source:**", ""]
    for title, sample, s in details_07:
        out.append(f"- `{sample}`: " + ", ".join(f"{k} → {v}" for k, v in s["verdicts"].items()))
    return "\n".join(out)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    card = render()
    if "--write" in argv:
        text = DOC.read_text(encoding="utf-8")
        new = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END), lambda _m: f"{BEGIN}\n{card}\n{END}", text, flags=re.S)
        DOC.write_text(new, encoding="utf-8")
    print(card)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

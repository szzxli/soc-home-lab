"""Tests for tools/verify_kev.py and tools/noisy_scorecard.py.

Offline: the feed is synthesized from the manifest (the live feed is checked by
the KEV verify GitHub Actions workflow), then mutated to prove each kind of
mismatch is caught.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import noisy_scorecard  # noqa: E402
import verify_kev as vk  # noqa: E402


@pytest.fixture()
def manifest():
    return vk.load_manifest(ROOT)


def feed_from(manifest):
    vulns = [{"cveID": c, **{f: m[f] for f in vk.FIELDS}} for c, m in manifest["cves"].items() if m["inKev"]]
    vulns.append({"cveID": "CVE-2020-0001", "vendorProject": "X", "product": "Y", "vulnerabilityName": "Z",
                  "dateAdded": "2020-01-01", "dueDate": "2020-01-15"})
    return {"catalogVersion": manifest["verified"]["catalogVersion"], "dateReleased": "2026-10-21T00:00:00Z",
            "vulnerabilities": vulns}


def test_repo_is_consistent_with_its_manifest(manifest):
    assert vk.verify(manifest, feed_from(manifest), ROOT) == []


def test_every_pack_has_sources_and_verified_line(manifest):
    assert len(manifest["packs"]) == 10
    for pack in manifest["packs"]:
        text = (ROOT / pack["file"]).read_text()
        assert "**Sources:**" in text and "Verified against CISA KEV on " in text, pack["file"]
        for c in pack["cves"]:
            assert f"https://nvd.nist.gov/vuln/detail/{c}" in text
            assert f"search_api_fulltext={c}" in text


def test_due_date_mismatch_is_caught(manifest):
    feed = feed_from(manifest)
    for v in feed["vulnerabilities"]:
        if v["cveID"] == "CVE-2026-104935":
            v["dueDate"] = "2026-10-30"
    problems = vk.verify(manifest, feed, ROOT)
    assert any("CVE-2026-104935: dueDate" in p for p in problems)
    # prose that states the old due date is flagged too
    assert any("START_HERE.md" in p and "due 2026-10-16" in p for p in problems)


def test_newly_listed_cve_is_caught(manifest):
    feed = feed_from(manifest)
    feed["vulnerabilities"].append({"cveID": "CVE-2026-25243", "vendorProject": "Redis", "product": "x",
                                    "vulnerabilityName": "x", "dateAdded": "2026-10-28", "dueDate": "2026-11-18"})
    problems = vk.verify(manifest, feed, ROOT)
    assert any("CVE-2026-25243: manifest says not in KEV" in p for p in problems)
    assert any("claims CVE-2026-25243 is not in KEV" in p for p in problems)
    assert any('data-kev="no" for CVE-2026-25243' in p for p in problems)


def test_delisted_cve_and_vendor_rename_are_caught(manifest):
    feed = feed_from(manifest)
    feed["vulnerabilities"] = [v for v in feed["vulnerabilities"] if v["cveID"] != "CVE-2026-21589"]
    for v in feed["vulnerabilities"]:
        if v["cveID"] == "CVE-2026-102764":
            v["product"] = "Remote Support and Privileged Remote Access"
    problems = vk.verify(manifest, feed, ROOT)
    assert any("CVE-2026-21589: manifest says in KEV" in p for p in problems)
    assert any("CVE-2026-102764: product" in p for p in problems)


def test_stale_block_is_caught(manifest):
    m = copy.deepcopy(manifest)
    m["verified"]["date"] = "2099-01-01"
    problems = vk.check_blocks(m, ROOT)
    assert len([p for p in problems if "out of date" in p]) == 11  # 10 packs + intel table


def test_prose_scanner_catches_wrong_claims(tmp_path, manifest):
    (tmp_path / "07-kev-hunting").mkdir()
    (tmp_path / "web").mkdir()
    (tmp_path / "README.md").write_text(
        "- Bricksforge CVE-2026-85097. **KEV: listed**\n\n"
        "- Ivanti CVE-2026-104935, In CISA KEV (added 2026-10-14, federal due 2026-10-16)\n\n"
        "- Siemens CVE-2026-110936 is **not** in CISA KEV.\n\n"
        "- Typo CVE-2026-1049350 here.\n")
    (tmp_path / "web" / "index.html").write_text(
        '<article class="tile" data-cve="CVE-2026-85097" data-kev="yes"></article>\n'
        "<tr><td>Redis</td><td>CVE-2026-25243 · KEV</td></tr>\n")
    problems = vk.scan_claims(manifest, feed_from(manifest), tmp_path)
    text = "\n".join(problems)
    assert "claims CVE-2026-85097 is in KEV" in text
    assert "added 2026-10-14" in text
    assert "claims CVE-2026-110936 is not in KEV" in text
    assert "CVE-2026-1049350 is not tracked" in text
    assert 'data-kev="yes" for CVE-2026-85097' in text
    assert "claims CVE-2026-25243 is in KEV" in text


def test_feed_error_exit_code(tmp_path):
    assert vk.main(["--feed", str(tmp_path / "missing.json")]) == 2


def test_cli_against_synth_feed(tmp_path, manifest):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps(feed_from(manifest)))
    report = tmp_path / "r.md"
    assert vk.main(["--feed", str(feed), "--report", str(report)]) == 0
    assert "all claims match" in report.read_text()


def test_noisy_data_doc_matches_scorecard():
    doc = (ROOT / "NOISY_DATA.md").read_text()
    block = doc.split(noisy_scorecard.BEGIN, 1)[1].split(noisy_scorecard.END, 1)[0].strip()
    assert block == noisy_scorecard.render().strip(), "run: python3 tools/noisy_scorecard.py --write"


def test_stale_verified_line_on_site_is_caught(manifest):
    m = copy.deepcopy(manifest)
    m["verified"] = {"date": "2026-10-28", "catalogVersion": "2026.10.28"}
    problems = vk.scan_claims(m, feed_from(manifest), ROOT)
    assert any(p.startswith("web/index.html") and "says verified 2026-10-24" in p for p in problems)

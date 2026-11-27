#!/usr/bin/env python3
"""Generate the weekly KEV page and coverage badge from the manifest + CISA feed.

Outputs (written in place, deterministic for a given feed + manifest + date):
  web/kev-this-week.html  - entries added to CISA KEV in the last 7 days of the
                            feed, each tied to a shipped hunt pack from
                            07-kev-hunting/kev-manifest.json or marked
                            "not covered yet"; plus the most recent tracked
                            in-KEV CVEs and the current coverage counts.
  web/img/kev-labs.svg    - badge "KEV labs: N", where N is the number of
                            manifest packs covering at least one CVE the
                            manifest marks inKev.

The feed source is the same one tools/verify_kev.py uses (cisa.gov, with the
cisagov GitHub mirror as fallback). Coverage is never invented: a CVE is
"covered" only when a manifest pack lists it and the pack file exists.

Usage:
  python3 tools/gen_kev_week.py [--feed kev.json] [--date YYYY-MM-DD]
Exit codes: 0 = written, 2 = feed could not be loaded.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import sys
import urllib.request
from pathlib import Path

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "07-kev-hunting" / "kev-manifest.json"
PAGE = ROOT / "web" / "kev-this-week.html"
BADGE = ROOT / "web" / "img" / "kev-labs.svg"
WINDOW_DAYS = 7
TRACKED_ROWS = 8
REPO_BLOB = "https://github.com/szzxli/soc-home-lab/blob/main/"

GC_LOADER = ("<script>(function(w,d,l){var q=l.search,skip=/[?&](v|cb|_|nocount)=|[?&]cachebust/i.test(q);"
             "try{var s=w.localStorage;if(/[?&]nocount=1(&|$)/.test(q))s.setItem('skipgc','t');"
             "if(/[?&]nocount=0(&|$)/.test(q))s.removeItem('skipgc');if(s.getItem('skipgc')==='t')skip=true}catch(e){}"
             "w.gcSkip=skip;if(skip)return;var g=d.createElement('script');g.async=true;"
             "g.src='https://gc.zgo.at/count.js';g.setAttribute('data-goatcounter','https://szzxli.goatcounter.com/count');"
             "(d.head||d.documentElement).appendChild(g)})(window,document,location);</script>")


def load_feed(path: str | None) -> dict:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    for url in (FEED_URL, MIRROR_URL):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "soc-home-lab kev-week generator"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001 - fall through to the mirror
            print(f"feed fetch failed ({url}): {e}", file=sys.stderr)
    raise SystemExit(2)


def coverage_map(manifest: dict) -> dict:
    """CVE -> pack, only for packs whose shipped file exists in the repo."""
    out = {}
    for pack in manifest["packs"]:
        if not (ROOT / pack["file"]).exists():
            continue
        for cve in pack.get("cves", []):
            out.setdefault(cve.upper(), pack)
    return out


def labs_count(manifest: dict) -> int:
    """KEV labs N: manifest packs covering >=1 CVE marked inKev, file shipped."""
    inkev = {c.upper() for c, v in manifest["cves"].items() if v.get("inKev")}
    n = 0
    for pack in manifest["packs"]:
        if not (ROOT / pack["file"]).exists():
            continue
        if any(c.upper() in inkev for c in pack.get("cves", [])):
            n += 1
    return n


def cov_cell(cve: str, cov: dict) -> str:
    pack = cov.get(cve.upper())
    if pack is None:
        return "not covered yet"
    return f'<a href="{REPO_BLOB}{pack["file"]}">{html.escape(pack["id"])}</a>'


def row(cve: str, vendor: str, product: str, added: str, due: str, cov: dict) -> str:
    who = html.escape(f"{vendor} {product}".strip())
    return (f"<tr><td>{html.escape(cve)}</td><td>{who}</td>"
            f"<td>Added {html.escape(added)}</td><td>Due {html.escape(due)}</td>"
            f"<td>{cov_cell(cve, cov)}</td></tr>")


def render_page(manifest: dict, feed: dict, checked: str) -> str:
    cov = coverage_map(manifest)
    inkev = {c.upper(): v for c, v in manifest["cves"].items() if v.get("inKev")}
    covered = sum(1 for c in inkev if c in cov)
    n_labs = labs_count(manifest)
    released = str(feed.get("dateReleased", ""))[:10]
    try:
        rel = dt.date.fromisoformat(released)
    except ValueError:
        rel = dt.date.fromisoformat(checked)
    start = rel - dt.timedelta(days=WINDOW_DAYS - 1)
    recent = [v for v in feed["vulnerabilities"]
              if start.isoformat() <= str(v.get("dateAdded", "")) <= rel.isoformat()]
    recent.sort(key=lambda v: (str(v.get("dateAdded", "")), str(v.get("cveID", ""))), reverse=True)
    tracked = sorted(inkev.items(), key=lambda kv: (str(kv[1].get("dateAdded", "")), kv[0]), reverse=True)
    tracked = tracked[:TRACKED_ROWS]

    recent_rows = "\n".join(
        row(str(v.get("cveID", "")), str(v.get("vendorProject", "")), str(v.get("product", "")),
            str(v.get("dateAdded", "")), str(v.get("dueDate", "")), cov)
        for v in recent)
    if not recent_rows:
        recent_rows = (f'<tr><td colspan="5">No new KEV entries in the last {WINDOW_DAYS} days '
                       f"as of {checked}.</td></tr>")
    tracked_rows = "\n".join(
        row(cve, str(v.get("vendorProject", "")), str(v.get("product", "")),
            str(v.get("dateAdded", "")), str(v.get("dueDate", "")), cov)
        for cve, v in tracked)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KEV This Week · SOC Home Lab</title>
<meta name="description" content="CISA KEV entries added this week, each tied to a shipped SOC Home Lab hunt pack or marked not covered yet.">
<link rel="canonical" href="https://szzxli.github.io/soc-home-lab/web/kev-this-week.html">
<link rel="stylesheet" href="css/style.css?v=20261029">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<nav class="nav" aria-label="Main">
<div class="wrap">
<a class="brand" href="./">soc<span>-home-lab</span></a>
<ul>
<li class="opt"><a href="./#labs">Labs</a></li>
<li><a href="./#kev">KEV hunts</a></li>
<li><a href="kev-this-week.html" aria-current="page">KEV this week</a></li>
<li><a href="demo.html">Demo</a></li>
<li class="opt"><a href="https://github.com/szzxli/soc-home-lab/blob/main/START_HERE.md" data-count="open-start-here">Start here</a></li>
<li><a href="https://github.com/szzxli/soc-home-lab">GitHub</a></li>
</ul>
</div>
</nav>

<main id="main" class="wrap">
<header class="page-head">
<p class="eyebrow">$ ./verify_kev.py --weekly</p>
<h1>KEV this week <span class="accent">· coverage</span></h1>
<p class="lead">What CISA added to the Known Exploited Vulnerabilities catalog this week, and which of those entries already have a hunt pack in this repo. Entries without a pack say so plainly.</p>
<p class="sub" style="margin:8px 0 0;font-size:14px"><a href="./">← back to all projects</a></p>
</header>

<div class="card">
<h2>Last checked</h2>
<p>Last checked {checked} against the CISA KEV catalog (version {html.escape(str(feed.get("catalogVersion", "")))}, released {html.escape(released)}). Coverage now: {n_labs} KEV labs covering {covered} of {len(inkev)} tracked in-catalog CVEs. Hunt packs use synthetic training data.</p>
<p><button class="btn" id="showWeek" data-count="kev-week-view" aria-expanded="false">Show this week's KEV entries</button></p>
<div id="weekTable" hidden>
<table>
<thead><tr><th>CVE</th><th>Vendor / product</th><th>Added</th><th>Due</th><th>Coverage</th></tr></thead>
<tbody>
{recent_rows}
</tbody>
</table>
</div>
</div>

<div class="card">
<h2>Most recent tracked entries</h2>
<p>The newest catalog entries this repo tracks, newest first. Coverage links to the shipped hunt checklist; intel-only entries have no pack yet.</p>
<table>
<thead><tr><th>CVE</th><th>Vendor / product</th><th>Added</th><th>Due</th><th>Coverage</th></tr></thead>
<tbody>
{tracked_rows}
</tbody>
</table>
</div>

<div class="card">
<h2>Sources</h2>
<p class="links"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV catalog</a> · <a href="https://github.com/szzxli/soc-home-lab/blob/main/07-kev-hunting/kev-manifest.json">coverage manifest</a> · <a href="https://github.com/szzxli/soc-home-lab/blob/main/tools/verify_kev.py">weekly verifier</a></p>
<p>Privacy: we use <a href="https://www.goatcounter.com" rel="noopener">GoatCounter</a>, a privacy-friendly, cookie-free page-view counter (no personal data, no cookies; its small script loads from gc.zgo.at).</p>
</div>
</main>
<script src="js/analytics.js" defer></script>
<script>
(function () {{
  var btn = document.getElementById('showWeek');
  var box = document.getElementById('weekTable');
  if (!btn || !box) return;
  btn.addEventListener('click', function () {{
    var show = box.hidden;
    box.hidden = !show;
    btn.setAttribute('aria-expanded', show ? 'true' : 'false');
    btn.textContent = show ? "Hide this week's KEV entries" : "Show this week's KEV entries";
  }});
}})();
</script>
{GC_LOADER}
</body>
</html>
"""


def render_badge(n: int) -> str:
    label, value = "KEV labs", str(n)
    lw = 6 * len(label) + 10
    vw = 6 * len(value) + 10
    w = lw + vw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {value}">
<title>{label}: {value}</title>
<linearGradient id="g" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{w}" height="20" rx="3"/></clipPath>
<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{vw}" height="20" fill="#2e7d32"/><rect width="{w}" height="20" fill="url(#g)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
<text x="{lw // 2}" y="14">{label}</text>
<text x="{lw + vw // 2}" y="14">{value}</text>
</g>
</svg>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", help="local CISA KEV JSON copy instead of fetching")
    ap.add_argument("--date", help="last-checked date YYYY-MM-DD (default: today, UTC)")
    args = ap.parse_args()
    checked = args.date or dt.datetime.now(dt.timezone.utc).date().isoformat()
    feed = load_feed(args.feed)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    PAGE.write_text(render_page(manifest, feed, checked), encoding="utf-8")
    BADGE.parent.mkdir(parents=True, exist_ok=True)
    BADGE.write_text(render_badge(labs_count(manifest)), encoding="utf-8")
    print(f"wrote {PAGE.relative_to(ROOT)} and {BADGE.relative_to(ROOT)} "
          f"(labs={labs_count(manifest)}, checked={checked})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

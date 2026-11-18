#!/usr/bin/env python3
"""Optimizely supply-chain detector: flag the 16 Nov 2026 incident in a
snippet-fetch / CSP-report log and correlate it per site.

Detection / forensic-triage practice only — no exploit code.

Background (see ../hunt-checklist-optimizely-supply-chain.md): an attacker
wrote a loader into the Project JavaScript of Optimizely customer projects,
so the infected snippet was still served from cdn.optimizely.com. The loader
swapped crypto wallets, skimmed cards (POST to 1688360.cc/card.php via
sendBeacon), stole cookies and screenshots (1688360.cc/hit.php), and routed
iOS devices to exploit kits (boot.js from 5vobauua3ojpklx.icu /
eil786npto9u5bq.icu). No CVE was assigned and the incident is not in CISA
KEV; the IOCs below are the published Report URI indicators.

Log format (one event per line, see ../samples/optimizely-snippets.log):
  <ISO-8601 UTC ts> <site> <EVENT> <URL> [fields...]
  EVENT is FETCH, BEACON, or CSP-REPORT.

Signals (all per site):
  INFECTED_SNIPPET  a fetch of cdn.optimizely.com whose snippet hash is one
                    of the two published infected track.js builds, or whose
                    line carries a published marker (window._k7,
                    window.__k7b, data-channel-code="02111110", BIGNIAO).
                    A clean Optimizely snippet never fires.
  C2_CONTACT        a fetch/beacon to a published IOC domain (1688360.cc,
                    5vobauua3ojpklx.icu, eil786npto9u5bq.icu,
                    l7bcsnwc7nzr3uo.icu, webshell.lol, linkforge.cc,
                    je4ft3gn8vxudum.icu, q1ls1ho9x7wsxlu.icu, ios-hack.icu).
  IOS_ROUTER        a fetch of boot.js from one of the two iOS-kit domains
                    (5vobauua3ojpklx.icu, eil786npto9u5bq.icu).
  SKIMMER_BEACON    a sendBeacon POST to 1688360.cc/card.php — the card
                    skimmer's exfiltration channel.
Verdicts per site:
  INCIDENT       any C2_CONTACT or IOS_ROUTER. SKIMMER_BEACON is a sub-label
                 of a C2 contact in this detector (the same line always also
                 fires C2_CONTACT), so the verdict rule is exactly the one
                 stated above.
  SUSPICIOUS     INFECTED_SNIPPET only — the snippet is infected but no
                 contact with attacker infrastructure was seen in the log
Benign by design: clean Optimizely snippets, unrelated third-party scripts,
and CSP-REPORT lines never fire. A CSP report whose blocked-uri names an IOC
domain is NOT contact — the browser refused it — so CSP-REPORT lines are
skipped entirely, before any IOC matching. Lines that are not events are
skipped and counted.

Usage: python3 optimizely-detect.py <snippets.log>
"""
import re
import sys

IOC_DOMAINS = {
    "1688360.cc",
    "5vobauua3ojpklx.icu",
    "eil786npto9u5bq.icu",
    "l7bcsnwc7nzr3uo.icu",
    "webshell.lol",
    "linkforge.cc",
    "je4ft3gn8vxudum.icu",
    "q1ls1ho9x7wsxlu.icu",
    "ios-hack.icu",
}
IOS_KIT_DOMAINS = {"5vobauua3ojpklx.icu", "eil786npto9u5bq.icu"}
INFECTED_HASHES = {
    # track.js 17:13 build and latest 17:57 build, per Report URI.
    "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f",
    "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40",
}
MARKERS = ("_k7", "__k7b", "02111110", "BIGNIAO")
HASH = re.compile(r"hash=([0-9a-f]{64})")
URL = re.compile(r"https?://([^/:\s]+)(/\S*)?")


def _host(url):
    m = URL.search(url or "")
    return m.group(1).lower() if m else ""


def _is_ioc(host):
    return any(host == d or host.endswith("." + d) for d in IOC_DOMAINS)


def analyze(path, stats=None):
    """Return {site: {"verdict": str, "hits": [(lineno, ts, kind, detail)]}}.

    If *stats* is a dict it receives counters: lines, skipped_malformed.
    """
    hits = {}  # site -> list of (lineno, ts, kind, detail)
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stats["lines"] += 1
            parts = line.split()
            if len(parts) < 4:
                stats["skipped_malformed"] += 1
                continue
            ts_text, site, event, url = parts[0], parts[1], parts[2], parts[3]
            if event == "CSP-REPORT":
                # A blocked-uri report names the domain but is not a contact.
                continue
            host = _host(url)
            kinds = []
            if "cdn.optimizely.com" in url:
                hm = HASH.search(line)
                if (hm and hm.group(1) in INFECTED_HASHES) or any(
                    mk in line for mk in MARKERS
                ):
                    kinds.append(("INFECTED_SNIPPET", f"infected Optimizely snippet: {url[:80]}"))
            if host and _is_ioc(host):
                kinds.append(("C2_CONTACT", f"contact with IOC domain: {url[:80]}"))
                if host in IOS_KIT_DOMAINS and "boot.js" in url:
                    kinds.append(("IOS_ROUTER", f"iOS-kit router: {url[:80]}"))
                if host == "1688360.cc" and "card.php" in url and "sendBeacon" in line:
                    kinds.append(("SKIMMER_BEACON", f"card skimmer beacon: {url[:80]}"))
            for kind, detail in kinds:
                hits.setdefault(site, []).append((n, ts_text, kind, detail))
    result = {}
    for site, hs in hits.items():
        kinds = {h[2] for h in hs}
        verdict = (
            "INCIDENT"
            if kinds & {"C2_CONTACT", "IOS_ROUTER", "SKIMMER_BEACON"}
            else "SUSPICIOUS"
        )
        result[site] = {"verdict": verdict, "hits": hs}
    return result


def main(path):
    stats = {}
    res = analyze(path, stats)
    if not res:
        print("no findings")
    for site, r in sorted(res.items()):
        print(f"[{r['verdict']}] {site} ({len(r['hits'])} hits):")
        for n, ts, kind, detail in r["hits"]:
            print(f"  L{n} {ts} {kind:<18} {detail[:110]}")
    if stats["skipped_malformed"]:
        print(f"note: {stats['skipped_malformed']} malformed line(s) skipped")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin")

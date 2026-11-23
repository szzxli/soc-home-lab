#!/usr/bin/env python3
"""ARTEX detector: flag agentic attack framework traffic in a proxy log and
correlate it per source address.

Detection / hunting practice only — no exploit code, no scanning for
exposed consoles.

Background (see ../hunt-checklist-artex-agentic-attacks.md): ARTEX is a Go
planner-and-worker agentic attack framework (AntiFox is the same code
renamed) reported in intrusions since August 2026. There is no CVE for the
framework itself, so there is no CISA KEV entry. This is a small slice of
the published markers for that framework — the 572-indicator feed was not
imported. A single line can carry more than one marker (for example a
branded user agent and a framework key header on the same request), so one
line may produce several hits.

Log format (one event per line, see ../samples/artex-proxy.log):
  <ISO-8601 UTC ts> <proxy> <src IP> <METHOD> <URI> ua="..." headers="..." dstport=...

Signals (all per source address):
  ARTEX_UA            User agent starting "artex-" (artex-pentest/1.0, the
                      per-role form artex-<role>/1.0), "antifox-"
                      (antifox-enrich/1.0, antifox-selfupdate), "norma/0.4",
                      or "spa-api-recon". A careful operator can change
                      these, so absence of a marker does not clear a host.
  ARTEX_KEY_HEADER    Request carrying an X-ARTX-KEY header. Legitimate
                      traffic to your applications does not send it.
  UNSIGNED_JWT_PROBE  URI carrying an unsigned-JWT marker: a base64
                      {"alg":"none"} header (eyJhbGciOiJub25l) or an
                      alg/none pair in the query string. Normal JWTs are
                      signed; an alg:none token is a probe, not a credential.
  CONSOLE_PORT        Connection to destination port 8788, the AntiFox
                      unauthenticated recording proxy. Weak on its own —
                      port 8788 is not reserved — so it only ever counts as
                      a supporting marker, never as an incident by itself.
Verdicts per source address (signals within 60 minutes of each other):
  INCIDENT       ARTEX_UA plus any other signal kind on the same source
                 within 60 minutes
  SUSPICIOUS     any signal kind on the source, without that correlation
Benign by design: normal browser traffic, authenticated API calls, and
ordinary destination ports never match. Lines that are not events are
skipped and counted.

Usage: python3 artex-agentic-detect.py <proxy.log>
"""
import re
import sys
from datetime import datetime, timedelta

UA_PATTERNS = (
    re.compile(r"artex-[a-z0-9_-]+/1\.0", re.I),
    re.compile(r"antifox-[a-z0-9_-]+/1\.0", re.I),
    re.compile(r"norma/0\.4", re.I),
    re.compile(r"spa-api-recon", re.I),
)
JWT_PATTERNS = (
    re.compile(r"eyJhbGciOiJub25l", re.I),          # base64 of {"alg":"none"
    re.compile(r"alg%22%3A%22none", re.I),          # URL-encoded "alg":"none"
    re.compile(r'alg["\']?\s*[:=]\s*["\']?none', re.I),
)
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
WINDOW = timedelta(minutes=60)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TIME_FMT)
    except (ValueError, TypeError):
        return None


def analyze(path, stats=None):
    """Return {src: {"verdict": str, "hits": [(lineno, ts, kind, detail)]}}.

    If *stats* is a dict it receives counters: lines, skipped_malformed.
    """
    hits = {}  # src -> list of (lineno, datetime|None, kind, detail)
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stats["lines"] += 1
            parts = line.split()
            if len(parts) < 5:
                stats["skipped_malformed"] += 1
                continue
            ts = _parse_ts(parts[0])
            src = parts[2]
            uri = parts[4]
            ua_m = re.search(r'ua="([^"]*)"', line)
            ua = ua_m.group(1) if ua_m else ""
            hdr_m = re.search(r'headers="([^"]*)"', line)
            headers = hdr_m.group(1) if hdr_m else ""
            port_m = re.search(r"dstport=(\d+)", line)
            port = port_m.group(1) if port_m else ""
            found = []
            if any(p.search(ua) for p in UA_PATTERNS):
                found.append(("ARTEX_UA", f"branded user agent: {ua[:60]!r}"))
            if "x-artx-key" in headers.lower():
                found.append(("ARTEX_KEY_HEADER", "request carries X-ARTX-KEY header"))
            if any(p.search(uri) for p in JWT_PATTERNS):
                found.append(("UNSIGNED_JWT_PROBE", "URI carries unsigned alg:none JWT marker"))
            if port == "8788":
                found.append(("CONSOLE_PORT", "connection to destination port 8788 (AntiFox recording proxy)"))
            for kind, detail in found:
                hits.setdefault(src, []).append((n, ts, kind, detail))
    result = {}
    for src, hs in hits.items():
        kinds = {h[2] for h in hs}
        correlated = False
        if "ARTEX_UA" in kinds and len(kinds) >= 2:
            uas = [h for h in hs if h[2] == "ARTEX_UA"]
            others = [h for h in hs if h[2] != "ARTEX_UA"]
            for u in uas:
                for o in others:
                    if u[1] is not None and o[1] is not None:
                        if abs(o[1] - u[1]) <= WINDOW:
                            correlated = True
                            break
                    else:
                        correlated = True
                        break
                if correlated:
                    break
        verdict = "INCIDENT" if correlated else "SUSPICIOUS"
        result[src] = {"verdict": verdict, "hits": hs}
    return result


def main(path):
    stats = {}
    res = analyze(path, stats)
    if not res:
        print("no findings")
    for src, r in sorted(res.items()):
        print(f"[{r['verdict']}] {src} ({len(r['hits'])} hits):")
        for n, ts, kind, detail in r["hits"]:
            print(f"  L{n} {ts} {kind:<20} {detail[:110]}")
    if stats["skipped_malformed"]:
        print(f"note: {stats['skipped_malformed']} malformed line(s) skipped")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin")

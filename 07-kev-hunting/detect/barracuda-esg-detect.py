#!/usr/bin/env python3
"""Barracuda ESG detector: flag the CVE-2026-116606 / CVE-2026-111560 chain in
an appliance log and correlate it per appliance.

Detection / forensic-triage practice only — no exploit code.

Background (see ../hunt-checklist-barracuda-esg.md): CVE-2026-116606 lets an
unauthenticated remote attacker invoke the configuration-import function and
restore a crafted backup, and CVE-2026-111560 turns a malicious timezone value
in that restored config into root command execution when the timezone is
processed. There are no vendor-published IOCs for this chain — no IPs, hashes,
domains, or log lines — so detection is behavioural: what the appliance log
shows the appliance doing, not a signature to match.

Log format (one event per line, see ../samples/barracuda-esg.log):
  <ISO-8601 UTC ts> <appliance> <EVENT> key=value ...

Signals (all per appliance):
  UNAUTH_CONFIG_IMPORT  CONFIG_IMPORT with auth=none — the CVE-2026-116606
                        step. An authenticated admin import is normal and
                        never fires.
  TZ_SHELL_META         TZ_SET whose timezone value contains shell
                        metacharacters (`;`, `|`, `&&`, `$(`, backtick).
                        Legitimate values look like America/Los_Angeles,
                        UTC, EST5EDT.
  ROOT_CMD_FROM_CONFIG  SHELL_CMD with user=root and origin=config-import —
                        a root command that came out of a restored config.
                        An admin shell session (origin=admin-shell) never
                        fires.
Verdicts per appliance (signals within 60 minutes of each other):
  INCIDENT       UNAUTH_CONFIG_IMPORT plus any other signal kind on the same
                 appliance within 60 minutes
  SUSPICIOUS     any signal kind on the appliance, without that correlation
Benign by design: authenticated admin imports, normal timezone changes, and
admin shell use never match. A lone TZ_SHELL_META is SUSPICIOUS, not an
incident: it can be a bad admin edit — check who set it and whether an
unauthenticated import preceded it. Lines that are not events are skipped
and counted.

Usage: python3 barracuda-esg-detect.py <appliance.log>
"""
import re
import sys
from datetime import datetime, timedelta

SHELL_META = re.compile(r"[;|&$`]")
VALUE = re.compile(r'value="([^"]*)"|value=(\S+)')
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
WINDOW = timedelta(minutes=60)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TIME_FMT)
    except (ValueError, TypeError):
        return None


def analyze(path, stats=None):
    """Return {appliance: {"verdict": str, "hits": [(lineno, ts, kind, detail)]}}.

    If *stats* is a dict it receives counters: lines, skipped_malformed.
    """
    hits = {}  # appliance -> list of (lineno, datetime|None, kind, detail)
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stats["lines"] += 1
            parts = line.split()
            if len(parts) < 3:
                stats["skipped_malformed"] += 1
                continue
            ts = _parse_ts(parts[0])
            ts_text = parts[0]
            host = parts[1]
            event = parts[2]
            kind = None
            detail = ""
            if event == "CONFIG_IMPORT" and "auth=none" in line:
                kind = "UNAUTH_CONFIG_IMPORT"
                detail = f"unauthenticated config import: {line.split('file=')[-1].strip()[:60] if 'file=' in line else ''}"
            elif event == "TZ_SET":
                m = VALUE.search(line)
                value = (m.group(1) if m and m.group(1) is not None else
                         m.group(2) if m else "")
                if value and SHELL_META.search(value):
                    kind = "TZ_SHELL_META"
                    detail = f"timezone value {value[:60]!r} contains shell metacharacters"
            elif event == "SHELL_CMD" and "user=root" in line and "origin=config-import" in line:
                kind = "ROOT_CMD_FROM_CONFIG"
                detail = f"root command from restored config: {line.split('command=')[-1].strip()[:80]}"
            if kind:
                hits.setdefault(host, []).append((n, ts, kind, detail))
    result = {}
    for host, hs in hits.items():
        kinds = {h[2] for h in hs}
        correlated = False
        if "UNAUTH_CONFIG_IMPORT" in kinds and len(kinds) >= 2:
            imports = [h for h in hs if h[2] == "UNAUTH_CONFIG_IMPORT"]
            others = [h for h in hs if h[2] != "UNAUTH_CONFIG_IMPORT"]
            for i in imports:
                for o in others:
                    if i[1] is not None and o[1] is not None:
                        if abs(o[1] - i[1]) <= WINDOW:
                            correlated = True
                            break
                    else:
                        # Untimestamped signals on the same appliance still count.
                        correlated = True
                        break
                if correlated:
                    break
        verdict = "INCIDENT" if correlated else "SUSPICIOUS"
        result[host] = {"verdict": verdict, "hits": hs}
    return result


def main(path):
    stats = {}
    res = analyze(path, stats)
    if not res:
        print("no findings")
    for host, r in sorted(res.items()):
        print(f"[{r['verdict']}] {host} ({len(r['hits'])} hits):")
        for n, ts, kind, detail in r["hits"]:
            print(f"  L{n} {ts} {kind:<22} {detail[:110]}")
    if stats["skipped_malformed"]:
        print(f"note: {stats['skipped_malformed']} malformed line(s) skipped")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin")

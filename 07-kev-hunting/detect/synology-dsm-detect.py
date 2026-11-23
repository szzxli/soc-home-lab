#!/usr/bin/env python3
"""Synology DSM detector: flag the CVE-2024-10441 hunt signals in a DSM
audit log and correlate them per NAS.

Detection / forensic-triage practice only — no exploit code.

Background (see ../hunt-checklist-cve-2024-10441.md): CVE-2024-10441 is an
improper encoding/escaping flaw in the DSM system plugin daemon that lets a
remote attacker execute arbitrary code. The vendor advisory and NVD describe
the trigger as "unspecified vectors", so there is no public request signature
to match — detection pivots to audit-log behaviour: what the NAS log shows
the NAS doing after the trigger.

Log format (one event per line, see ../samples/synology-dsm.log):
  <ISO-8601 UTC ts> <NAS host> <EVENT> key=value ...

Signals (all per NAS host):
  ANON_PLUGIN_API         PLUGIN_API with auth=none — an unauthenticated
                          call against the plugin daemon. An authenticated
                          admin call is normal and never fires.
  DAEMON_RESTART          PLUGIN_DAEMON_RESTART with reason=unexpected — a
                          restart outside a maintenance window. A scheduled
                          restart (e.g. after a DSM update) never fires.
  DAEMON_SHELL_CHILD      PLUGIN_DAEMON_CHILD whose process is a shell or a
                          network tool (/bin/sh, /bin/bash, curl, wget, nc).
                          The daemon's normal children are plugin processes,
                          never a shell.
  SUSPICIOUS_PERSISTENCE  SCHED_TASK_CREATE or USER_CREATE with auth=none —
                          persistence created without authentication. An
                          admin-created task or user never fires.
Verdicts per NAS host (signals within 60 minutes of each other):
  INCIDENT       DAEMON_SHELL_CHILD on its own, or ANON_PLUGIN_API plus any
                 other signal kind on the same NAS within 60 minutes
  SUSPICIOUS     any signal kind on the NAS, without that correlation
Benign by design: authenticated admin API use, scheduled daemon restarts,
and admin-created tasks/users never match. Lines that are not events are
skipped and counted.

Usage: python3 synology-dsm-detect.py <dsm-audit.log>
"""
import re
import sys
from datetime import datetime, timedelta

SHELL_TOOLS = re.compile(r"(^|/)(sh|bash|dash|zsh|curl|wget|nc|ncat|socat)$")
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
WINDOW = timedelta(minutes=60)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TIME_FMT)
    except (ValueError, TypeError):
        return None


def analyze(path, stats=None):
    """Return {host: {"verdict": str, "hits": [(lineno, ts, kind, detail)]}}.

    If *stats* is a dict it receives counters: lines, skipped_malformed.
    """
    hits = {}  # host -> list of (lineno, datetime|None, kind, detail)
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
            host = parts[1]
            event = parts[2]
            kind = None
            detail = ""
            if event == "PLUGIN_API" and "auth=none" in line:
                kind = "ANON_PLUGIN_API"
                detail = "unauthenticated plugin-daemon API call"
            elif event == "PLUGIN_DAEMON_RESTART" and "reason=unexpected" in line:
                kind = "DAEMON_RESTART"
                detail = "plugin daemon restarted outside a maintenance window"
            elif event == "PLUGIN_DAEMON_CHILD":
                m = re.search(r"process=(\S+)", line)
                proc = m.group(1) if m else ""
                if proc and SHELL_TOOLS.search(proc):
                    kind = "DAEMON_SHELL_CHILD"
                    detail = f"plugin daemon spawned shell/network tool: {proc}"
            elif event in ("SCHED_TASK_CREATE", "USER_CREATE") and "auth=none" in line:
                kind = "SUSPICIOUS_PERSISTENCE"
                m = re.search(r"name=(\S+)", line)
                detail = ("persistence created without authentication: "
                          f"{m.group(1) if m else event}")
            if kind:
                hits.setdefault(host, []).append((n, ts, kind, detail))
    result = {}
    for host, hs in hits.items():
        kinds = {h[2] for h in hs}
        correlated = False
        if "DAEMON_SHELL_CHILD" in kinds:
            correlated = True
        elif "ANON_PLUGIN_API" in kinds and len(kinds) >= 2:
            imports = [h for h in hs if h[2] == "ANON_PLUGIN_API"]
            others = [h for h in hs if h[2] != "ANON_PLUGIN_API"]
            for i in imports:
                for o in others:
                    if i[1] is not None and o[1] is not None:
                        if abs(o[1] - i[1]) <= WINDOW:
                            correlated = True
                            break
                    else:
                        # Untimestamped signals on the same host still count.
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

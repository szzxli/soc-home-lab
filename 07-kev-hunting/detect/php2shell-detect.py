#!/usr/bin/env python3
"""PHP2Shell detector: flag post-trigger behaviour of CVE-2026-109618 /
CVE-2026-109619 in a Sysmon-for-Linux event log and correlate it per host.

Detection / forensic-triage practice only — no exploit code.

Background (see ../hunt-checklist-php2shell.md): the flaw is memory corruption
inside PHP itself, reached before any application code runs, so the triggering
request has no distinctive shape to hunt on the wire. Detection pivots to what
the PHP worker does AFTER the trigger — the observable CISA names: a PHP worker
process launching a shell or downloading tools — plus the usual follow-on, a new
.php file dropped by a web worker.

Signals (all per host, EventID = Sysmon-for-Linux process / network / file):
  SHELL_SPAWN    EventID 1, parent is a PHP web worker (php-fpm, php-cgi,
                 httpd/apache2 mod_php, frankenphp, lsphp) and the child is a
                 shell (sh, bash, dash, zsh). Bare `php` (CLI) is NOT a web
                 worker: cron running `php artisan` must not fire.
  TOOL_DOWNLOAD  EventID 1, child is curl/wget, and its parent is a PHP web
                 worker OR a shell this detector already flagged as a
                 SHELL_SPAWN (linked by ParentProcessGuid).
  NET_OUT        EventID 3, image is a flagged shell or download tool
                 connecting out (linked by ProcessGuid).
  WEBSHELL_DROP  EventID 11, image is a PHP web worker creating a new .php /
                 .phtml file, except under known template-cache directories
                 (storage/framework/views, var/cache, cache/twig), which
                 frameworks write legitimately — see the allowlist note below.
Verdicts per host (signals within 60 minutes of each other):
  INCIDENT       SHELL_SPAWN plus any other signal kind on the same host
  SUSPICIOUS     exactly one signal kind on the host
Benign by design: FPM master spawning pool workers, cron/CLI php, shells and
download tools whose parent is not a PHP worker (admin login, monitoring),
outbound connections made directly by a PHP worker, and .php writes under
template-cache directories never match. A lone SHELL_SPAWN is SUSPICIOUS, not
an incident: known application shell-outs (document conversion, media tools)
are the main false-positive source — triage the command line and allowlist the
exact command if it is a known application behaviour; do not silence the
signal class. Lines that are not valid JSON events are skipped and counted.

Usage: python3 php2shell-detect.py <sysmon.log>
"""
import json
import re
import sys
from datetime import datetime, timedelta

PHP_WORKER = re.compile(r"(?:^|/)(php-fpm[^/]*|php-cgi|httpd|apache2|frankenphp|lsphp)$", re.I)
SHELL = re.compile(r"(?:^|/)(sh|bash|dash|zsh)$", re.I)
TOOL = re.compile(r"(?:^|/)(curl|wget)$", re.I)
PHP_FILE = re.compile(r"\.(?:php|phtml|php\d)$", re.I)
# Template-cache directories frameworks write .php into legitimately.
TEMPLATE_CACHE = re.compile(
    r"(?:^|/)(?:storage/framework/views|var/cache|cache/twig)(?:/|$)", re.I
)
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
WINDOW = timedelta(minutes=60)


def _basename(path):
    return (path or "").rsplit("/", 1)[-1]


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
    shell_guids = set()  # ProcessGuids of flagged SHELL_SPAWN children
    tool_guids = set()  # ProcessGuids of flagged TOOL_DOWNLOAD children
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stats["lines"] += 1
            try:
                ev = json.loads(line)
            except ValueError:
                stats["skipped_malformed"] += 1
                continue
            if not isinstance(ev, dict):
                stats["skipped_malformed"] += 1
                continue
            host = ev.get("Computer") or "unknown"
            ts = _parse_ts(ev.get("Time"))
            ts_text = ev.get("Time") or "?"
            eid = ev.get("EventID")
            image = ev.get("Image") or ""
            parent = ev.get("ParentImage") or ""
            kind = None
            detail = ""
            if eid == 1:
                if PHP_WORKER.search(_basename(parent)) and SHELL.search(_basename(image)):
                    kind = "SHELL_SPAWN"
                    detail = f"{_basename(parent)} -> {_basename(image)}: {(ev.get('CommandLine') or '')[:100]}"
                    shell_guids.add(ev.get("ProcessGuid"))
                elif TOOL.search(_basename(image)) and (
                    PHP_WORKER.search(_basename(parent))
                    or ev.get("ParentProcessGuid") in shell_guids
                ):
                    kind = "TOOL_DOWNLOAD"
                    detail = f"{_basename(parent)} -> {_basename(image)}: {(ev.get('CommandLine') or '')[:100]}"
                    tool_guids.add(ev.get("ProcessGuid"))
            elif eid == 3:
                if ev.get("ProcessGuid") in shell_guids | tool_guids and (
                    SHELL.search(_basename(image)) or TOOL.search(_basename(image))
                ):
                    kind = "NET_OUT"
                    detail = f"{_basename(image)} -> {ev.get('DestinationIp')}:{ev.get('DestinationPort')}"
            elif eid == 11:
                target = ev.get("TargetFilename") or ""
                if (
                    PHP_WORKER.search(_basename(image))
                    and PHP_FILE.search(target)
                    and not TEMPLATE_CACHE.search(target)
                ):
                    kind = "WEBSHELL_DROP"
                    detail = f"{_basename(image)} created {target[:100]}"
            if kind:
                hits.setdefault(host, []).append((n, ts, kind, detail))
    result = {}
    for host, hs in hits.items():
        kinds = {h[2] for h in hs}
        # Correlate within the window: sort by time; unparseable times group together.
        timed = sorted([h for h in hs if h[1] is not None], key=lambda h: h[1])
        correlated = False
        if len(kinds) >= 2 and timed:
            for i in range(len(timed)):
                for j in range(i + 1, len(timed)):
                    if timed[j][1] - timed[i][1] <= WINDOW and timed[i][2] != timed[j][2]:
                        correlated = True
                        break
                if correlated:
                    break
        # Untimestamped signals on the same host still count as one group.
        if len(kinds) >= 2 and any(h[1] is None for h in hs):
            correlated = True
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
            print(f"  L{n} {ts} {kind:<14} {detail[:110]}")
    if stats["skipped_malformed"]:
        print(f"note: {stats['skipped_malformed']} malformed line(s) skipped")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin")

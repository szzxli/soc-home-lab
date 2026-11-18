#!/usr/bin/env python3
"""Check Point DynamicCLI detector: flag CVE-2026-123039 abuse in
/var/log/dynamicCli.log and report post-fix rejections.

Detection / forensic-triage practice only — no exploit code.

Background (see ../hunt-checklist-checkpoint-dynamiccli.md): the Gaia OS
DynamicCLI daemon (dynamic_server) runs as root and listens on the
world-writable local socket /tmp/dynamic_socket without authenticating
connecting processes, so an authenticated local user can send it a command
that runs as root. In the observed incident this was the second layer after
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) gave unauthenticated RCE as
the portal account. The vendor checks (sk1000362) are verbatim greps on
/var/log/dynamicCli.log; this detector implements them.

Log format (one event per line, see ../samples/checkpoint-dynamiccli.log):
  <ISO-8601 UTC ts> <gateway> dynamicCli[pid]: <message>
  Lines marked [clish-wrapper] came through the legitimate Clish wrapper.

Signals (all per gateway):
  NON_WRAPPER_RECEIVED  a "Received" line that did not come through the
                        Clish wrapper (no [clish-wrapper] marker) and is
                        not the #return_value# echo below. Legitimate
                        wrapper lines never fire.
  SYSTEM_SINK           a "Received = #return_value#" line — the daemon
                        returning a command's output, i.e. a command was
                        executed through the socket.
  EXPLOIT_KEYWORD       a line containing one of the vendor's exploit
                        keywords: id; / whoami / /etc/shadow / ncat /
                        nc - / /dev/tcp / curl / wget / base64 / useradd /
                        authorized_keys.
  REJECTED_UID          "Rejected connection from unauthorized uid" — the
                        post-fix daemon refusing a connection.
Verdicts per gateway (precedence INCIDENT > SUSPICIOUS > BLOCKED_ATTEMPT):
  INCIDENT         any SYSTEM_SINK or EXPLOIT_KEYWORD
  SUSPICIOUS       NON_WRAPPER_RECEIVED only — triage the command; a
                   non-wrapper Received line is a vendor grep target, not
                   proof of execution by itself
  BLOCKED_ATTEMPT  REJECTED_UID only. This is NOT an incident: it is
                   evidence the patched daemon rejected the connection.
                   Confirm the rejection and check whether the same source
                   tried other paths; do not open an incident on it alone.
Benign by design: legitimate Clish wrapper lines never match. A lone
NON_WRAPPER_RECEIVED is SUSPICIOUS, not an incident. Lines that are not
dynamicCli records are skipped and counted.

Usage: python3 checkpoint-dynamiccli-detect.py <dynamicCli.log>
"""
import re
import sys

LINE = re.compile(r"^(\S+)\s+(\S+)\s+dynamicCli\[\d+\]:\s+(.*)$")
EXPLOIT_KEYWORDS = re.compile(
    r"id;|whoami|/etc/shadow|\bncat\b|nc\s+-|/dev/tcp|\bcurl\b|\bwget\b|"
    r"base64|useradd|authorized_keys",
    re.I,
)
REJECTED = "Rejected connection from unauthorized uid"


def analyze(path, stats=None):
    """Return {gateway: {"verdict": str, "hits": [(lineno, ts, kind, detail)]}}.

    If *stats* is a dict it receives counters: lines, skipped_malformed.
    """
    hits = {}  # gateway -> list of (lineno, ts, kind, detail)
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stats["lines"] += 1
            m = LINE.match(line.rstrip("\n"))
            if not m:
                stats["skipped_malformed"] += 1
                continue
            ts_text, host, msg = m.group(1), m.group(2), m.group(3)
            kinds = []
            if REJECTED in msg:
                kinds.append(("REJECTED_UID", "post-fix daemon rejected the connection"))
            else:
                if "#return_value#" in msg:
                    kinds.append(("SYSTEM_SINK", "daemon returned command output"))
                elif "Received" in msg and "wrapper" not in msg:
                    kinds.append(("NON_WRAPPER_RECEIVED", f"non-wrapper Received: {msg[:80]}"))
                if EXPLOIT_KEYWORDS.search(msg):
                    kinds.append(("EXPLOIT_KEYWORD", f"vendor keyword in: {msg[:80]}"))
            for kind, detail in kinds:
                hits.setdefault(host, []).append((n, ts_text, kind, detail))
    result = {}
    for host, hs in hits.items():
        kinds = {h[2] for h in hs}
        if "SYSTEM_SINK" in kinds or "EXPLOIT_KEYWORD" in kinds:
            verdict = "INCIDENT"
        elif "NON_WRAPPER_RECEIVED" in kinds:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BLOCKED_ATTEMPT"
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

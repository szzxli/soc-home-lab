#!/usr/bin/env python3
"""Flow-audit detector for a Node-RED missing-adminAuth lab (CVE-2026-58115).

Detection only. Reads a flows export plus an optional combined access log and
reports defensive signals:

  EXEC_NODE       a node whose type is exec
  HTTP_IN_EXEC    an http-in node with a downstream exec node
  UNEXPECTED      a node id missing from the baseline, or whose stable
                  fields (type, wiring, command, url, method, name) changed
  REMOVED         a baseline node id absent from the current export
  TMP_WRITE       an exec command that writes under /tmp or /dev/shm
  POST_FLOWS      an access-log request of POST to a path ending in /flows

Verdicts for each source IP that POSTed /flows (the flows file is the
point-in-time host snapshot, not proof of which request body landed):

  INCIDENT    2xx POST /flows and the export has exec, http-in->exec, or a
              /tmp or /dev/shm exec command
  SUSPICIOUS  2xx POST /flows and the export has none of those
  RECON       POST /flows and every one of them is non-2xx

Usage:
  python3 flows-audit.py --flows flows.json [--baseline baseline.json]
                         [--access access.log]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

LOG = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ')
# /tmp and /dev/shm as directories. /tmpfile and /temporary do not match.
TMP_PATH = re.compile(r"(?:/tmp|/dev/shm)(?:/|[\s;|&<>'\"`]|$)")
SIG_KEYS = ("type", "z", "name", "command", "addpay", "append", "useSpawn", "url", "method", "wires")


def load_flows(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("flows"), list):
        return data["flows"]
    raise ValueError(f"{path}: expected a flow array or an object with 'flows'")


def _wire_targets(node: dict) -> list:
    out = []
    wires = node.get("wires") or []
    if not isinstance(wires, list):
        return out
    for port in wires:
        if isinstance(port, list):
            out.extend(str(x) for x in port)
        elif isinstance(port, str):
            out.append(port)
    return out


def downstream_ids(start: str, by_id: dict) -> set:
    seen = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        node = by_id.get(cur)
        if not node:
            continue
        stack.extend(_wire_targets(node))
    seen.discard(start)
    return seen


def signature(node: dict) -> str:
    sig = {k: node.get(k) for k in SIG_KEYS if k in node}
    sig["type"] = node.get("type")
    return json.dumps(sig, sort_keys=True, default=str)


def path_is_flows(uri: str) -> bool:
    path = uri.split("?", 1)[0]
    if len(path) > 1:
        path = path.rstrip("/")
    return path == "/flows" or path.endswith("/flows")


def tmp_hits(command: str) -> list:
    found = []
    for match in TMP_PATH.finditer(command or ""):
        text = match.group(0)
        if text.startswith("/dev/shm") and "/dev/shm" not in found:
            found.append("/dev/shm")
        elif text.startswith("/tmp") and "/tmp" not in found:
            found.append("/tmp")
    return found


def _index(nodes: list) -> dict:
    return {n.get("id"): n for n in nodes if isinstance(n, dict) and n.get("id")}


def analyze(flows_path, access_log=None, baseline_path=None, stats=None):
    """Return flow findings plus per-IP access verdicts.

    If *stats* is a dict it receives access-log counters: lines, skipped_malformed.
    """
    nodes = load_flows(Path(flows_path))
    by_id = _index(nodes)
    baseline = _index(load_flows(Path(baseline_path))) if baseline_path else {}

    exec_nodes = []
    tmp_writes = []
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") != "exec":
            continue
        command = node.get("command") or ""
        exec_nodes.append({
            "id": node.get("id"),
            "name": node.get("name") or "",
            "z": node.get("z") or "",
            "command": command,
        })
        paths = tmp_hits(command)
        if paths:
            tmp_writes.append({"id": node.get("id"), "command": command, "paths": paths})

    http_in_to_exec = []
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") != "http in":
            continue
        reached = [
            nid for nid in sorted(downstream_ids(node.get("id"), by_id))
            if by_id.get(nid, {}).get("type") == "exec"
        ]
        if reached:
            http_in_to_exec.append({
                "id": node.get("id"),
                "name": node.get("name") or "",
                "method": node.get("method") or "",
                "url": node.get("url") or "",
                "exec_ids": reached,
            })

    unexpected = []
    if baseline_path:
        for node in nodes:
            if not isinstance(node, dict) or not node.get("id"):
                continue
            prev = baseline.get(node["id"])
            if prev is None:
                unexpected.append({
                    "id": node["id"], "type": node.get("type"),
                    "name": node.get("name") or "", "reason": "new",
                })
            elif signature(prev) != signature(node):
                unexpected.append({
                    "id": node["id"], "type": node.get("type"),
                    "name": node.get("name") or "", "reason": "changed",
                })
    removed = []
    if baseline_path:
        current_ids = set(by_id)
        for nid, prev in baseline.items():
            if nid not in current_ids:
                removed.append({
                    "id": nid, "type": prev.get("type"),
                    "name": prev.get("name") or "",
                })

    hostile = bool(exec_nodes or http_in_to_exec or tmp_writes)
    access = {}
    stats = stats if stats is not None else {}
    stats.update(lines=0, skipped_malformed=0)
    if access_log:
        with open(access_log, errors="replace", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                stats["lines"] += 1
                m = LOG.match(line)
                if not m:
                    stats["skipped_malformed"] += 1
                    continue
                ip, ts, method, uri, status = m.groups()
                if method.upper() != "POST" or not path_is_flows(uri):
                    continue
                access.setdefault(ip, []).append((n, ts, "POST_FLOWS", status, uri))

    result_access = {}
    for ip, hits in access.items():
        ok = [h for h in hits if h[3].startswith("2")]
        if ok and hostile:
            verdict = "INCIDENT"
        elif ok:
            verdict = "SUSPICIOUS"
        else:
            verdict = "RECON"
        result_access[ip] = {"verdict": verdict, "hits": hits}

    return {
        "exec_nodes": exec_nodes,
        "http_in_to_exec": http_in_to_exec,
        "unexpected": unexpected,
        "removed": removed,
        "tmp_writes": tmp_writes,
        "access": result_access,
        "stats": stats,
    }


def _render(res: dict) -> str:
    lines = []
    lines.append(
        "[FLOWS] exec_nodes={e} http_in_to_exec={h} unexpected={u} removed={r} tmp_writes={t}".format(
            e=len(res["exec_nodes"]),
            h=len(res["http_in_to_exec"]),
            u=len(res["unexpected"]),
            r=len(res["removed"]),
            t=len(res["tmp_writes"]),
        )
    )
    for node in res["exec_nodes"]:
        lines.append(f"  EXEC_NODE {node['id']} {node['name']}: {node['command']}")
    for node in res["http_in_to_exec"]:
        lines.append(
            f"  HTTP_IN_EXEC {node['id']} {node['method']} {node['url']} -> {','.join(node['exec_ids'])}"
        )
    for node in res["unexpected"]:
        lines.append(f"  UNEXPECTED {node['reason']} {node['id']} {node['type']} {node['name']}")
    for node in res["removed"]:
        lines.append(f"  REMOVED {node['id']} {node['type']} {node['name']}")
    for node in res["tmp_writes"]:
        lines.append(f"  TMP_WRITE {node['id']} {' '.join(node['paths'])}: {node['command']}")
    if not res["access"] and not any(
        res[k] for k in ("exec_nodes", "http_in_to_exec", "unexpected", "removed", "tmp_writes")
    ):
        return "no findings"
    for ip, row in sorted(res["access"].items()):
        lines.append(f"[{row['verdict']}] {ip} ({len(row['hits'])} hits):")
        for n, ts, kind, status, uri in row["hits"]:
            lines.append(f"  L{n} {ts} {kind:<12} {status} {uri[:120]}")
    if res["stats"].get("skipped_malformed"):
        lines.append(f"note: {res['stats']['skipped_malformed']} malformed line(s) skipped")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--flows", required=True, help="flows.json export (array or {flows: [...]})")
    ap.add_argument("--baseline", help="known-good flows export; enables UNEXPECTED and REMOVED")
    ap.add_argument("--access", help="combined access log covering the admin API")
    args = ap.parse_args(argv)
    try:
        res = analyze(args.flows, args.access, args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(_render(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

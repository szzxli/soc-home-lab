#!/usr/bin/env python3
"""Packet hunt: parse a pcap from scratch (stdlib only) and flag four
behaviours in it.

Detection practice only — no exploit code, no real traffic. The two
sample pcaps in samples/ are synthetic; regenerate them with
generate_pcap.py. This parser is a teaching tool, not a replacement for
tshark or Suricata: it handles Ethernet + IPv4 + TCP/UDP, it does not
verify checksums (the generator zeroes them), and it does not reassemble
TCP streams — each packet is judged on its own, plus the two grouped
checks below (SYN scan, beacon).

Detectors:
  SYN_SCAN         one source sends SYN-only packets to >= 10 distinct
                   destination ports (a port scan; a normal client opens
                   one or two)
  DNS_EXFIL        a DNS query whose label is >= 40 chars or whose full
                   name is >= 63 chars (exfil-shaped; normal names are
                   short — www.example.com is 15)
  SUSPICIOUS_HTTP  an HTTP request from a scripting user agent (curl,
                   wget, python-*, Go-http-client) or for a sensitive
                   path (/admin/, /etc/passwd, cmd=). A browser fetching
                   a page never matches.
  BEACON           >= 5 small (1-100 byte) PSH packets on one
                   src -> dst:port flow at near-regular intervals (every
                   gap within half to twice the median gap, median gap
                   5-300 s). Humans do not click that regularly.

Each finding names the packet number (1-based, in file order) so you can
open the same packet in Wireshark and see it yourself.

Usage: python3 hunt_pcap.py samples/malicious.pcap
"""
import struct
import sys
from collections import defaultdict
from statistics import median

SYN_SCAN_MIN_PORTS = 10
DNS_LABEL_MAX = 40
DNS_NAME_MAX = 63
BEACON_MIN_PACKETS = 5
BEACON_MIN_GAP = 5
BEACON_MAX_GAP = 300
SCRIPTED_UA = ("curl", "wget", "python", "go-http-client")
SENSITIVE_PATH = ("/admin/", "/etc/passwd", "cmd=", ".php?cmd")


def _read_pcap(path):
    """Return (endian, linktype, [(ts, frame), ...]). Raises on bad magic."""
    data = open(path, "rb").read()
    if len(data) < 24:
        raise ValueError("file too short for a pcap global header")
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    else:
        raise ValueError(f"not a pcap file (magic {magic.hex()})")
    _ver_major, _ver_minor, _tz, _sig, snaplen, linktype = struct.unpack(
        endian + "HHiiii", data[4:24])
    packets = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            break  # truncated final packet: stop, do not crash
        packets.append((ts_sec + ts_usec / 1e6, data[off:off + incl]))
        off += incl
    return endian, linktype, packets


def _parse_ipv4(frame):
    """Return (src, dst, proto, payload) for an Ethernet/IPv4 frame, or None."""
    if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    return src, dst, ip[9], ip[ihl:]


def _parse_tcp(segment):
    """Return (sport, dport, flags, payload) or None."""
    if len(segment) < 20:
        return None
    sport, dport, _seq, _ack, off_flags = struct.unpack("!HHIIH", segment[:14])
    flags = off_flags & 0x01FF
    doff = ((off_flags >> 12) & 0xF) * 4
    if len(segment) < doff:
        return None
    return sport, dport, flags, segment[doff:]


def _parse_udp(segment):
    """Return (sport, dport, payload) or None."""
    if len(segment) < 8:
        return None
    sport, dport, length, _chk = struct.unpack("!HHHH", segment[:8])
    return sport, dport, segment[8:8 + max(0, length - 8)]


def _parse_dns_name(payload, off=12):
    """Return the query name in a DNS request payload, or None."""
    labels = []
    while off < len(payload):
        n = payload[off]
        if n == 0:
            return ".".join(labels) if labels else None
        if n & 0xC0:  # compression pointer: not in a query, bail out
            return None
        off += 1
        if off + n > len(payload):
            return None
        labels.append(payload[off:off + n].decode("ascii", "replace"))
        off += n
    return None


def _parse_http(payload):
    """Return (method, path, user_agent) for an HTTP request, or None."""
    try:
        text = payload.decode("latin-1")
    except UnicodeDecodeError:
        return None
    head, _, _ = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or " " not in lines[0]:
        return None
    method, path = lines[0].split(" ", 2)[:2]
    if method not in ("GET", "POST", "HEAD", "PUT", "DELETE"):
        return None
    ua = ""
    for line in lines[1:]:
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
    return method, path, ua


def analyze(path):
    """Return a list of findings: dicts with packet, detector, src, detail."""
    _endian, linktype, packets = _read_pcap(path)
    findings = []
    syn_ports = defaultdict(set)       # src -> {dst ports}
    syn_first = {}                     # src -> first packet number
    beacon_flows = defaultdict(list)   # (src, dst, dport) -> [(ts, pkt_no)]
    for n, (ts, frame) in enumerate(packets, 1):
        if linktype != 1:
            continue
        parsed = _parse_ipv4(frame)
        if parsed is None:
            continue
        src, dst, proto, segment = parsed
        if proto == 6:  # TCP
            tcp = _parse_tcp(segment)
            if tcp is None:
                continue
            sport, dport, flags, payload = tcp
            if flags & 0x02 and not flags & 0x10:  # SYN, no ACK
                syn_ports[src].add(dport)
                syn_first.setdefault(src, n)
            if flags & 0x08 and 1 <= len(payload) <= 100:  # PSH, small
                beacon_flows[(src, dst, dport)].append((ts, n))
            http = _parse_http(payload) if payload else None
            if http:
                _method, req_path, ua = http
                reasons = []
                if any(tok in ua.lower() for tok in SCRIPTED_UA):
                    reasons.append(f"scripting user agent {ua!r}")
                if any(tok in req_path for tok in SENSITIVE_PATH):
                    reasons.append(f"sensitive path {req_path!r}")
                if reasons:
                    findings.append({"packet": n, "detector": "SUSPICIOUS_HTTP",
                                     "src": src, "detail": "; ".join(reasons)})
        elif proto == 17:  # UDP
            udp = _parse_udp(segment)
            if udp is None:
                continue
            _sport, dport, payload = udp
            if dport == 53:
                name = _parse_dns_name(payload)
                if name:
                    long_label = max((len(part) for part in name.split(".")), default=0)
                    if long_label >= DNS_LABEL_MAX or len(name) >= DNS_NAME_MAX:
                        findings.append({"packet": n, "detector": "DNS_EXFIL",
                                         "src": src,
                                         "detail": f"long DNS query name {name!r}"})
    for src, ports in syn_ports.items():
        if len(ports) >= SYN_SCAN_MIN_PORTS:
            findings.append({"packet": syn_first[src], "detector": "SYN_SCAN",
                             "src": src,
                             "detail": f"{len(ports)} distinct ports SYN-scanned"})
    for (src, dst, dport), hits in beacon_flows.items():
        if len(hits) < BEACON_MIN_PACKETS:
            continue
        times = [t for t, _ in hits]
        gaps = [b - a for a, b in zip(times, times[1:])]
        med = median(gaps)
        if not (BEACON_MIN_GAP <= med <= BEACON_MAX_GAP):
            continue
        if all(med / 2 <= g <= med * 2 for g in gaps):
            findings.append({"packet": hits[0][1], "detector": "BEACON",
                             "src": src,
                             "detail": f"{len(hits)} small PSH packets to "
                                       f"{dst}:{dport} every ~{med:.0f}s"})
    findings.sort(key=lambda f: f["packet"])
    return findings


def main(path):
    try:
        findings = analyze(path)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}")
        return 2
    if not findings:
        print("no findings")
        return 0
    for f in findings:
        print(f"[{f['detector']}] packet {f['packet']} src {f['src']}: {f['detail']}")
    print(f"{len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin"))

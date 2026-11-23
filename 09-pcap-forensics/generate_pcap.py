#!/usr/bin/env python3
"""Generate the two synthetic pcaps for the 09-pcap-forensics lab.

Stdlib only. Everything is deterministic: fixed timestamps, fixed
addresses (documentation ranges, RFC 5737), fixed payloads, no random
input. Re-run to regenerate both files byte-for-byte.

    python3 generate_pcap.py            # writes samples/*.pcap

Capture notes (this is a parser-training capture, not a wire capture):
- IP/TCP/UDP checksums are zeroed. Real stacks fill them in; the hunt
  script in this lab does not verify checksums, and neither should a
  training parser.
- Domains use the reserved .example TLD. Nothing here resolves, and
  nothing here is a real indicator.
- The "malicious" pcap contains four behaviours the hunt script looks
  for: a SYN scan, long-label DNS queries, a scripted-UA HTTP request,
  and a regular-interval beacon. The "benign" pcap contains the same
  protocols doing ordinary things.

Usage: python3 generate_pcap.py [--out DIR]
"""
import argparse
import socket
import struct
from pathlib import Path

BASE = 1795450000  # fixed epoch base: 2026-11-23T00:00:00Z-ish, deterministic

# Documentation-range addresses only (RFC 5737).
ATTACKER = "203.0.113.60"
VICTIM = "192.0.2.10"
INSIDE = "192.0.2.50"
WORKSTATION = "192.0.2.20"
WEB = "198.51.100.5"

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"


def _ip(addr):
    return socket.inet_aton(addr)


def _tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    offset = 5 << 12
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset | flags,
                         65535, 0, 0)
    return _ipv4(src, dst, 6, header + payload)


def _udp(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    return _ipv4(src, dst, 17, header + payload)


def _ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64,
                         proto, 0, _ip(src), _ip(dst))
    return DST_MAC + SRC_MAC + struct.pack("!H", 0x0800) + header + payload


def _dns_query(name, qid=0x1234):
    labels = b"".join(bytes([len(part)]) + part.encode()
                      for part in name.split("."))
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)


def _http_get(path, host, ua):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()


def _write_pcap(path, packets):
    """packets: list of (timestamp_seconds, frame_bytes)."""
    out = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in packets:
        out += struct.pack("!IIII", int(ts), 0, len(frame), len(frame)) + frame
    Path(path).write_bytes(out)
    return len(packets)


def build_malicious():
    """Four hunt behaviours + ordinary background traffic."""
    pkts = []
    t = BASE
    # Background: a normal DNS lookup and a normal HTTP fetch.
    pkts.append((t, _udp(WORKSTATION, WEB, 53000, 53,
                         _dns_query("www.example.com"))))
    t += 1
    pkts.append((t, _tcp(WORKSTATION, WEB, 40000, 80, 1000, 0, 0x02)))
    pkts.append((t + 1, _tcp(WEB, WORKSTATION, 80, 40000, 5000, 1001, 0x12)))
    pkts.append((t + 2, _tcp(WORKSTATION, WEB, 40000, 80, 1001, 5001, 0x10,
                             _http_get("/index.html", "www.example.com",
                                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))))
    # Behaviour 1: SYN scan — 12 SYNs, 12 distinct ports, no handshake.
    scan_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443, 5900, 6379]
    for i, port in enumerate(scan_ports):
        pkts.append((BASE + 100 + i, _tcp(ATTACKER, VICTIM, 51000 + i, port,
                                          2000 + i, 0, 0x02)))
    # Behaviour 2: long-label DNS queries (exfil-shaped), 3 of them.
    for i in range(3):
        label = "a" * 40 + str(i)
        pkts.append((BASE + 200 + i * 2,
                     _udp(INSIDE, WEB, 53100 + i, 53,
                          _dns_query(f"{label}.exfil-test.example"))))
    # Behaviour 3: scripted-UA HTTP request for a config file.
    pkts.append((BASE + 300, _tcp(ATTACKER, VICTIM, 52000, 80, 3000, 0, 0x02)))
    pkts.append((BASE + 301, _tcp(VICTIM, ATTACKER, 80, 52000, 6000, 3001, 0x12)))
    pkts.append((BASE + 302, _tcp(ATTACKER, VICTIM, 52000, 80, 3001, 6001, 0x10,
                                  _http_get("/admin/config.zip", "192.0.2.10",
                                            "curl/8.0.1"))))
    # Behaviour 4: beacon — 6 small PSH packets, exactly 30 s apart.
    for i in range(6):
        pkts.append((BASE + 400 + i * 30,
                     _tcp(INSIDE, ATTACKER, 53000, 4444, 4000 + i, 7000,
                          0x18, f"BEACON-{i:04d}".encode())))
    # More background: a second normal DNS lookup.
    pkts.append((BASE + 600, _udp(WORKSTATION, WEB, 53001, 53,
                                  _dns_query("mail.example.com"))))
    pkts.sort(key=lambda p: p[0])
    return pkts


def build_benign():
    """The same protocols doing ordinary things — nothing should fire."""
    pkts = []
    t = BASE
    pkts.append((t, _udp(WORKSTATION, WEB, 53000, 53,
                         _dns_query("www.example.com"))))
    pkts.append((t + 1, _tcp(WORKSTATION, WEB, 40000, 80, 1000, 0, 0x02)))
    pkts.append((t + 2, _tcp(WEB, WORKSTATION, 80, 40000, 5000, 1001, 0x12)))
    pkts.append((t + 3, _tcp(WORKSTATION, WEB, 40000, 80, 1001, 5001, 0x10,
                             _http_get("/index.html", "www.example.com",
                                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))))
    pkts.append((t + 4, _tcp(WORKSTATION, WEB, 40000, 80, 1100, 5100, 0x18,
                             _http_get("/about.html", "www.example.com",
                                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))))
    # One more host, one more ordinary fetch — still only 2 SYNs per source.
    pkts.append((t + 10, _udp(INSIDE, WEB, 53100, 53,
                              _dns_query("mail.example.com"))))
    pkts.append((t + 11, _tcp(INSIDE, WEB, 41000, 443, 2000, 0, 0x02)))
    pkts.append((t + 12, _tcp(WEB, INSIDE, 443, 41000, 8000, 2001, 0x12)))
    pkts.append((t + 13, _tcp(INSIDE, WEB, 41000, 443, 2001, 8001, 0x10,
                              b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03")))
    pkts.sort(key=lambda p: p[0])
    return pkts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "samples"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    n1 = _write_pcap(out / "malicious.pcap", build_malicious())
    n2 = _write_pcap(out / "benign.pcap", build_benign())
    print(f"wrote {out / 'malicious.pcap'} ({n1} packets)")
    print(f"wrote {out / 'benign.pcap'} ({n2} packets)")


if __name__ == "__main__":
    main()

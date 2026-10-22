#!/usr/bin/env python3
"""Generate the NOISY synthetic sample logs for the three in-repo 07 detectors.

The clean samples in ../ are short and tidy: every line is either obviously
benign or obviously bad. Real logs are not. These variants add:
  * volume       thousands of routine lines (health checks, sync clients, crons)
  * look-alikes  benign activity that trips the reference detectors on purpose
                 (soft-404 WAF pages, '::' in page titles, package-managed SUID
                 binaries, reboots that reset sequence numbers, rotated service
                 accounts, ticket typos, document titles containing '$(' ...)
  * missing data truncated lines, '-' requests, missing fields, bad timestamps

Everything is SYNTHETIC and deterministic (fixed seed), so the expected TP/FP
numbers in ../../../NOISY_DATA.md stay reproducible. Attacker addresses come
only from documentation ranges (RFC 5737 / RFC 3849); everything else is
private (RFC 1918). No working payloads: request strings are reduced to the
indicators a defender keys on.

Usage: python3 generate_noisy.py [outdir]   (default: this directory)
The answer key for each log is written to truth.json.
"""
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

SEED = 20261021
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent

UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6)"
UA_LNX = "Mozilla/5.0 (X11; Linux x86_64)"


def clf(ip, user, ts, method, path, status, size, ua, ref="-"):
    return (f'{ip} - {user} [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} {size} "{ref}" "{ua}"')


def finish(events, header):
    """Sort (ts, line) events by time, keep the original order for ties."""
    events.sort(key=lambda e: e[0])
    return "\n".join(header + [line for _, line in events]) + "\n"


# --------------------------------------------------------------------- confluence
def confluence(rng):
    day = datetime(2026, 10, 16)
    ev = []
    users = [(f"10.0.{rng.randint(1, 3)}.{i}", f"user{i:02d}", rng.choice([UA_WIN, UA_MAC, UA_LNX]))
             for i in range(10, 50)]
    users += [(f"[2001:db8::{i:x}]", f"v6user{i}", UA_LNX) for i in range(1, 5)]
    spaces = ["TEAM", "OPS", "DEV", "HR", "SEC", "ENG", "PM"]
    pages = ["Home", "Runbooks", "Oncall", "Sprint+42", "Retro", "Onboarding", "Architecture",
             "Release+Notes", "Postmortem+2026-10-02", "Roadmap+Q4"]
    # routine browsing / API / static resources, 08:00-19:00
    for _ in range(1900):
        ip, user, ua = rng.choice(users)
        ts = day + timedelta(hours=8, seconds=rng.randint(0, 11 * 3600))
        r = rng.random()
        if r < 0.45:
            path, size = f"/confluence/display/{rng.choice(spaces)}/{rng.choice(pages)}", rng.randint(9000, 60000)
        elif r < 0.65:
            path, size = f"/confluence/rest/api/content?spaceKey={rng.choice(spaces)}&limit=25", rng.randint(2000, 9000)
        elif r < 0.85:
            path = f"/confluence/s/{rng.getrandbits(32):08x}/9120/_/download/batch/confluence.web.resources:view-content/view-content.js"
            size = rng.randint(30000, 90000)
        elif r < 0.95:
            path, size = f"/confluence/pages/viewpage.action?pageId={rng.randint(800000, 900000)}", rng.randint(9000, 40000)
        else:  # C++ / Rust developers searching for '::' — in the QUERY STRING (benign by design)
            q = rng.choice(["std::vector", "std::map", "tokio::spawn", "Foo::Bar", "boost::asio"])
            path, size = f"/confluence/dosearchsite.action?queryString={q}", rng.randint(4000, 12000)
        status = 200 if rng.random() > 0.03 else rng.choice([304, 404])
        ev.append((ts, clf(ip, user, ts, "GET", path, status, size, ua)))
    # kubernetes liveness probe every 2 minutes, all day
    for m in range(0, 24 * 60, 2):
        ts = day + timedelta(minutes=m, seconds=7)
        ev.append((ts, clf("10.0.0.7", "-", ts, "GET", "/confluence/status", 200, 21, "kube-probe/1.30")))
    # LOOK-ALIKE 1: page titles that contain '::' in the PATH (benign Rust/C++ docs space)
    for i, title in enumerate(["Rust+Traits+::+Cheatsheet", "C%2B%2B+std::chrono+notes", "Namespace::Conventions"]):
        ts = day + timedelta(hours=10 + i, minutes=13)
        ev.append((ts, clf("10.0.2.31", "dev_mia", ts, "GET", f"/confluence/display/DEV/{title}", 200, 15500, UA_LNX)))
    # approved scanner (allowlisted in the detector), weekly window 12:00-12:30
    for i, p in enumerate(["/confluence/download/::WEB-INF/web.xml", "/confluence/login.action",
                           "/confluence/download/::conf/server.xml", "/confluence/rest/api/space"]):
        ts = day + timedelta(hours=12, minutes=4, seconds=i)
        ev.append((ts, clf("10.0.5.8", "-", ts, "GET", p, 404 if "::" in p else 200, 231, "Nessus SOAP")))
    # LOOK-ALIKE 2: a NEW internal scanner node, not yet on the allowlist. The WAF in
    # front of Confluence answers blocked requests with a 200 "Request blocked" page
    # (a soft 404), so status codes alone look like successful sensitive reads.
    for i, p in enumerate(["/confluence/download/::WEB-INF/web.xml", "/confluence/download/::META-INF/MANIFEST.MF",
                           "/confluence/plugins/servlet/::..::/conf/server.xml", "/confluence/::::/etc/hostname"]):
        ts = day + timedelta(hours=12, minutes=6, seconds=i)
        ev.append((ts, clf("10.0.5.9", "-", ts, "GET", p, 200, 1204, "Nessus SOAP")))
    # MALICIOUS 1: recon-only prober (all 404)
    for i, p in enumerate(["/confluence/::::/etc/hostname", "/confluence/plugins/servlet/::..::/conf/server.xml",
                           "/confluence/download/::META-INF/MANIFEST.MF"]):
        ts = day + timedelta(hours=10, minutes=2, seconds=i)
        ev.append((ts, clf("198.51.100.7", "-", ts, "GET", p, 404, 231, "Mozilla/5.0 zgrab/0.x")))
    # MALICIOUS 2: 404 path-guessing burst, then a 200 on a sensitive file
    for i, (p, st, sz) in enumerate([("::WEB-INF/classes/confluence-init.properties.bak", 404, 231),
                                     ("::conf/web.xml", 404, 231), ("::WEB-INF/web.xml.old", 404, 231),
                                     ("::WEB-INF/web.xml", 200, 9812), ("::META-INF/MANIFEST.MF", 200, 402)]):
        ts = day + timedelta(hours=14, minutes=12, seconds=i)
        ev.append((ts, clf("203.0.113.9", "-", ts, "GET", "/confluence/download/" + p, st, sz, "python-requests/2.31")))
    # MALICIOUS 3: same attack, '::' percent-encoded as %3A%3A to dodge naive grep
    for i, (p, st, sz) in enumerate([("%3A%3AWEB-INF/web.xml.bak", 404, 231), ("%3A%3AWEB-INF/web.xml", 200, 9812)]):
        ts = day + timedelta(hours=21, minutes=40, seconds=i * 3)
        ev.append((ts, clf("192.0.2.77", "-", ts, "GET", "/confluence/download/" + p, st, sz, "Go-http-client/1.1")))
    # MISSING / MALFORMED: '-' request (client timeout), truncated line, empty UA, blank line
    for h in (3, 9, 15):
        ts = day + timedelta(hours=h, minutes=1)
        ev.append((ts, f'10.0.3.77 - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "-" 408 0 "-" "-"'))
    ts = day + timedelta(hours=11, minutes=59)
    ev.append((ts, f'10.0.1.12 - user12 [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET /confluence/display/TE'))
    ts = day + timedelta(hours=16, minutes=20)
    ev.append((ts, clf("10.0.1.14", "user14", ts, "GET", "/confluence/display/OPS/Home", 200, 18000, "")))
    ev.append((day + timedelta(hours=17), ""))
    header = [
        "# SYNTHETIC training log (NOISY variant) — Atlassian Confluence Data Center access log (CVE-2026-21589 lab).",
        "# ALL DATA SYNTHETIC: generated by generate_noisy.py (seed 20261021); no real attacker data.",
        "# Attacker addresses are from documentation ranges (RFC 5737 / RFC 3849) only.",
        "# Contains ~2,700 routine lines, benign look-alikes that trip the reference detector,",
        "# and missing / malformed lines. The answer key is in truth.json — look only after you hunt.",
    ]
    truth = {"entity": "source IP", "malicious": ["198.51.100.7", "203.0.113.9", "192.0.2.77"],
             "expected_incident": ["203.0.113.9", "192.0.2.77"],
             "look_alikes": {"10.0.2.31": "'::' inside Confluence page titles (path, not query)",
                             "10.0.5.9": "new internal scanner, not allowlisted; WAF returns 200 block pages (1,204 bytes)"}}
    return finish(ev, header), truth


# ---------------------------------------------------------------------- appliance
def appliance(rng):
    start = datetime(2026, 10, 12)
    hosts = [f"bt-rs-0{i}" for i in range(1, 7)]
    seq = {h: 1000 * (i + 1) for i, h in enumerate(hosts)}
    ev = []

    def add(ts, host, rest, seq_field=True, ts_text=None):
        s = f" seq={seq[host]}" if seq_field else ""
        if seq_field:
            seq[host] += 1
        ev.append((ts, f"{ts_text or ts.strftime('%Y-%m-%dT%H:%M:%SZ')} host={host}{s} {rest}"))

    # Build per host in time order so sequence numbers stay monotonic.
    plan = {h: [] for h in hosts}
    for h in hosts:
        for hour in range(72):
            base = start + timedelta(hours=hour)
            if hour % 6 == 1:
                plan[h].append((base, "src=cron event=haproxy_reload cfg_changed=no"))
            plan[h].append((base + timedelta(minutes=15, seconds=12),
                            f"src=appliance event=vault_read account=svc_vault_sync item=jump-cred-{rng.randint(1, 999):04d}"))
            if hour % 24 == 3:
                plan[h].append((base, "src=logrotate event=rotate file=/var/log/bt/appliance.log kept=14"))
            busy = 8 <= hour % 24 <= 18
            if True:
                for _ in range(rng.randint(6, 12) if busy else rng.randint(0, 2)):
                    t = base + timedelta(seconds=rng.randint(0, 3599))
                    c = f"10.20.{rng.randint(0, 3)}.{rng.randint(10, 250)}"
                    r = rng.random()
                    if r < 0.5:
                        plan[h].append((t, f"src=httpd event=request client={c} method=GET path=/login status=200 bytes=6120"))
                    elif r < 0.8:
                        plan[h].append((t, f"src=appliance event=session_start account=helpdesk_{rng.choice(['ana', 'bo', 'cy', 'di'])} "
                                           f"jumpitem=JI-{rng.randint(1000, 9999)} client={c}"))
                    else:
                        plan[h].append((t, f"src=httpd event=request client={c} method=GET path=/appliance/status status=200 bytes=812"))
    # bt-rs-01 LOOK-ALIKE: legit admin role change whose ticket reference has a typo (CHG4471, no dash)
    plan["bt-rs-01"] += [
        (start + timedelta(days=1, hours=6), "src=fim event=modify path=/etc/haproxy/haproxy.cfg owner=root ticket=CHG-4471"),
        (start + timedelta(days=1, hours=6, minutes=5), "src=appliance event=role_change account=ops_lee jumpitem=JI-0412 "
                                                        "old_role=Operator new_role=Administrator by=admin_kim ticket=CHG4471")]
    # bt-rs-02 MISSING FIELDS: vault read with no account field (forwarder dropped it)
    plan["bt-rs-02"] += [(start + timedelta(days=1, hours=9, minutes=41), "src=appliance event=vault_read item=jump-cred-0977 client=10.20.0.44")]
    # bt-rs-03 MALICIOUS: the full ARMORY CASTLE chain, then records deleted
    t0 = start + timedelta(days=1, hours=3, minutes=41)
    chain = [(0, "src=httpd event=request client=198.51.100.23 method=GET path=/appliance/api/info status=200 bytes=402"),
             (72, "src=fim event=create path=/var/www/html/appliance/api/status_check.php owner=www-data size=1840 ticket=-"),
             (108, "src=httpd event=request client=198.51.100.23 method=POST path=/appliance/api/status_check.php status=200 bytes=96"),
             (383, "src=auditd event=setuid_set path=/var/tmp/.cache/dbus-helper owner=root mode=4755 pkg=none"),
             (655, "src=appliance event=vault_export account=www-data item=ALL client=127.0.0.1"),
             (1208, "src=fim event=modify path=/etc/rc.local owner=root ticket=-"),
             (1209, "src=fim event=modify path=/etc/sudoers.d/90-appliance owner=root ticket=-"),
             (1713, "src=fim event=modify path=/etc/haproxy/haproxy.cfg owner=root ticket=-"),
             (1731, "src=net event=listen proto=websocket port=8843 proc=haproxy new=yes"),
             (2484, "src=appliance event=role_change account=helpdesk_tmp jumpitem=JI-0007 old_role=Operator "
                    "new_role=Administrator by=helpdesk_tmp ticket=-")]
    plan["bt-rs-03"] += [(t0 + timedelta(seconds=s), r) for s, r in chain]
    plan["bt-rs-03"] += [(t0 + timedelta(seconds=2490), "SKIP24")]  # 24 records deleted after the role change
    # bt-rs-04 LOOK-ALIKE: dbus package upgrade (package-managed SUID helper outside /usr/bin)
    # followed by the reboot it needs -> the per-host sequence restarts at 1.
    plan["bt-rs-04"] += [(start + timedelta(days=1, hours=2, minutes=10),
                          "src=auditd event=setuid_set path=/usr/lib/dbus-1.0/dbus-daemon-launch-helper owner=root mode=4754 pkg=dbus"),
                         (start + timedelta(days=1, hours=2, minutes=12), "REBOOT")]
    # bt-rs-05 LOOK-ALIKE: vault sync service account rotated to svc_vault_sync2 on day 3
    plan["bt-rs-05"] = [(t, r.replace("account=svc_vault_sync ", "account=svc_vault_sync2 ")
                         if t >= start + timedelta(days=2) else r) for t, r in plan["bt-rs-05"]]
    # bt-rs-06 MALICIOUS (subtle): web shell, then a SOCKS listener 30 hours later
    plan["bt-rs-06"] += [(start + timedelta(hours=9, minutes=3), "src=fim event=create path=/var/www/html/appliance/img/thumb.php5 owner=www-data size=912 ticket=-"),
                         (start + timedelta(hours=39, minutes=17), "src=net event=listen proto=socks5 port=1080 proc=python3 new=yes")]
    for h in hosts:
        for t, rest in sorted(plan[h], key=lambda x: x[0]):
            if rest == "SKIP24":
                seq[h] += 24
                continue
            if rest == "REBOOT":
                seq[h] = 1
                add(t, h, "src=appliance event=boot reason=package_upgrade")
                continue
            add(t, h, rest)
    # MISSING / MALFORMED on bt-rs-02: no seq field, a bad timestamp, a bare timestamp
    t = start + timedelta(days=2, hours=4)
    ev.append((t, f"{t:%Y-%m-%dT%H:%M:%SZ} host=bt-rs-02 src=httpd event=request client=10.20.1.9 method=GET path=/login status=200 bytes=6120"))
    ev.append((t + timedelta(seconds=1), "2026-10-14 04:00:01 host=bt-rs-02 src=cron event=haproxy_reload cfg_changed=no"))
    ev.append((t + timedelta(seconds=2), f"{t:%Y-%m-%dT%H:%M:%SZ}"))
    header = [
        "# SYNTHETIC training log (NOISY variant) — BeyondTrust Remote Support (RS) appliance (CVE-2026-102764 lab).",
        "# ALL DATA SYNTHETIC: generated by generate_noisy.py (seed 20261021); no real attacker data, no implants.",
        "# Attacker addresses are from documentation ranges (RFC 5737) only.",
        "# Format: <ts> host=<host> seq=<per-host sequence> src=<subsystem> event=<event> [key=value ...]",
        "# Six appliances over three days: routine noise, benign look-alikes, missing fields, and",
        "# two compromised hosts. The answer key is in truth.json — look only after you hunt.",
    ]
    truth = {"entity": "host", "malicious": ["bt-rs-03", "bt-rs-06"], "expected_incident": ["bt-rs-03", "bt-rs-06"],
             "look_alikes": {"bt-rs-01": "ticket typo CHG4471 on an approved role change",
                             "bt-rs-02": "vault_read with the account field missing",
                             "bt-rs-04": "package-managed SUID helper (pkg=dbus) + reboot resets seq",
                             "bt-rs-05": "vault sync service account rotated to svc_vault_sync2"},
             "notes": {"bt-rs-06": "web shell and SOCKS listener 30h apart: outside the 24h correlation window"}}
    return finish(ev, header), truth


# ---------------------------------------------------------------------- nextcloud
def nextcloud(rng):
    day = datetime(2026, 10, 18)
    ev = []
    users = [(f"10.0.1.{i}", f"user{i}", rng.choice([UA_WIN, UA_MAC])) for i in range(20, 60)]
    sync = "Mozilla/5.0 (Linux) mirall/3.14.1"
    for _ in range(1800):
        ip, user, ua = rng.choice(users)
        ts = day + timedelta(seconds=rng.randint(6 * 3600, 20 * 3600))
        r = rng.random()
        if r < 0.35:
            ev.append((ts, clf(ip, user, ts, "PROPFIND", f"/remote.php/dav/files/{user}/", 207, rng.randint(900, 9000), sync)))
        elif r < 0.5:
            ev.append((ts, clf(ip, user, ts, "PUT", f"/remote.php/dav/files/{user}/Documents/f{rng.randint(1, 999)}.docx", 201, 0, sync)))
        elif r < 0.7:
            ev.append((ts, clf(ip, user, ts, "GET", "/index.php/apps/files/", 200, rng.randint(30000, 45000), ua)))
        elif r < 0.85:
            ev.append((ts, clf(ip, user, ts, "GET", "/ocs/v2.php/apps/notifications/api/v2/notifications?format=json", 200, 742, ua)))
        else:  # opening a document in the built-in editor goes through proxy.php
            ev.append((ts, clf(ip, user, ts, "GET", "/apps/richdocumentscode/proxy.php?req=/browser/dist/cool.html", 200, 30112, ua)))
    for m in range(0, 24 * 60, 5):  # health check polls proxy.php?status every 5 minutes
        ts = day + timedelta(minutes=m)
        ev.append((ts, clf("10.0.0.9", "-", ts, "GET", "/apps/richdocumentscode/proxy.php?status", 200, 64, "nc-healthcheck/1.0")))
    # LOOK-ALIKE 1: a document title containing "$(" passed through proxy.php (benign user)
    ts = day + timedelta(hours=10, minutes=22)
    ev.append((ts, clf("10.0.1.33", "user33", ts, "GET",
                       "/apps/richdocumentscode/proxy.php?req=/cool/convert-to&title=Budget%20%24%28draft%29%20v2.xlsx",
                       200, 18802, UA_WIN)))
    # LOOK-ALIKE 2: an old desktop client that sends an un-normalized relative path
    for k in range(3):
        ts = day + timedelta(hours=11 + k, minutes=5)
        ev.append((ts, clf("10.0.1.40", "user40", ts, "GET",
                           "/apps/richdocumentscode/proxy.php?req=/browser/dist/../dist/cool.html", 200, 30112, UA_WIN)))
    # LOOK-ALIKE 3: internal vulnerability scanner (all 4xx)
    for i, (p, st) in enumerate([("/apps/richdocumentscode/proxy.php?status=%2e%2e%2f", 403),
                                 ("/apps/richdocumentscode/shx1.php", 404)]):
        ts = day + timedelta(hours=12, minutes=4, seconds=i)
        ev.append((ts, clf("10.0.5.8", "-", ts, "GET", p, st, 221, "Nessus SOAP")))
    # MALICIOUS 1: recon prober (all 4xx)
    for i, (p, st) in enumerate([("/apps/richdocumentscode/proxy.php?status=%2e%2e%2f", 403),
                                 ("/apps/richdocumentscode/proxy.php?status=${IFS}probe", 403),
                                 ("/apps/richdocumentscode/shx1.php", 404)]):
        ts = day + timedelta(hours=8, minutes=40, seconds=i)
        ev.append((ts, clf("198.51.100.44", "-", ts, "GET", p, st, 221, "curl/8.5.0")))
    # MALICIOUS 2: probe accepted (200) then commands to a dropped shell
    for i, (p, sz) in enumerate([("/apps/richdocumentscode/proxy.php?status=%24%28SYNTHETIC-MARKER%29", 64),
                                 ("/apps/richdocumentscode/shx7.php?c=id", 54),
                                 ("/apps/richdocumentscode/shx7.php?c=find%20-name%20*.kdbx", 311),
                                 ("/apps/richdocumentscode/shx7.php?c=cat%20config.php", 2210)]):
        ts = day + timedelta(hours=9, minutes=31, seconds=40 * i)
        ev.append((ts, clf("203.0.113.50", "-", ts, "GET", p, 200, sz, "Go-http-client/1.1")))
    # MALICIOUS 3: a second operator uses the shell from another address (no probe from this IP)
    for i, p in enumerate(["/apps/richdocumentscode/shx7.php?c=uname%20-a", "/apps/richdocumentscode/shx7.php?c=ls%20data"]):
        ts = day + timedelta(hours=22, minutes=10, seconds=30 * i)
        ev.append((ts, clf("192.0.2.150", "-", ts, "GET", p, 200, 120, "curl/8.5.0")))
    # MISSING / MALFORMED
    for h in (2, 13):
        ts = day + timedelta(hours=h, minutes=17)
        ev.append((ts, f'10.0.1.22 - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "-" 400 0 "-" "-"'))
    ts = day + timedelta(hours=15, minutes=2)
    ev.append((ts, f'10.0.1.23 - user23 [{ts:%d/%b/%Y:%H:%M:%S} +0000] "PROPFIND /remote.php/dav/fi'))
    ev.append((ts + timedelta(seconds=1), clf("10.0.1.24", "user24", ts, "GET", "/index.php/apps/files/", 200, 41220, "")))
    header = [
        "# SYNTHETIC training log (NOISY variant) — Nextcloud web server access log (CVE-2026-110447 lab,",
        "# richdocumentscode / Built-in CODE Server). ALL DATA SYNTHETIC: generated by generate_noisy.py",
        "# (seed 20261021); no real attacker data, no working payloads (indicator strings only).",
        "# Attacker addresses are from documentation ranges (RFC 5737) only.",
        "# The answer key is in truth.json — look only after you hunt.",
    ]
    truth = {"entity": "source IP", "malicious": ["198.51.100.44", "203.0.113.50", "192.0.2.150"],
             "expected_incident": ["203.0.113.50", "192.0.2.150"],
             "look_alikes": {"10.0.1.33": "document title containing '$(' passed through proxy.php",
                             "10.0.1.40": "old client sending '../' in a proxy.php req path",
                             "10.0.5.8": "internal vulnerability scanner, all 4xx"}}
    return finish(ev, header), truth


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    truth = {}
    for name, fn in (("confluence-access-noisy.log", confluence), ("appliance-noisy.log", appliance),
                     ("nextcloud-access-noisy.log", nextcloud)):
        text, t = fn(random.Random(SEED))
        (OUT / name).write_text(text, encoding="utf-8")
        truth[name] = t
        print(f"wrote {name}: {text.count(chr(10))} lines")
    (OUT / "truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

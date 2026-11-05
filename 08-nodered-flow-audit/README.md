# 08 — Node-RED misconfiguration and flow-audit lab

**This is not a CISA KEV pack.** CVE-2026-58115 is a missing-authentication
condition on the Node-RED admin API (CWE-306). Siemens published it as
SSA-834709 for SIMATIC IoT2050 devices that ship Node-RED. The lab below
uses the official Node-RED container so you can practice the hunt without
Siemens hardware.

**CISA KEV:** not listed. Re-checked the live CISA KEV JSON on 2026-11-05
(catalog version 2026.11.04, `dateReleased` 2026-11-04T20:00:05.774Z).
`CVE-2026-58115` is absent. VulnCheck's own KEV lists this CVE, according
to VulnCheck's public write-up (they added it after observations on
2026-10-30). That is VulnCheck KEV, not CISA KEV.

**What you practice:** start vanilla Node-RED with `adminAuth` left off,
deploy a benign `inject` → `exec` flow that only runs `id` and `echo` into
files under `/dev/shm` and `/tmp`, then find that misconfiguration with a
flows export, a proxy access log, a Sigma-style rule, and a Suricata-style
rule. No exploit, no download, no listener.

## Safety

1. Node-RED is published as `127.0.0.1:1881:1880`. The proxy uses host
   networking and `lab/nginx.conf` listens on `127.0.0.1:1880` only. Do not
   publish either port on every interface, and do not replace that listen
   line with a bare `listen 1880` (that binds every IPv4 interface). Do not point
   `BASE` at another host. `lab/deploy-benign.sh` exits if `BASE` is not
   loopback.
2. The flow command is fixed. `addpay` is false, so nothing you send is
   appended to the shell command. There is no `http in` node in the
   container flow.
3. Tear the lab down when you are done: `docker compose down`.
4. Samples under `samples/` are synthetic. They use RFC 5737 addresses and
   `example.com`. They are not indicators from a real incident.

## What the advisory actually covers

| Item | Value |
|---|---|
| CVE | CVE-2026-58115 |
| Weakness | CWE-306 Missing Authentication for Critical Function |
| CVSS v3.1 | 10.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| CVSS v4.0 | 10.0 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| Advisory | Siemens ProductCERT SSA-834709 (published 2026-08-11, V1.1 last update 2026-11-04) |
| Affected, per SSA-834709 | SIMATIC IoT2050 Advanced (`6ES7647-0BA00-1YA2`), Basic (`6ES7647-0BA00-0YA2`), M.2 (`6ES7647-0BB00-1YA2`), SM (`6ES7647-0CA00-1AA2`), Industrial OS **< V4.3.4-1**, Node-RED installed |
| Vendor fix | Industrial OS V4.3.4-1 or later, or uninstall Node-RED, or harden Node-RED |
| CISA republication | ICSA-26-237-03 (2026-08-25) republishes the Siemens advisory. It is not a KEV listing |

The condition the advisory names is: the Node-RED HTTP admin interface does
not enforce authentication, so a remote client can deploy nodes that run
operating-system commands. Upstream Node-RED leaves `adminAuth` commented
out unless you turn it on. That is the condition this container reproduces.
It is not a claim that Node-RED 4.1.0 has a separate memory-corruption bug.

Public reporting (VulnCheck, 2026-10-30 and the days after) describes
unauthenticated `POST /flows` deploying an `inject` node wired to an `exec`
node, and later flows that wire `http in` toward `exec` so a second request
can run a command. This pack hunts those shapes. It does not include the
request bodies, download steps, or addresses from that reporting. One
reported source sat in a cloud provider ASN; do not blocklist the ASN.
Samples use `203.0.113.50` and `198.51.100.40` as documentation-range
stand-ins.

Sources: [SSA-834709](https://cert-portal.siemens.com/productcert/html/ssa-834709.html) ·
[NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58115) ·
[CISA ICSA-26-237-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-237-03) ·
[Node-RED securing guide](https://nodered.org/docs/user-guide/runtime/securing-node-red) ·
[VulnCheck write-up](https://www.vulncheck.com/blog/exploitation-targeting-node-red)

## Run the local lab (Linux, Docker)

From this directory:

```bash
mkdir -p lab/runtime
docker compose up -d
./lab/assert-admin-auth-off.sh
./lab/deploy-benign.sh
./lab/collect-and-hunt.sh
docker compose down
```

`assert-admin-auth-off.sh` requires unauthenticated `GET /flows` to return
200 and requires `/data/settings.js` to contain only the commented-out
`//adminAuth` default.

`deploy-benign.sh` posts `lab/benign-flow.json` to `http://127.0.0.1:1880/flows`
(the proxy). The proxy appends a combined line to `lab/runtime/access.log`
and forwards to Node-RED on `127.0.0.1:1881`. Port 1881 bypasses the access
log; use 1880 for the exercise.

`collect-and-hunt.sh` prints the two marker files from inside the container
and runs `detect/flows-audit.py` against the exported flows and the proxy
log. It exits non-zero unless the output contains `EXEC_NODE`, `TMP_WRITE`,
and `POST_FLOWS`.

The proxy uses host networking so it can open `127.0.0.1:1881` and still
bind `1880` on the host. Checked on Linux Docker. `lab/runtime/` is gitignored.

### Checked on this image before the write-up

2026-11-05, `nodered/node-red:4.1.0`
(`sha256:da6ac47cce14ed8df7ceddc8a15c8f4c0a41e0836c4d6e68e7a6a82329305a6b`),
`nginx:1.27-alpine`.

- `GET /flows` without credentials returned 200.
- `settings.js` had `adminAuth` only in comments (`//adminAuth`).
- `POST /flows` returned 200 and a JSON `rev`. The proxy log line was
  `POST /flows HTTP/1.1` status 200, 74 bytes, client `127.0.0.1`.
- Inside the container, `/dev/shm/nodered-lab-whoami.txt` was
  `uid=1000(node-red) gid=1000(node-red) groups=1000(node-red)` and
  `/tmp/nodered-lab-marker.txt` was `lab-ok`.
- The auditor reported `EXEC_NODE lab-exec`, `TMP_WRITE` for `/dev/shm` and
  `/tmp`, three `UNEXPECTED` lab nodes, two `REMOVED` nodes (the image's
  default "Flow 1" tab and its comment), and `[INCIDENT] 127.0.0.1` for the
  `POST /flows`. `127.0.0.1` is the lab runner, not an external indicator.

The container flow has no `http in` node. `samples/flows-http-in-exec.json`
is the synthetic graph used to test that signal.

## Hunt the synthetic samples (no Docker)

From the repo root. Walk [hunt-checklist.md](./hunt-checklist.md) first if
you want to write your own detection before looking at the script.

```bash
python3 08-nodered-flow-audit/detect/flows-audit.py \
  --flows 08-nodered-flow-audit/samples/flows-lab-exec.json \
  --baseline 08-nodered-flow-audit/samples/flows-baseline.json \
  --access 08-nodered-flow-audit/samples/nodered-access.log
```

| Signal | Where it is flagged |
|---|---|
| `EXEC_NODE` | `type == exec` |
| `HTTP_IN_EXEC` | `http in` can reach an `exec` by following `wires` |
| `UNEXPECTED` / `REMOVED` | diff against `--baseline` (type, name, command, wires, url, method). Editor-only fields such as `x` / `y` are ignored |
| `TMP_WRITE` | exec command references `/tmp/` or `/dev/shm/` (`/tmpfile` does not match) |
| `POST_FLOWS` | combined log, method POST, path `/flows` or ending in `/flows` |

Verdicts per source IP: `[INCIDENT]` (2xx deploy and a hostile export),
`[SUSPICIOUS]` (2xx deploy, export has none of those nodes), `[RECON]`
(POST `/flows` never got a 2xx). The export is a point-in-time snapshot.
The access log has no body, so the script cannot prove which POST wrote
which node.

Rules next to the script:

- `detect/nodered-post-flows.yml` — web-server Sigma rule for an accepted
  `POST` whose path ends in `/flows`
- `detect/nodered-exec-tmp-write.yml` — Linux process-creation Sigma rule
  for a `node` parent whose command line contains `/tmp/` or `/dev/shm/`.
  Expect false positives on build hosts; pair it with the flows audit
- `detect/nodered-post-flows.rules` — two Suricata lab rules (local SIDs
  `1000001` and `1000002`). Remap the SIDs before loading them on a sensor
  you care about. One matches `POST` with a URI ending in `/flows`. The
  other also requires the body to contain a JSON `exec` node type

Lab 02's CloudTrail Sigma engine does not load these rules. `pytest` checks
that the files are present and name the signals above.

## Tests

```bash
python3 -m pytest 08-nodered-flow-audit/tests -v
```

Stdlib plus pytest. No network.

## Resume bullet (copy-ready)

- Built a detection-only Node-RED lab for CVE-2026-58115 (not in CISA KEV):
  loopback Node-RED with `adminAuth` off, a benign inject-to-exec marker
  flow, and a flows.json audit plus Sigma and Suricata rules for
  `POST /flows`, exec nodes, http-in wired to exec, and writes under
  `/tmp` or `/dev/shm`.

# 07 — kev-hunting

**Problem:** When CISA adds a vulnerability to the KEV catalog, federal agencies get a
hard deadline — but *your* network doesn't patch itself. The gap between "KEV published"
and "patch deployed" is the hunting window, and the public reporting usually contains
enough of the attack chain to hunt on.

**Case:** October 2026 KEV additions (CISA catalog version 2026.10.16, federal due
**2026-10-19**), plus the week of 10-12→10-18 additions (9 new KEV entries):

**New this week — full lab built:**
- **CVE-2026-85097** — Bricksforge (Bricks Builder add-on) unauthenticated RCE
  (CVSS 10.0/9.8, CWE-434). Polyglot GIF+PHP upload → crafted
  `temporaryFileUploads[].url` ending in `.php` → code execution. Patchstack:
  exploited in the wild since 2026-10-07; ~6,000 sites exposed; fixed in
  3.1.8.10 — **patch does not remove existing shells**. Not in CISA KEV.
  Companion: `../../soc-skills/labs/cve-2026-85097-bricksforge-rce.md`
  + `cve-2026-85097-detect.py` (validated TP=1 FP=0 on synthetic log)
  + `samples/bricksforge-access.log`.

**New this week — intel only (no public lab environment, KEV-listed):**
- **CVE-2026-104935** — Ivanti Connect Secure auth bypass by spoofing (CVSS 8.6,
  CWE-290) → unauthenticated RCE. Zero-day, Volexity + Rapid7 analysis. No lab
  (commercial VPN appliance).
- **CVE-2026-0322** — Palo Alto PAN-OS code injection (CVSS 8.6), authenticated
  mgmt-interface RCE as root. No lab (needs real firewall).
- **CVE-2026-96951** — Microsoft Windows MotW security-feature bypass (CVSS 8.8),
  exploited zero-day; October Patch Tuesday fixed a record 1,413 CVEs. No lab
  (Windows + sample complexity).
- **CVE-2026-76519** — Cisco Secure Email Gateway relative path traversal. No lab
  (needs real appliance).
- **CVE-2026-105133 / CVE-2026-105134** — Ahsay AhsayCBS improper auth + command
  injection. No lab (niche backup product).
- **CVE-2026-102764** — BeyondTrust Remote Support / PRA authentication bypass
  (CVSS 9.3, CWE-290). Mandiant/GTIG: suspected PRC-nexus **ARMORY CASTLE**
  (ex-UNC5221) exploited it as a zero-day from **late August 2026**. Chain:
  SAWFLY PHP web shell → root SUID shell → secrets-vault dump → passwordless sudo
  via boot script → BARECLAW SOCKS5-over-WebSocket via HAProxy → Jump Item role
  escalation → log deletion. Fixed in 26.2.4.
- **CVE-2025-61624** — Fortinet multiple-products path traversal. Palo Alto:
  **PEERSTITCH** campaign used FortiManager to expose 500+ firewalls, then this
  flaw to plant a memory-resident implant. No public PoC for either trigger as of
  2026-10-17.
- **CVE-2026-21589** — Atlassian Data Center `::` path traversal (CVSS 9.3,
  CWE-552). Unauthenticated file read on 8 products (Confluence/Jira/Bitbucket
  DC etc.); KEV 2026-10-15, federal due **2026-10-18**. watchTowr: `::` treated
  as path separator in Java normalization; honeypot hits within ~2h of
  disclosure; actively exploited in the wild (Previdian: 617 attempts, 68 IPs,
  21 countries). Companion: `../../soc-skills/labs/cve-2026-21589-atlassian-traversal.md`
  + `hunt-checklist-cve-2026-21589.md` + `samples/confluence-access.log`.
- **CVE-2026-110447** — Nextcloud Collabora Built-in CODE Server (`richdocumentscode`)
  OS command injection → unauthenticated RCE (CVSS 9.2, CWE-78). MITRE CVE text
  confirms in-the-wild exploitation Sept–Oct 2026 (PHP web shells; **not** in CISA
  KEV). Precondition: bundled CODE server not running. Fix ≥ 26.4.303 or full
  removal — **disabling is not enough**. Companion:
  `../../soc-skills/labs/cve-2026-110447-nextcloud-collabora-rce.md`
  + `hunt-checklist-cve-2026-110447.md` + `samples/nextcloud-access.log`.

**What it is:** A threat-hunting lab built around the KEV-to-action pipeline: take a
fresh KEV entry, extract huntable artifacts from public reporting, write detection
heuristics, and document the hunt. Companion piece:
`../../soc-skills/labs/cve-2026-102764-beyondtrust-auth-bypass.md` (lab card with
the full writeup + NICE mapping).

**Skills:** Threat-intel consumption (KEV), IOC extraction, log hunting, detection
engineering, incident documentation.

> `samples/` contains **synthetic training logs only** — generated for this lab,
> no real attacker data, no real malware. The real implants are never included.

## Safety rules (read first)

1. Hunt in **your own lab/VM logs** or the provided synthetic samples. Never run
   "hunt queries" against systems you don't own.
2. No exploit code lives here and none should be written here — this lab is
   **detection only**. Do not go looking for a PoC to "test".
3. If you find a real indicator during the exercises, stop and treat it as a real
   incident (isolate, escalate) — don't continue the lab on a compromised box.

## Lab exercises (do them yourself, in order)

### Exercise 1 — Intel extraction (30 min)
Read the BeyondTrust advisory BT26-05 summary and the Mandiant reporting referenced
in the soc-skills lab card. Extract every **huntable artifact** into a table:
artifact → log source → example value. Aim for the 7 in `hunt-checklist.md`.
Write the table in `incident-report-template.md` §1.

### Exercise 2 — Write the hunt (45 min)
Using the synthetic `samples/appliance.log`, write a script (or extend
`../02-python-ioc-analyzer/`) that flags each artifact type and correlates:
**≥2 distinct artifact types on one host within 24h → incident**.
Compare your output with the reference implementation in
`../../soc-skills/labs/cve-2026-102764-detect.py` *after* yours runs.

### Exercise 3 — Tune against benign noise (30 min)
The samples include benign admin activity (scheduled haproxy reloads, routine
vault reads, scheduled log rotation). Tune your heuristics so none of them
become incidents — document every allowlist decision and *why* in the report §3.
A hunter who can't explain their allowlist can't defend their alerts.

### Exercise 4 — Incident report (30 min)
Fill `incident-report-template.md` end to end as if Exercise 2's incident were
real: timeline, IoCs, severity call (justify P1), containment (isolate appliance,
rotate vault, rebuild from known-good), eradication, recovery, lessons learned.

## Detection notes

| Signal | Where | Why it matters |
|---|---|---|
| New `.php` under appliance web root | file integrity / syslog | SAWFLY web shell = initial persistence |
| setuid-root file outside pkg mgmt | EDR / auditd | Root SUID shell = privilege foothold |
| Vault read by unusual account | appliance audit log | Secrets theft precedes lateral movement |
| Boot script + sudoers changed together | file integrity | Passwordless sudo = reboot persistence |
| haproxy.cfg changed + new WS/SOCKS listener | config backup / netstat | BARECLAW = C2 channel |
| Jump Item role → Administrator | appliance audit log | Privilege escalation on the support plane |
| Log sequence gaps | SIEM | Actor deletes logs — absence is evidence |

## Resume bullet (copy-ready)

- Built a KEV-driven threat-hunting lab from the October 2026 CISA additions
  (BeyondTrust CVE-2026-102764 / Fortinet CVE-2025-61624): extracted 7 huntable
  artifacts from Mandiant/GTIG reporting, wrote a correlating hunt heuristic
  (≥2 artifact types / host / 24h), and documented the full incident workflow.

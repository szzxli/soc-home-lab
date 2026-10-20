# soc-home-lab

Hands-on cybersecurity lab projects: a mini-SOC on AWS, a Python IOC analyzer, a phishing analysis lab, binary triage, agent skills, and supply-chain defense. Built to demonstrate verifiable, practical security skills.

🔗 **https://github.com/szzxli/soc-home-lab**

📊 Skills quantified: these projects are graded against a public rubric and mapped to the NIST NICE framework in the companion repo **[szzxli/soc-skills](https://github.com/szzxli/soc-skills)** — including a one-page HR-readable skill profile.

> All datasets, log samples, and email artifacts in this repo are **synthetic training samples** — clearly labeled as such. No real incidents, real logs, or real phishing emails are presented here.

🧭 **[START_HERE.md](./START_HERE.md)** — one index of every project and every 07 case: dates, KEV status, log source, run mode, prerequisites, outputs.

## Projects

### 01 — [mini-soc](./01-mini-soc/)
**Problem:** SOC analysts need to know how cloud detections actually fire — not just theory.
**What it is:** A minimal AWS detection stack (VPC → CloudTrail → S3 → GuardDuty → SecurityHub), three adversary-emulation scenarios using [Stratus Red Team](https://stratus-red-team.cloud/) (verified technique IDs), a triage guide, and blank incident report templates.
**Skills:** CloudTrail analysis, GuardDuty triage, incident response workflow, Terraform IaC.

### 02 — [python-ioc-analyzer](./02-python-ioc-analyzer/)
**Problem:** Tier-1 analysts drown in raw CloudTrail logs; simple heuristics catch the obvious badness fast.
**What it is:** A working CLI tool that parses CloudTrail JSON, flags anomalous logins / failed-login spikes / risky IAM changes, enriches IPs via AbuseIPDB, and emits a Markdown report. Ships with synthetic sample data and passing pytest suite.
**Skills:** Python scripting, log analysis, IOC enrichment, detection heuristics.

### 03 — [phishing-analysis-lab](./03-phishing-analysis-lab/)
**Problem:** Phishing triage is daily Tier-1 SOC work — header forensics, auth-result interpretation, URL deobfuscation.
**What it is:** A full walkthrough of a reconstructed training-sample phish, a header-analysis cheatsheet, a blank analysis report template, and a self-test guide using GoPhish (own mailbox only).
**Skills:** Email header forensics, SPF/DKIM/DMARC, URL analysis, phishing triage.

### 04 — [rea-triage](./04-rea-triage/)
**Problem:** Agent-facing reverse-engineering CLIs expose dozens of granular subcommands and machine-oriented JSON — powerful, but not human-friendly for quick triage.
**What it is:** A one-command ELF binary triage CLI (`triage.py <binary>`): section-entropy packing heuristics, W^X detection, suspicious-import watchlist, string IOC extraction, score-based verdict (benign/suspicious/malicious), and a one-page analyst report. Optional third-party `inspect-binary-layout` enrichment when a provider is configured; degrades honestly without it.
**Skills:** Static binary analysis, ELF internals, malware triage heuristics, detection engineering.

### 05 — [soc-skills](./05-soc-skills/)
**Problem:** The trending `mattpocock/skills` (291k stars) packages one TypeScript engineer's agent workflow — nothing in it speaks SOC.
**What it is:** Six agent skills for the Tier-1 analyst loop, each distilled from a working project in this repo: `alert-triage`, `incident-report`, `cloudtrail-ioc`, `phishing-analysis`, `binary-triage`, `detection-engineering`. Each skill declares its trigger, workflow, output contract, and honesty boundaries. MIT licensed, copy-paste installable into any agent's skills directory.
**Skills:** Detection triage, incident documentation, knowledge distillation into agent skills.

### 06 — [ghostaction-supply-chain](./06-ghostaction-supply-chain/)
**Problem:** Supply-chain attacks now target the developer's own workbench — a malicious `.vscode/tasks.json` executes code on project open, and a cron backdoor survives deleting the repo.
**What it is:** A safe, hands-on lab built around the GhostAction technique (Oct 2026): inert training samples demonstrating the mechanism, a hunt checklist for workspace tasks + cron/systemd persistence, and a blank incident report template.
**Skills:** Supply-chain threat modeling, static config review, persistence hunting, incident documentation.

### 07 — [kev-hunting](./07-kev-hunting/)
**Problem:** CISA KEV entries come with a federal deadline, but your network doesn't patch itself — the gap between "KEV published" and "patch deployed" is the hunting window.
**What it is:** A threat-hunting lab built around the October 2026 KEV additions and same-week in-the-wild cases. Full labs with hunt checklists, synthetic logs, and companion detection scripts: BeyondTrust CVE-2026-102764 (7 huntable artifacts from Mandiant/GTIG reporting, correlating hunt heuristic), Atlassian CVE-2026-21589, Nextcloud CVE-2026-110447, Bricksforge CVE-2026-85097, Ivanti CVE-2026-104935, Siemens CVE-2026-110936, Redis CVE-2026-25243, five unauthenticated agent-tool RCE CVEs, and the M365 app-identity persistence pattern (ConnectWise incident, no CVE). Further KEV entries are tracked intel-only with the reason recorded (see the 07 README). Full per-case index: [START_HERE.md](./START_HERE.md).
**Skills:** Threat-intel consumption, IOC extraction, log hunting, detection engineering, incident documentation.

## Resume bullets (copy-ready)

- Built a mini-SOC on AWS (CloudTrail, GuardDuty, SecurityHub via Terraform); emulated adversary techniques with Stratus Red Team and authored triage runbooks for GuardDuty findings.
- Developed a Python CLI tool that parses CloudTrail logs, applies detection heuristics (impossible-travel logins, brute-force spikes, risky IAM changes), and enriches IOCs via AbuseIPDB — with synthetic test data and a passing pytest suite.
- Performed structured phishing email analysis (header forensics, SPF/DKIM/DMARC interpretation, URL deobfuscation, IOC extraction) on reconstructed training samples; documented Tier-1 response procedures.
- Built a one-command ELF binary triage tool: static heuristics (section entropy, W^X, suspicious imports, string IOCs), score-based verdict, analyst-ready report; optional REA provider enrichment.
- Authored six MIT-licensed agent skills for SOC analysts (alert triage, incident reporting, CloudTrail IOC analysis, phishing analysis, binary triage, detection engineering), distilled from working home-lab projects — the security-flavored answer to `mattpocock/skills`.
- Authored incident report templates and detection triage guides following SOC documentation standards.

## Skills matrix

| SOC Analyst JD keyword | Covered in |
|---|---|
| SIEM / log analysis | 01 (CloudTrail, GuardDuty), 02 (log parsing) |
| Incident response & triage | 01 (triage guide, IR templates) |
| Threat detection / IOCs | 02 (heuristics, AbuseIPDB enrichment), 03 (IOC extraction) |
| Phishing analysis | 03 (full walkthrough + cheatsheet) |
| Cloud security (AWS) | 01 (VPC, IAM, S3, GuardDuty, SecurityHub) |
| Scripting / automation (Python) | 02 (CLI tool + tests) |
| IaC (Terraform) | 01 (`terraform/main.tf`) |
| Documentation & reporting | 01 + 03 (templates, write-ups) |

## Cost & cleanup

- Project 01 needs your own AWS account; estimated **$5–15/month** at minimal config. **Run `terraform destroy` when done** — do not leave detectors running unattended.
- Projects 02 and 03 are free (local only, plus optional AbuseIPDB free API key).

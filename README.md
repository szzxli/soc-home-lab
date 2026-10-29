# soc-home-lab

> **👉 New here? Read [START_HERE.md](./START_HERE.md) first.** It explains what this repo is, gives you a path to follow (new to SOC / practicing detection / prepping for interviews), and has one table of every case with its CVE/KEV status, skills, contents, and the command to verify its detection.

Hands-on cybersecurity lab projects: a mini-SOC on AWS, a Python IOC analyzer, a phishing analysis lab, binary triage, agent skills, a VS Code supply-chain defense lab, and KEV-driven threat-hunting packs. Built to demonstrate verifiable, practical security skills.

🔗 **https://github.com/szzxli/soc-home-lab**

**▶ Live demo:** [CloudTrail IOC analyzer in your browser](https://szzxli.github.io/soc-home-lab/web/demo.html) (synthetic data, nothing leaves the page) · [Project site](https://szzxli.github.io/soc-home-lab/web/)

**Quick start** (Python 3.9+):

```bash
git clone https://github.com/szzxli/soc-home-lab.git
cd soc-home-lab/02-python-ioc-analyzer
pip install -r requirements.txt
python ioc_analyzer.py --input sample_data/sample_cloudtrail.json --output report.md
```

📊 Skills quantified: these projects are graded against a public rubric and mapped to the NIST NICE framework in the companion repo **[szzxli/soc-skills](https://github.com/szzxli/soc-skills)** — including a one-page HR-readable skill profile.

> All datasets, log samples, and email artifacts in this repo are **synthetic training samples** — clearly labeled as such. No real incidents, real logs, or real phishing emails are presented here.

**What this is / isn't:** beginner-to-intermediate SOC practice on synthetic data (clean samples plus [noisy variants](./NOISY_DATA.md) with honest TP/FP numbers). It isn't proof of job readiness and isn't real SOC volume.

**What's different here:** KEV-driven, with every CVE / KEV claim re-verified weekly against the official CISA feed ([`tools/verify_kev.py`](./tools/verify_kev.py), [workflow](./.github/workflows/kev-verify.yml)) · the demo [runs in your browser](https://szzxli.github.io/soc-home-lab/web/demo.html) · pairs with the [soc-skills gap analysis](https://szzxli.github.io/soc-skills/web/).

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
**Problem:** General-purpose agent skill packs don't cover SOC work.
**What it is:** Six agent skills for the Tier-1 analyst loop, each distilled from a working project in this repo: `alert-triage`, `incident-report`, `cloudtrail-ioc`, `phishing-analysis`, `binary-triage`, `detection-engineering`. Each skill declares its trigger, workflow, output contract, and honesty boundaries. MIT licensed, copy-paste installable into any agent's skills directory.
**Skills:** Detection triage, incident documentation, knowledge distillation into agent skills.

### 06 — [ghostaction-supply-chain](./06-ghostaction-supply-chain/)
**Problem:** Supply-chain attacks now target the developer's own workbench — a malicious `.vscode/tasks.json` can execute code the moment a project folder is opened, and a cron-based backdoor survives deleting the repo files.
**What it is:** A safe, hands-on supply-chain defense lab built around the GhostAction technique (October 2026): inert training samples that demonstrate the mechanism with zero malicious behavior, a hunt checklist for the two persistence points (workspace tasks + cron), four exercises, and a blank incident report template.
**Skills:** Supply-chain threat modeling, static review of editor configs, persistence hunting (cron/systemd), incident documentation.

### 07 — [kev-hunting](./07-kev-hunting/)
**Problem:** CISA KEV entries come with a federal deadline, but your network doesn't patch itself — the gap between "KEV published" and "patch deployed" is the hunting window.
**What it is:** Threat-hunting packs built from the October 2026 CISA KEV additions and same-week in-the-wild cases. Every pack starts with its KEV status, a **Sources** line (CISA KEV, NVD, vendor advisory where one is cited) and the date it was last checked; KEV status last verified 2026-10-24 (catalog version 2026.10.23), re-checked weekly. Each pack has a hunt checklist; each also has a synthetic log and a reference detection script — three in this repo under [`07-kev-hunting/detect/`](./07-kev-hunting/detect/) (with tests in [`07-kev-hunting/tests/`](./07-kev-hunting/tests/)), the rest in the companion repo [soc-skills](https://github.com/szzxli/soc-skills/tree/main/labs). Per-case details and verify commands are in [START_HERE.md](./START_HERE.md).

- **Hunt packs (checklist + synthetic log + reference detection in soc-skills):** Plex2Shell CVE-2026-96652/96654/96655/96656 · Bricksforge CVE-2026-85097 · Ivanti Connect Secure CVE-2026-104935 · Siemens Software Center CVE-2026-110936 · Redis CVE-2026-25243 · AI agent tool endpoints without auth (CVE-2026-77936 / 75128 / 77932 / 109442 / 109437) · M365 app-identity persistence (ConnectWise incident, no CVE)
- **Hunt packs (checklist + synthetic log + noisy log + reference detection in [`07-kev-hunting/detect/`](./07-kev-hunting/detect/)):** Atlassian CVE-2026-21589 · Nextcloud CVE-2026-110447 · BeyondTrust Remote Support CVE-2026-102764 (plus exercises in the 07 README). TP/FP on the noisy logs: [NOISY_DATA.md](./NOISY_DATA.md)
- **Intel only, with the reason recorded in the [07 README](./07-kev-hunting/README.md):** SiteGuard CVE-2026-106931 · PAN-OS CVE-2026-0322 · Microsoft Windows Command Injection Vulnerability (CVE-2026-96951) · Cisco SEG CVE-2026-76519 · Ahsay CVE-2026-105133 / CVE-2026-105134 · Fortinet CVE-2025-61624

**Skills:** Threat-intel consumption, IOC extraction, log hunting, detection engineering, incident documentation.

## Go deeper (free, complementary)

This kit is small on purpose. For real attack telemetry, bigger datasets and graded challenges:
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) ·
[Splunk Boss of the SOC](https://bots.splunk.com/) ·
[CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/) ·
[LetsDefend](https://letsdefend.io/) ·
[Blue Team Labs Online](https://blueteamlabs.online/).

## Resume bullets (copy-ready)

- Built a mini-SOC on AWS (CloudTrail, GuardDuty, SecurityHub via Terraform); emulated adversary techniques with Stratus Red Team and authored triage runbooks for GuardDuty findings.
- Developed a Python CLI tool that parses CloudTrail logs, applies detection heuristics (impossible-travel logins, brute-force spikes, risky IAM changes), and enriches IOCs via AbuseIPDB — with synthetic test data and a passing pytest suite.
- Performed structured phishing email analysis (header forensics, SPF/DKIM/DMARC interpretation, URL deobfuscation, IOC extraction) on reconstructed training samples; documented Tier-1 response procedures.
- Built a one-command ELF binary triage tool: static heuristics (section entropy, W^X, suspicious imports, string IOCs), score-based verdict, analyst-ready report; optional REA provider enrichment.
- Authored six MIT-licensed agent skills for SOC analysts (alert triage, incident reporting, CloudTrail IOC analysis, phishing analysis, binary triage, detection engineering), distilled from working home-lab projects.
- Built a supply-chain defense lab around the GhostAction technique (malicious VS Code workspace tasks + cron persistence): wrote a static detector for dangerous `tasks.json` patterns and a persistence-hunt runbook covering cron/systemd/autostart.
- Authored incident report templates and detection triage guides following SOC documentation standards.

## Skills matrix

| SOC Analyst JD keyword | Covered in |
|---|---|
| SIEM / log analysis | 01 (CloudTrail, GuardDuty), 02 (log parsing) |
| Incident response & triage | 01 (triage guide, IR templates), 06 + 07 (IR report templates) |
| Threat detection / IOCs | 02 (heuristics, AbuseIPDB enrichment), 03 (IOC extraction), 07 (hunt checklists + detection scripts) |
| Phishing analysis | 03 (full walkthrough + cheatsheet) |
| Cloud security (AWS) | 01 (VPC, IAM, S3, GuardDuty, SecurityHub) |
| Scripting / automation (Python) | 02 (CLI tool + tests) |
| IaC (Terraform) | 01 (`terraform/main.tf`) |
| Documentation & reporting | 01 + 03 (templates, write-ups) |

## Cost & cleanup

- Project 01 needs your own AWS account; estimated **$5–15/month** at minimal config. **Run `terraform destroy` when done** — do not leave detectors running unattended.
- Projects 02–07 are free (local only; 02 can use an optional AbuseIPDB free API key).

## Privacy

Privacy: we count anonymous page views with [GoatCounter](https://www.goatcounter.com) — no cookies, no personal data, no consent banner needed. Your content never goes to the counter: anything you type, paste or upload stays in your browser (except requests you start yourself, such as an AI-grading or lookup call to a provider you choose). Exactly what is sent is documented at the top of the site's `analytics.js`.

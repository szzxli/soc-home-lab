# soc-home-lab

> **👉 New here? Read [START_HERE.md](./START_HERE.md) first.** It explains what this repo is, gives you a path to follow (new to SOC / practicing detection / prepping for interviews), and has one table of every case with its CVE/KEV status, skills, contents, and the command to verify its detection.

Hands-on cybersecurity lab projects: a mini-SOC on AWS, a Python IOC analyzer, a phishing analysis lab, binary triage, agent skills, and KEV-driven threat-hunting packs. Built to demonstrate verifiable, practical security skills.

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

### 06 — ghostaction-supply-chain *(not yet published)*
Listed in earlier versions of this README, but the `06-ghostaction-supply-chain/` folder isn't in the repo yet. It will be linked here once it's committed.

### 07 — [kev-hunting](./07-kev-hunting/)
**Problem:** CISA KEV entries come with a federal deadline, but your network doesn't patch itself — the gap between "KEV published" and "patch deployed" is the hunting window.
**What it is:** Threat-hunting packs built from the October 2026 CISA KEV additions and same-week in-the-wild cases. Each pack has a hunt checklist; most also have a synthetic log and a reference detection script in the companion repo [soc-skills](https://github.com/szzxli/soc-skills/tree/main/labs). Per-case details and verify commands are in [START_HERE.md](./START_HERE.md).

- **Hunt packs (checklist + synthetic log + reference detection):** Plex2Shell CVE-2026-96652/96654/96655/96656 · Bricksforge CVE-2026-85097 · Ivanti Connect Secure CVE-2026-104935 · Siemens Software Center CVE-2026-110936 · Redis CVE-2026-25243 · AI agent tool endpoints without auth (CVE-2026-77936 / 75128 / 77932 / 109442 / 109437) · M365 app-identity persistence (ConnectWise incident, no CVE)
- **Hunt packs (partial):** Atlassian CVE-2026-21589 (checklist + self-contained detection script) · Nextcloud CVE-2026-110447 (checklist only) · BeyondTrust CVE-2026-102764 (checklist + exercises; sample log not yet in repo)
- **Intel only, with the reason recorded in the [07 README](./07-kev-hunting/README.md):** SiteGuard CVE-2026-106931 · PAN-OS CVE-2026-0322 · Microsoft Windows Command Injection Vulnerability (CVE-2026-96951) · Cisco SEG CVE-2026-76519 · Ahsay CVE-2026-105133 / CVE-2026-105134 · Fortinet CVE-2025-61624

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

## Privacy

Privacy: we count anonymous page views with [GoatCounter](https://www.goatcounter.com) — no cookies, no personal data, no consent banner needed. Your content never goes to the counter: anything you type, paste or upload stays in your browser (except requests you start yourself, such as an AI-grading or lookup call to a provider you choose). Exactly what is sent is documented at the top of the site's `analytics.js`.

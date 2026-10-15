# soc-home-lab

Hands-on cybersecurity lab projects: a mini-SOC on AWS, a Python IOC analyzer, and a phishing analysis lab. Built to demonstrate verifiable, practical security skills.

🔗 **https://github.com/szzxli/soc-home-lab**

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
**Problem:** This week's #1 trending `morluto/rea` exposes 50+ agent-facing subcommands and machine-oriented Evidence JSON — powerful, but not human-friendly for quick triage.
**What it is:** A one-command ELF binary triage CLI (`triage.py <binary>`) built on the REA *idea*: section-entropy packing heuristics, W^X detection, suspicious-import watchlist, string IOC extraction, score-based verdict (benign/suspicious/malicious), and a one-page analyst report. Optional REA `inspect-binary-layout` enrichment when the provider is configured; degrades honestly without it.
**Skills:** Static binary analysis, ELF internals, malware triage heuristics, detection engineering.

## Resume bullets (copy-ready)

- Built a mini-SOC on AWS (CloudTrail, GuardDuty, SecurityHub via Terraform); emulated adversary techniques with Stratus Red Team and authored triage runbooks for GuardDuty findings.
- Developed a Python CLI tool that parses CloudTrail logs, applies detection heuristics (impossible-travel logins, brute-force spikes, risky IAM changes), and enriches IOCs via AbuseIPDB — with synthetic test data and a passing pytest suite.
- Performed structured phishing email analysis (header forensics, SPF/DKIM/DMARC interpretation, URL deobfuscation, IOC extraction) on reconstructed training samples; documented Tier-1 response procedures.
- Built a one-command ELF binary triage tool (inspired by trending `morluto/rea`): static heuristics (section entropy, W^X, suspicious imports, string IOCs), score-based verdict, analyst-ready report; optional REA provider enrichment.
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

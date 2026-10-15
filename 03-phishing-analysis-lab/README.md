# 03 — Phishing Analysis Lab

A hands-on lab for **phishing email triage and analysis** — one of the most common daily tasks for a Tier-1 SOC analyst. Every file in this project is in English and built around a single honest principle: the training samples here are **reconstructed by me for practice**, clearly labeled as such, and no real-world incident is claimed.

Repository: https://github.com/szzxli/soc-home-lab

---

## What's in this project

| File | What it is |
|---|---|
| `header-analysis-cheatsheet.md` | Quick-reference: key header fields, SPF/DKIM/DMARC verdict tables, and a one-line recognition guide for common obfuscation techniques |
| `sample-walkthrough.md` | Full end-to-end analysis of a **reconstructed training sample** (labeled `RECONSTRUCTED TRAINING SAMPLE — not a real phish received`): headers → auth → multi-layer URL decoding → attachment IOCs → verdict → Tier-1 response steps |
| `gophish-selftest-guide.md` | How to send a simulated phish to **your own mailbox only** with GoPhish, then analyze it yourself using this project's method. Includes a compliance box with legal boundaries. |
| `report-template.md` | Blank phishing analysis report template (metadata / headers / auth / IOCs / verdict / actions) — ships blank by design, never pre-filled with a fabricated case |

---

## Learning path

Follow this order — each step builds on the previous one:

1. **Read the cheatsheet** (`header-analysis-cheatsheet.md`). Learn what each header field means and how to read SPF/DKIM/DMARC results at a glance. This is your desk reference for everything after.
2. **Follow the walkthrough** (`sample-walkthrough.md`). Trace a complete analysis: Received-chain reading, `Return-Path` vs `From` vs `Reply-To` mismatch, line-by-line `Authentication-Results` interpretation, multi-layer URL deobfuscation (URL-decode → Base64-decode → landing analysis), attachment IOC extraction, verdict with severity rating, and the Tier-1 response playbook.
3. **Phish yourself** (`gophish-selftest-guide.md`). Set up GoPhish, send a simulated phish to your own mailbox **only**, then analyze it with the walkthrough method *before* clicking anything. Compare your verdict against what GoPhish recorded.
4. **Write it up** (`report-template.md`). Document your self-test (or any future real report) using the template. Practice writing verdicts with evidence, severity, confidence, and recommended actions — this is what hiring managers want to see.

---

## SOC skills this maps to

Phishing triage is Tier-1 daily work. This lab demonstrates:

- **Email header analysis** — Received-chain tracing, sender-identity verification (`Return-Path` / `From` / `Reply-To`), Message-ID assessment
- **Email authentication** — reading and interpreting SPF, DKIM, and DMARC results, including alignment and domain-owner policy (`p=reject`/`quarantine`/`none`)
- **URL deobfuscation** — layered decoding (URL encoding, Base64), short-link/redirector chain expansion with `curl -I`, landing-page assessment without interaction
- **IOC extraction** — file hashing (SHA-256/MD5), embedded URL extraction from attachments, sandbox submission workflow
- **Verdict & severity rating** — evidence-weighted judgment with confidence levels and exculpatory-evidence checks
- **Incident response basics** — reporter containment, evidence preservation, blast-radius hunting, blocking, and reporting/escalation
- **Professional integrity** — reconstructed samples are labeled as reconstructed; reports are never pre-filled with fabricated cases; offensive tooling (GoPhish) is used strictly within legal and ethical bounds

These map directly to Associate Cybersecurity Analyst / SOC Analyst job descriptions: *"analyze phishing emails," "triage security alerts," "document findings," "escalate per playbook."*

---

## Honesty & compliance notes

- The walkthrough sample is **fictional and self-authored** — it says so at the top of the file. All domains are placeholders (`*.example`), all IPs are from the `192.0.2.0/24` TEST-NET-1 documentation range.
- The GoPhish guide restricts simulations to **your own mailbox**. Targeting others without written authorization may violate computer-crime laws.
- The report template is intentionally blank. A portfolio artifact built on an invented "real incident" would be a lie an interviewer could unravel in one question — this project is designed so every claim in it survives scrutiny.

---

*Part of the [soc-home-lab](https://github.com/szzxli/soc-home-lab) series — verifiable, hands-on security experience.*

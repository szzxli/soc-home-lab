# START HERE — Case Index

One index for everything in this repo: the seven numbered projects, plus every
case tracked in [07-kev-hunting](./07-kev-hunting/) listed individually.

**How to read this index**

- Values come only from the project/case documents themselves. Anything the
  source documents do not specify is marked **Not stated** rather than guessed —
  this applies to difficulty in particular: no document in this repo rates
  difficulty, so no row here invents one.
- All logs, samples, and email artifacts are **synthetic training data**,
  labeled as such in their own folders. No real incident data is included.
- "Complete lab" means the folder ships a checklist/exercises plus data to
  work on. "Intel only" means the case is tracked in the 07 README as a
  written note — no lab was built, and the README says why.

## Projects 01–07

| # | Project | Published / last reviewed | Threat source & evidence | KEV status | Log source & data form | How to run | Difficulty | Est. time | Prerequisites | Output | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 01 | [mini-soc](./01-mini-soc/) | Not stated | Not applicable — adversary-emulation scenarios (Stratus Red Team), not an intel case | No CVE | CloudTrail events + GuardDuty findings generated live in your AWS account | AWS (your own account, Terraform) | Not stated | Not stated (a 15-minute quickstart is documented) | Your own AWS account, Terraform ≥ 1.5, AWS CLI credentials, Stratus Red Team binary | Deployed mini-SOC, triage notes, incident report | Complete lab |
| 02 | [python-ioc-analyzer](./02-python-ioc-analyzer/) | Not stated | Not applicable — tooling project | No CVE | CloudTrail JSON (synthetic sample included) | Local script (Python) | Not stated | Not stated | Python 3.9+ | Markdown IOC findings report | Complete lab (tool + test suite) |
| 03 | [phishing-analysis-lab](./03-phishing-analysis-lab/) | Not stated | Not applicable — reconstructed training sample, self-authored | No CVE | Reconstructed training-sample email (headers, auth results, URLs) | Offline (documents; optional GoPhish self-test to your own mailbox only) | Not stated | Not stated | Not stated | Completed phishing analysis report (four-stage template) | Complete lab |
| 04 | [rea-triage](./04-rea-triage/) | Not stated | Not applicable — tooling project | No CVE | ELF binaries (synthetic demo ELF generator included) | Local script (Python, pyelftools) | Not stated | Not stated | Python 3 + pyelftools | One-page triage report with score-based verdict | Complete lab (tool + test suite) |
| 05 | [soc-skills](./05-soc-skills/) | Not stated | Not applicable — agent skill pack | No CVE | SKILL.md files (Markdown) | Offline (copy into an agent's skills directory) | Not stated | Not stated | Not stated | Six installed agent skills | Complete |
| 06 | [ghostaction-supply-chain](./06-ghostaction-supply-chain/) | Case reported Oct 2026 (per project README) | GhostAction campaign reporting (GBHackers, linked in the project README) | No CVE | Inert sample files (`.vscode/tasks.json`, disguised JS) + your own host's cron/systemd state | Offline (static analysis; persistence hunt on your own machine) | Not stated | ~2 hours (exercise times as written: 15 + 45 + 30 + 30 min) | Not stated | Detector script + completed incident report | Complete lab |
| 07 | [kev-hunting](./07-kev-hunting/) | Oct 2026 (CISA catalog version 2026.10.16, per project README) | CISA KEV catalog + vendor/researcher reporting, per case below | Per case (see table below) | Synthetic sample logs in `07-kev-hunting/samples/` | Offline (samples + reference detection scripts in the companion repo) | Not stated | Per case (see table below) | Per case (see table below) | Hunt findings + incident report | Complete lab (umbrella project; per-case status below) |

## 07-kev-hunting — every case, individually

| Case | Published / last reviewed | Threat source & evidence | KEV status | Log source & data form | How to run | Difficulty | Est. time | Prerequisites | Output | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-102764 — BeyondTrust Remote Support / PRA auth bypass (ARMORY CASTLE chain) | KEV Oct 2026; federal due 2026-10-19 (per 07 README) | Mandiant/GTIG reporting (per 07 README and hunt checklist) | Listed | Synthetic appliance log (`samples/appliance.log`) | Offline | Not stated | ~2.25 hours (exercise times as written: 30 + 45 + 30 + 30 min) | Not stated | Huntable-artifact table, hunt script, completed incident report | Complete lab |
| CVE-2025-61624 — Fortinet multiple-products path traversal (PEERSTITCH) | KEV Oct 2026 (per 07 README) | Palo Alto Networks reporting (per 07 README) | Listed | None — no sample log | Not applicable | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |
| CVE-2026-21589 — Atlassian Data Center `::` path traversal | KEV 2026-10-15; federal due 2026-10-18 | watchTowr research + Previdian honeypot reporting (per 07 README) | Listed | Synthetic Confluence access log (`samples/confluence-access.log`) | Offline | Not stated | Not stated | Web access logs for the affected Atlassian DC products (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-110447 — Nextcloud Collabora built-in CODE Server RCE | In-the-wild exploitation Sept–Oct 2026 (per 07 README) | MITRE CVE text confirming in-the-wild exploitation (per 07 README) | Not listed | Synthetic Nextcloud access log (`samples/nextcloud-access.log`) | Offline | Not stated | Not stated | Nextcloud with `richdocumentscode` installed; access logs (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-85097 — Bricksforge (WordPress) unauthenticated RCE | Exploited in the wild since 2026-10-07 (per 07 README) | Patchstack reporting (per 07 README) | Not listed | Synthetic WordPress access log (`samples/bricksforge-access.log`) | Offline | Not stated | Not stated | WordPress + Bricksforge install and its access logs (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-104935 — Ivanti Connect Secure welcome.cgi auth bypass → RCE | Checklist reality check dated 2026-10-19; exploited in the wild from 2026-10-03 | UTA0576 in-the-wild exploitation reporting (per 07 README) | Not listed | Synthetic welcome.cgi log, header-enriched (`samples/ivanti-welcome-cgi.log`) | Offline | Not stated | Not stated | Header-enriched HTTP logs — the checklist states the HTTP layer is blind without them | Hunt results + incident report | Complete lab |
| CVE-2026-110936 — Siemens Software Center DLL sideloading | Checklist reality check dated 2026-10-20; exploited in the wild Oct 2026 | Romulus ClickFix platform reporting (per 07 README) | Not listed | Synthetic Sysmon-style process/DLL log (`samples/siemens-sideload.log`) | Offline | Not stated | Not stated | Endpoint telemetry: Sysmon Event 1 (ProcessCreate) minimum, Event 7 (ImageLoad) for DLL evidence (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-25243 — Redis RESTORE double-free → authenticated RCE | Checklist reality check dated 2026-10-20; honeypot-observed in the wild 2026-10-16/17 | Honeypot observations of scripted in-the-wild attempts (per 07 README and hunt checklist) | Not listed | Synthetic Redis command-audit log (`samples/redis-restore-audit.log`) | Offline | Not stated | Not stated | A Redis command-audit feed — stock Redis does not log commands (per hunt checklist) | Hunt results + incident report | Complete lab |
| Agent tool-execution endpoints without authentication — CVE-2026-77936 (Letta) / CVE-2026-75128 (Langchain-Chatchat) / CVE-2026-77932 (DB-GPT) / CVE-2026-109442 (piflow) / CVE-2026-109437 (Cognition) | Five CVEs published 2026-10-20 (per hunt checklist) | NVD entries for the five CVEs (per hunt checklist) | Not listed (none of the five, as of 2026-10-20) | Synthetic enriched proxy access log (`samples/agent-tool-unauth-rce-access.log`) | Offline | Not stated | Not stated | Enriched proxy/WAF logs recording credential presence + body excerpt (per 07 README) | Hunt results + incident report | Complete lab |
| M365 app-identity persistence — ConnectWise Cloud Backup incident pattern | Incident discovered 2026-10-15; checklist facts as of 2026-10-20 | ConnectWise advisory + Huntress confirmation (per hunt checklist) | No CVE | Synthetic M365 / Entra ID audit log (`samples/m365-app-identity-audit.log`) | Offline | Not stated | Not stated | Entra ID audit records for role changes, app credential changes, and service-principal sign-ins, retained ≥ 90 days (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-0322 — Palo Alto PAN-OS code injection | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) | Not stated | Listed | None — no sample log | Not applicable (no lab: needs a real firewall, per 07 README) | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |
| CVE-2026-96951 — Microsoft Windows MotW security-feature bypass | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) | Not stated | Listed | None — no sample log | Not applicable (no lab: Windows + sample complexity, per 07 README) | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |
| CVE-2026-76519 — Cisco Secure Email Gateway path traversal | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) | Not stated | Listed | None — no sample log | Not applicable (no lab: needs a real appliance, per 07 README) | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |
| CVE-2026-105133 — Ahsay AhsayCBS improper authentication | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) | Not stated | Listed | None — no sample log | Not applicable (no lab, per 07 README) | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |
| CVE-2026-105134 — Ahsay AhsayCBS command injection | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) | Not stated | Listed | None — no sample log | Not applicable (no lab, per 07 README) | Not stated | Not stated | Not stated | Intel note in the 07 README | Intel only |

---

Back to the [repo README](./README.md) for project write-ups, resume bullets,
and the skills matrix.

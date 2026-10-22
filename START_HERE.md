# START HERE

**soc-home-lab is a free, open-source practice kit for people breaking into SOC
(Security Operations Center) work.** It has hands-on projects you can run on
your own laptop or AWS account: a mini cloud SOC, a CloudTrail log analyzer,
a phishing analysis walkthrough, an ELF binary triage tool, SOC agent skills,
a VS Code supply-chain defense lab, and a set of threat-hunting packs built from real October 2026 vulnerabilities
(CISA KEV and in-the-wild cases). Each hunt pack gives you a hunt checklist and
a synthetic log to hunt in, and most come with a reference detection script you
can run yourself. All logs and samples are **synthetic training data**. No real
incident data is included.

## Pick your path

| If you are… | Start with | Then |
|---|---|---|
| **New to SOC**: you want to learn what a Tier-1 analyst actually does | [03 phishing-analysis-lab](./03-phishing-analysis-lab/) (offline, no setup) → [02 python-ioc-analyzer](./02-python-ioc-analyzer/) (one `pip install`, or try the [browser demo](https://szzxli.github.io/soc-home-lab/web/demo.html)) | [01 mini-soc](./01-mini-soc/) if you have an AWS account (costs about $5–15/month; run `terraform destroy` when you're done) |
| **Practicing detection**: you want to hunt in logs and check your logic against a reference | Any 07 hunt pack marked **Hunt pack** below that has a command in the "Verify" column. Work through the checklist, write your own detection, *then* run the reference script | [04 rea-triage](./04-rea-triage/) for binary triage, plus the Sigma rules in [02](./02-python-ioc-analyzer/rules/) |
| **Prepping for interviews**: you want talking points and resume bullets | The [README](./README.md) (resume bullets + JD-keyword skills matrix) | Do one 07 hunt pack end to end so you can talk through a real recent CVE: what you'd look for, in which log, and why |

## Case index

Blank cell = the repo doesn't say. Nothing here is estimated. No document in
the repo rates difficulty, so the Difficulty column is blank throughout.
"Verify" commands run from the repo root. Three 07 reference detection scripts
(BeyondTrust, Nextcloud, Atlassian) ship in this repo under
[`07-kev-hunting/detect/`](./07-kev-hunting/detect/), with a pytest suite in
[`07-kev-hunting/tests/`](./07-kev-hunting/tests/). The other seven live in the
companion repo [szzxli/soc-skills](https://github.com/szzxli/soc-skills),
so clone it next to this one first:

```bash
git clone https://github.com/szzxli/soc-home-lab && git clone https://github.com/szzxli/soc-skills
cd soc-home-lab
```

### Projects

| # | Case | CVE / KEV | Skills | Difficulty | Included | Verify |
|---|---|---|---|---|---|---|
| 01 | [mini-soc](./01-mini-soc/): AWS detection stack + Stratus Red Team scenarios | No CVE | cloud, triage, IR | | Terraform, attack runbook, triage guide, IR report template | Live AWS only: follow the [15-minute quickstart](./01-mini-soc/README.md) (`terraform apply`, `stratus detonate …`) and confirm the GuardDuty finding |
| 02 | [python-ioc-analyzer](./02-python-ioc-analyzer/): CloudTrail IOC CLI + Sigma engine | No CVE | cloud, detection, triage | | Tool, synthetic CloudTrail log + [noisy variant](./NOISY_DATA.md), 3 Sigma rules, sample reports, tests | `cd 02-python-ioc-analyzer && pip install -r requirements.txt && python -m pytest tests/ -v` |
| 03 | [phishing-analysis-lab](./03-phishing-analysis-lab/): header forensics walkthrough | No CVE | phishing, triage | | Walkthrough, header cheatsheet, report template, GoPhish self-test guide | |
| 04 | [rea-triage](./04-rea-triage/): one-command ELF triage | No CVE | binary triage, detection | | Tool, synthetic demo ELF + generator, tests | `cd 04-rea-triage && pip install -r requirements.txt && python -m pytest tests/ -v` |
| 05 | [soc-skills](./05-soc-skills/): 6 agent skills for the Tier-1 loop | No CVE | triage, IR, detection, phishing, binary triage, cloud | | 6 `SKILL.md` files | |
| 06 | [ghostaction-supply-chain](./06-ghostaction-supply-chain/): GhostAction-style malicious VS Code workspace tasks + cron persistence | No CVE | supply chain, hunting, IR | | Inert training samples (`tasks.json`, `font-cache.js`), hunt checklist, 4 exercises, IR report template | Static review only: read `06-ghostaction-supply-chain/samples/` (don't run them outside a disposable VM) |
| 07 | [kev-hunting](./07-kev-hunting/): umbrella for the hunt packs below | See each case | detection, hunting | | 10 hunt checklists, 10 synthetic logs (+ 3 [noisy variants](./NOISY_DATA.md)), 3 in-repo detection scripts + tests | `cd 07-kev-hunting && python -m pytest tests/ -v` (in-repo detectors); see each case |

### 07 kev-hunting: hunt packs

| Case | CVE / KEV | Skills | Difficulty | Included | Verify |
|---|---|---|---|---|---|
| [Plex2Shell: Plex Media Server RCE chain](./07-kev-hunting/hunt-checklist-cve-2026-96652.md) | CVE-2026-96652 / 96654 / 96655 / 96656. **KEV: listed** | detection, hunting, triage | | Hunt checklist, [synthetic log](./07-kev-hunting/samples/plex2shell-access.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/cve-2026-96652-plex2shell-detect.py 07-kev-hunting/samples/plex2shell-access.log` |
| [Bricksforge (WordPress) unauthenticated RCE](./07-kev-hunting/hunt-checklist-cve-2026-85097.md) | CVE-2026-85097. KEV: not listed (exploited in the wild) | detection, hunting | | Hunt checklist, [synthetic log](./07-kev-hunting/samples/bricksforge-access.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/cve-2026-85097-detect.py 07-kev-hunting/samples/bricksforge-access.log` |
| [Ivanti Connect Secure welcome.cgi auth bypass → RCE](./07-kev-hunting/hunt-checklist-cve-2026-104935.md) | CVE-2026-104935. **KEV: listed** (added 2026-10-13, due 2026-10-16) | detection, hunting | | Hunt checklist, [synthetic log](./07-kev-hunting/samples/ivanti-welcome-cgi.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/cve-2026-104935-detect.py 07-kev-hunting/samples/ivanti-welcome-cgi.log` |
| [Siemens Software Center DLL sideloading (ClickFix)](./07-kev-hunting/hunt-checklist-cve-2026-110936.md) | CVE-2026-110936. **KEV: listed** (added 2026-10-20, due 2026-11-03) | detection, hunting, triage | | Hunt checklist, [synthetic Sysmon log](./07-kev-hunting/samples/siemens-sideload.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/cve-2026-110936-detect.py 07-kev-hunting/samples/siemens-sideload.log` |
| [Redis RESTORE double-free → RCE](./07-kev-hunting/hunt-checklist-cve-2026-25243.md) | CVE-2026-25243. KEV: not listed (exploited in the wild) | detection, hunting | | Hunt checklist, [synthetic audit log](./07-kev-hunting/samples/redis-restore-audit.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/cve-2026-25243-detect.py 07-kev-hunting/samples/redis-restore-audit.log` |
| [AI agent tool endpoints without auth (5 CVEs)](./07-kev-hunting/hunt-checklist-agent-tool-unauth-rce.md) | CVE-2026-77936 / 75128 / 77932 / 109442 / 109437. KEV: not listed | detection, hunting | | Hunt checklist, [synthetic proxy log](./07-kev-hunting/samples/agent-tool-unauth-rce-access.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/agent-tool-unauth-rce-detect.py 07-kev-hunting/samples/agent-tool-unauth-rce-access.log` |
| [M365 app-identity persistence (ConnectWise incident)](./07-kev-hunting/hunt-checklist-m365-app-identity-persistence.md) | No CVE, not KEV | cloud, detection, hunting, IR | | Hunt checklist, [synthetic M365 audit log](./07-kev-hunting/samples/m365-app-identity-audit.log), reference detection (soc-skills) | `python3 ../soc-skills/labs/m365-app-identity-persistence-detect.py 07-kev-hunting/samples/m365-app-identity-audit.log` |
| [Atlassian Data Center `::` path traversal](./07-kev-hunting/hunt-checklist-cve-2026-21589.md) | CVE-2026-21589. **KEV: listed** | detection, hunting | | Hunt checklist, [synthetic log](./07-kev-hunting/samples/confluence-access.log), reference detection in this repo ([`detect/`](./07-kev-hunting/detect/cve-2026-21589-log-detect.py)), plus a soc-skills version with built-in synthetic lines and a [lab card](https://github.com/szzxli/soc-skills/blob/main/labs/cve-2026-21589-atlassian-traversal.md) | `python3 07-kev-hunting/detect/cve-2026-21589-log-detect.py 07-kev-hunting/samples/confluence-access.log` (or `python3 ../soc-skills/labs/cve-2026-21589-detect.py`) |
| [Nextcloud Collabora CODE server RCE](./07-kev-hunting/hunt-checklist-cve-2026-110447.md) | CVE-2026-110447. KEV: not listed (exploited in the wild) | detection, hunting | | Hunt checklist, [synthetic log](./07-kev-hunting/samples/nextcloud-access.log), reference detection in this repo ([`detect/`](./07-kev-hunting/detect/cve-2026-110447-detect.py)), [lab card](https://github.com/szzxli/soc-skills/blob/main/labs/cve-2026-110447-nextcloud-collabora-rce.md) (soc-skills) | `python3 07-kev-hunting/detect/cve-2026-110447-detect.py 07-kev-hunting/samples/nextcloud-access.log` |
| [BeyondTrust Remote Support (RS) auth bypass (ARMORY CASTLE)](./07-kev-hunting/hunt-checklist.md) | CVE-2026-102764. **KEV: listed** | detection, hunting, IR | | Hunt checklist + exercises in the [07 README](./07-kev-hunting/README.md), [synthetic appliance log](./07-kev-hunting/samples/appliance.log), [incident-report template](./07-kev-hunting/incident-report-template.md), reference detection in this repo ([`detect/`](./07-kev-hunting/detect/cve-2026-102764-detect.py)), [lab card](https://github.com/szzxli/soc-skills/blob/main/labs/cve-2026-102764-beyondtrust-auth-bypass.md) (soc-skills) | `python3 07-kev-hunting/detect/cve-2026-102764-detect.py 07-kev-hunting/samples/appliance.log` |

### 07 kev-hunting: tracked as intel only (no lab, reason in the [07 README](./07-kev-hunting/README.md))

| Case | CVE / KEV | Why no lab (per 07 README) |
|---|---|---|
| EG Secure Solutions SiteGuard Server Edition OS command injection | CVE-2026-106931. KEV: listed | Commercial licensed WAF, no free repro environment |
| Palo Alto PAN-OS code injection | CVE-2026-0322. KEV: listed | Needs a real firewall |
| Microsoft Windows Command Injection Vulnerability | CVE-2026-96951. **KEV: listed** (added 2026-10-13, due 2026-10-16) | Windows + sample complexity |
| Cisco Secure Email Gateway path traversal | CVE-2026-76519. KEV: listed | Needs a real appliance |
| Ahsay AhsayCBS improper authentication | CVE-2026-105133. KEV: listed | Niche backup product |
| Ahsay AhsayCBS command injection | CVE-2026-105134. KEV: listed | Niche backup product |
| Fortinet multiple-products path traversal (PEERSTITCH) | CVE-2025-61624. KEV: listed | No public PoC for either trigger as of 2026-10-17 |

**KEV accuracy:** every CVE, vendor / product name, KEV date added, federal
due date and "in KEV / not in KEV" label above was checked against the official
[CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json):
last verified 2026-10-21 (catalog version 2026.10.21). Each hunt checklist
starts with its KEV status, a Sources line (CISA KEV, NVD, vendor advisory where
cited) and that date. [`tools/verify_kev.py`](./tools/verify_kev.py) re-checks
all of it, weekly and on every pull request, and opens an issue if anything
drifts. It never edits the repo itself.

**Totals:** 23 indexed entries = 6 published projects (01–06) + 10 hunt packs
in 07 (all 10 with a synthetic log *and* a runnable reference detection: 7 in
soc-skills, 3 in `07-kev-hunting/detect/`) + 7 intel-only notes.

## Case details (dates, sources, log type, prerequisites)

The same entries, with the extra facts recorded in each case's own documents.
Blank = not stated.

<details>
<summary>Show the detailed tables</summary>

| # | Project | Published / last reviewed | Threat source & evidence | KEV status | Log source & data form | How to run | Difficulty | Est. time | Prerequisites | Output | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 01 | [mini-soc](./01-mini-soc/) |  | Not applicable — adversary-emulation scenarios (Stratus Red Team), not an intel case | No CVE | CloudTrail events + GuardDuty findings generated live in your AWS account | AWS (your own account, Terraform) |  |  (a 15-minute quickstart is documented) | Your own AWS account, Terraform ≥ 1.5, AWS CLI credentials, Stratus Red Team binary | Deployed mini-SOC, triage notes, incident report | Complete lab |
| 02 | [python-ioc-analyzer](./02-python-ioc-analyzer/) |  | Not applicable — tooling project | No CVE | CloudTrail JSON (synthetic sample included) | Local script (Python) |  |  | Python 3.9+ | Markdown IOC findings report | Complete lab (tool + test suite) |
| 03 | [phishing-analysis-lab](./03-phishing-analysis-lab/) |  | Not applicable — reconstructed training sample, self-authored | No CVE | Reconstructed training-sample email (headers, auth results, URLs) | Offline (documents; optional GoPhish self-test to your own mailbox only) |  |  |  | Completed phishing analysis report (four-stage template) | Complete lab |
| 04 | [rea-triage](./04-rea-triage/) |  | Not applicable — tooling project | No CVE | ELF binaries (synthetic demo ELF generator included) | Local script (Python, pyelftools) |  |  | Python 3 + pyelftools | One-page triage report with score-based verdict | Complete lab (tool + test suite) |
| 05 | [soc-skills](./05-soc-skills/) |  | Not applicable — agent skill pack | No CVE | SKILL.md files (Markdown) | Offline (copy into an agent's skills directory) |  |  |  | Six installed agent skills | Complete |
| 06 | [ghostaction-supply-chain](./06-ghostaction-supply-chain/) | October 2026 (per 06 README) | GhostAction reporting (GBHackers, per 06 README) | No CVE | Inert `.vscode/tasks.json` + disguised JS payload samples; your own host's cron/systemd entries | Offline (static review; persistence hunt on your own Linux VM) |  | ~2 hours (exercise times as written: 15 + 45 + 30 + 30 min) | A Linux VM for the persistence hunt | Red-flag list, `tasks.json` detector, completed incident report | Complete lab |
| 07 | [kev-hunting](./07-kev-hunting/) | Oct 2026 (CISA catalog version 2026.10.21, per 07 README) | CISA KEV catalog + vendor/researcher reporting, per case below | Per case (see table below) | Synthetic sample logs in `07-kev-hunting/samples/` | Offline (samples + reference detection scripts in `07-kev-hunting/detect/` and the companion repo) |  | Per case (see table below) | Per case (see table below) | Hunt findings + incident report | Complete lab (umbrella project; per-case status below) |

| Case | Published / last reviewed | Threat source & evidence | KEV status | Log source & data form | How to run | Difficulty | Est. time | Prerequisites | Output | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-96652 / 96654 / 96655 / 96656 — Plex2Shell (Plex Media Server RCE chain) | CVEs published 2026-10-19; in the wild from 2026-10-17 (per 07 README) | Plex advisory + BoredHackerBlog honeypot (per 07 README) | Listed (added 2026-10-20, federal due 2026-10-23 / 2026-11-03) | Synthetic Plex access log (`samples/plex2shell-access.log`) | Offline (optional isolated `plexinc/pms-docker` lab, per 07 README) |  |  | Plex Media Server access logs |  | Hunt pack |
| CVE-2026-102764 — BeyondTrust Remote Support (RS) auth bypass (ARMORY CASTLE chain) | KEV Oct 2026; federal due 2026-10-19 (per 07 README) | Mandiant/GTIG reporting (per 07 README and hunt checklist) | Listed | Synthetic appliance log (`samples/appliance.log`) | Offline |  | ~2.25 hours (exercise times as written: 30 + 45 + 30 + 30 min) |  | Huntable-artifact table, hunt script, completed incident report | Hunt pack |
| CVE-2025-61624 — Fortinet multiple-products path traversal (PEERSTITCH) | KEV Oct 2026 (per 07 README) | Palo Alto Networks reporting (per 07 README) | Listed | None — no sample log | Not applicable |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-21589 — Atlassian Data Center `::` path traversal | KEV 2026-10-15; federal due 2026-10-18 | watchTowr research + Previdian honeypot reporting (per 07 README) | Listed | Synthetic Confluence access log (`samples/confluence-access.log`); the soc-skills script also has built-in synthetic lines | Offline |  |  | Web access logs for the affected Atlassian DC products (per hunt checklist) | Hunt results + incident report | Hunt pack |
| CVE-2026-110447 — Nextcloud Collabora built-in CODE Server RCE | In-the-wild exploitation Sept–Oct 2026 (per 07 README) | MITRE CVE text confirming in-the-wild exploitation (per 07 README) | Not listed | Synthetic Nextcloud access log (`samples/nextcloud-access.log`) | Offline |  |  | Nextcloud with `richdocumentscode` installed; access logs (per hunt checklist) | Hunt results + incident report | Hunt pack |
| CVE-2026-85097 — Bricksforge (WordPress) unauthenticated RCE | Exploited in the wild since 2026-10-07 (per 07 README) | Patchstack reporting (per 07 README) | Not listed | Synthetic WordPress access log (`samples/bricksforge-access.log`) | Offline |  |  | WordPress + Bricksforge install and its access logs (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-104935 — Ivanti Connect Secure welcome.cgi auth bypass → RCE | Checklist reality check dated 2026-10-19; exploited in the wild from 2026-10-03 | UTA0576 in-the-wild exploitation reporting (per 07 README) | Listed (added 2026-10-13, federal due 2026-10-16) | Synthetic welcome.cgi log, header-enriched (`samples/ivanti-welcome-cgi.log`) | Offline |  |  | Header-enriched HTTP logs — the checklist states the HTTP layer is blind without them | Hunt results + incident report | Complete lab |
| CVE-2026-110936 — Siemens Software Center DLL sideloading | Checklist reality check dated 2026-10-20; exploited in the wild Oct 2026 | Romulus ClickFix platform reporting (per 07 README) | Listed (added 2026-10-20, federal due 2026-11-03) | Synthetic Sysmon-style process/DLL log (`samples/siemens-sideload.log`) | Offline |  |  | Endpoint telemetry: Sysmon Event 1 (ProcessCreate) minimum, Event 7 (ImageLoad) for DLL evidence (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-25243 — Redis RESTORE double-free → authenticated RCE | Checklist reality check dated 2026-10-20; honeypot-observed in the wild 2026-10-16/17 | Honeypot observations of scripted in-the-wild attempts (per 07 README and hunt checklist) | Not listed | Synthetic Redis command-audit log (`samples/redis-restore-audit.log`) | Offline |  |  | A Redis command-audit feed — stock Redis does not log commands (per hunt checklist) | Hunt results + incident report | Complete lab |
| Agent tool-execution endpoints without authentication — CVE-2026-77936 (Letta) / CVE-2026-75128 (Langchain-Chatchat) / CVE-2026-77932 (DB-GPT) / CVE-2026-109442 (piflow) / CVE-2026-109437 (Cognition) | Five CVEs published 2026-10-20 (per hunt checklist) | NVD entries for the five CVEs (per hunt checklist) | Not listed (none of the five, as of 2026-10-20) | Synthetic enriched proxy access log (`samples/agent-tool-unauth-rce-access.log`) | Offline |  |  | Enriched proxy/WAF logs recording credential presence + body excerpt (per 07 README) | Hunt results + incident report | Complete lab |
| M365 app-identity persistence — ConnectWise Cloud Backup incident pattern | Incident discovered 2026-10-15; checklist facts as of 2026-10-20 | ConnectWise advisory + Huntress confirmation (per hunt checklist) | No CVE | Synthetic M365 / Entra ID audit log (`samples/m365-app-identity-audit.log`) | Offline |  |  | Entra ID audit records for role changes, app credential changes, and service-principal sign-ins, retained ≥ 90 days (per hunt checklist) | Hunt results + incident report | Complete lab |
| CVE-2026-106931 — EG Secure Solutions SiteGuard Server Edition OS command injection | KEV 2026-10-20 additions; federal due 2026-10-23 (per 07 README) | Vendor advisory alert-202610-1 (per 07 README) | Listed | None — no sample log | Not applicable (no lab: commercial licensed WAF, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-0322 — Palo Alto PAN-OS code injection | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) |  | Listed | None — no sample log | Not applicable (no lab: needs a real firewall, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-96951 — Microsoft Windows Command Injection Vulnerability | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) |  | Listed (added 2026-10-13, federal due 2026-10-16) | None — no sample log | Not applicable (no lab: Windows + sample complexity, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-76519 — Cisco Secure Email Gateway path traversal | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) |  | Listed | None — no sample log | Not applicable (no lab: needs a real appliance, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-105133 — Ahsay AhsayCBS improper authentication | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) |  | Listed | None — no sample log | Not applicable (no lab, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |
| CVE-2026-105134 — Ahsay AhsayCBS command injection | Oct 2026 (week of 10-12 → 10-18 KEV additions, per 07 README) |  | Listed | None — no sample log | Not applicable (no lab, per 07 README) |  |  |  | Intel note in the 07 README | Intel only |

</details>

## What "Verify" shows (and what it doesn't)

On 2026-10-21 each Verify command above was run against this repo's samples
with soc-skills at commit `4118685`:

- 02: 16 tests passed. 04: 10 tests passed.
- Each of the 7 sample-based reference detections exited 0 and printed exactly
  one `[INCIDENT]` for the planted attack. Most also print `[SUSPICIOUS]`
  lines for borderline benign activity that you're meant to triage.
- The Atlassian script reports `TP=4 FP=0 TN=6 FN=0` on its built-in lines.
- Re-checked 2026-10-21 on main (`b43ec3c`): the 3 in-repo detections in
  `07-kev-hunting/detect/` each exited 0 and printed exactly one `[INCIDENT]`
  on their sample (plus `[SUSPICIOUS]` / `[RECON]` lines to triage), and
  `07-kev-hunting/tests/` passed (6 tests).

- Noisy variants (added 2026-10-21): on the three noisy 07 logs the in-repo
  detectors raise 4 true and 2 false `[INCIDENT]` verdicts and miss 2
  incidents; on the noisy CloudTrail log the 02 heuristics give 8 TP / 23 FP
  findings and 1 FN. All on purpose, explained with tuning hints in
  [NOISY_DATA.md](./NOISY_DATA.md).

**Read this honestly:** passing on a synthetic fixture shows that the script
and the fixture agree. It doesn't show the detection works on real telemetry.
Treat every reference detection as a starting point to tune against your own
logs, not as a production rule.

---

Back to the [README](./README.md) · Website: <https://szzxli.github.io/soc-home-lab/web/>

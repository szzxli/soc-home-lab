# Incident Report Template — 07 kev-hunting

> **FILLING GUIDE — read before you write.** Copy this file (e.g.
> `reports/IR-2026-NNN.md`) and fill it; keep the blank template untouched.
> Each section has *italic* guidance — delete it as you fill. Write for a
> reader who was not in the room. Facts first, opinions labeled. If you do not
> know something, write "Unknown" and say how you would find out.
>
> **Where the README exercises land:**
> Exercise 1 → §1.2 (huntable-artifact table) · Exercise 3 → §3.2 (allowlist
> decisions) · Exercise 4 → the whole report.
>
> **Honesty rule for this lab:** the `samples/` logs are synthetic. A report
> written from them is a *training* report — label it so. Never present it as
> a production incident.

---

# Incident Report: [SHORT TITLE]

| Field | Value |
|---|---|
| Report ID | `IR-YYYY-NNN` |
| Status | Open / Contained / Eradicated / Closed |
| Severity | P1 / P2 / P3 / P4 — *justify in §1.3* |
| Related CVE / KEV entry | CVE-YYYY-NNNNN — KEV added YYYY-MM-DD, federal due YYYY-MM-DD (or "not in KEV") |
| Date detected (UTC) | YYYY-MM-DD HH:MM |
| Date opened / closed | YYYY-MM-DD / YYYY-MM-DD (or "Open") |
| Author / role | |
| Escalated to | *name/team + time, or "not escalated" + why* |
| Data source | Production / Lab VM / **Synthetic sample (`samples/<file>`)** |

## 1. Summary

### 1.1 Executive summary
*2–4 sentences: what happened, what was affected, current state. A manager
should be able to read only this paragraph.*

### 1.2 Huntable artifacts (intel extraction)
*One row per artifact extracted from public reporting (advisory, vendor blog,
KEV entry, researcher writeup). This table drives the hunt.*

| # | Artifact | Log source | Example value (from intel or sample) | Found? (Y/N, line/ref) |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

### 1.3 Severity call

| Level | Use when |
|---|---|
| **P1 — Critical** | Confirmed compromise of an internet-facing or privileged system (code execution, persistence, credential theft), or ≥2 correlated artifact types on one host |
| **P2 — High** | Confirmed exploitation attempt that reached the vulnerable code path (e.g. 200 on a sensitive path) but no confirmed foothold yet |
| **P3 — Medium** | Hostile recon / probing only (all 4xx, no follow-on), vulnerable version present |
| **P4 — Low** | Probing against a patched or out-of-scope asset; informational |

*Chosen level + one or two sentences justifying it against the table. If you
downgraded from the table's answer, say why.*

## 2. Detection source & timeline

### 2.1 Detection source
- **How it was found:** hunt (KEV-driven) / SIEM alert / EDR / WAF / user report / third-party notification
- **Rule or script:** *name + version/commit of the detector that fired*
- **Log sources consulted:** *list each, with retention window — note any gaps*
- **Log integrity:** *were there sequence gaps, rotations, or missing windows? If yes,
  state that every count in this report is a lower bound.*

### 2.2 Timeline
*One row per event, UTC, oldest first. Include attacker activity AND your
response actions. Every row needs evidence.*

| Time (UTC) | Host / asset | Event | Evidence (log file + line, event ID) | Actor (attacker / analyst / system) |
|---|---|---|---|---|
| YYYY-MM-DD HH:MM:SS | | | | |

- **Dwell time:** first attacker activity → detection = *N h*
- **Time to contain:** detection → containment = *N h*

## 3. Detection logic & allowlist decisions

### 3.1 Heuristic
*What the detector keys on and the correlation rule (e.g. "≥2 distinct artifact
types on one host within 24h → incident"). Link the script.*

### 3.2 Allowlist / tuning decisions
*Every suppression needs a reason a reviewer can check. "It was noisy" is not a
reason.*

| Suppressed activity | Rule (what exactly is allowlisted) | Why it is safe | Evidence / ticket | Review date |
|---|---|---|---|---|
| | | | | |

### 3.3 Detection results
| Metric | Value |
|---|---|
| True positives | |
| False positives (before / after tuning) | |
| Known blind spots | *e.g. needs header-enriched logs; in-memory only stages* |

## 4. Affected assets & scope

### 4.1 Affected assets
| Asset (hostname / IP) | Role | Exposure (internet / internal) | Product + version | Vulnerable? | Compromise state (none / probed / exploited / persistence) |
|---|---|---|---|---|---|
| | | | | | |

### 4.2 Scope
- **In scope / confirmed affected:** *hosts, accounts, data*
- **Confirmed NOT affected (and how you know):** *stating negative scope matters as much as positive*
- **Data exposure:** confirmed accessed / possibly exposed / none — *which files, secrets, records*
- **Credentials at risk:** *every secret readable by the compromised process/user*
- **Lateral movement:** *evidence for/against, and what you checked*

## 5. Indicators of compromise (IOCs)

*Defanged where clickable (`198.51.100[.]23`, `hxxp://`). Mark each with
confidence and whether it is from intel or observed in your logs.*

| Type | Value | First seen (UTC) | Last seen (UTC) | Source (intel / observed) | Confidence | Notes |
|---|---|---|---|---|---|---|
| IP | | | | | | |
| URL path / request pattern | | | | | | |
| File path / hash | | | | | | |
| Account | | | | | | |
| Process / service / listener | | | | | | |

- **Shared to:** *threat-intel platform / blocklist / ISAC — or "not shared" + why*

## 6. Response

### 6.1 Containment
*What you did to stop the bleeding, in order, with timestamps. e.g. isolate the
appliance from the network, block source IPs at the edge, disable the abused
account, take the vulnerable service offline. Preserve evidence first (memory,
disk, logs) where the box allows it.*

| Time (UTC) | Action | Performed by | Verified by |
|---|---|---|---|
| | | | |

### 6.2 Eradication
*Remove every foothold. For KEV cases: **patching does not remove an existing
web shell, SUID binary, planted codec, or added credential** — enumerate and
remove each persistence artifact, then rotate every credential in §4.2.*

- [ ] Persistence artifacts removed (list each)
- [ ] All at-risk credentials / secrets / tokens rotated
- [ ] Vulnerable component patched to fixed version (state version) or removed
- [ ] Re-ran the hunt/detector after eradication — zero hits

### 6.3 Recovery
*How systems returned to service: rebuilt from known-good image / restored
from backup / re-enabled after verification. State the verification that
proved it safe and the monitoring period.*

- **Rebuild / restore method:**
- **Verification:**
- **Enhanced monitoring until:** YYYY-MM-DD

## 7. Lessons learned

- **What worked (keep doing):**
- **What failed or was missing (fix):**
- **Detection gaps found:**
- **Patch / KEV process:** *time from KEV publication → patch on this asset; was the federal due date met?*

| Action item | Owner | Due | Status |
|---|---|---|---|
| | | YYYY-MM-DD | Open |

## Appendix
- *Raw log excerpts (with file + line numbers), commands run, detector output.*
- *Links: advisory, KEV entry, soc-skills lab card.*

# Phishing Analysis Report Template

> Fill in every section from the actual evidence in front of you. Do not invent details to complete a section — if a field is unknown, write `UNKNOWN` and say why. A blank or honest "unknown" is always better than a fabricated IOC.

---

## 1. Metadata

| Field | How to fill (one line each) |
|---|---|
| Report ID | `RPT-YYYY-NNN` — your own sequential numbering, e.g. `RPT-2026-014` |
| Analyst | Your name / handle |
| Date analyzed | `YYYY-MM-DD`, timezone noted |
| Source of sample | Where the email came from: user report, gateway quarantine, self-test (GoPhish), etc. **Never claim a real incident you didn't work.** |
| Sample provenance | Real user-reported phish / GoPhish self-test / reconstructed training sample (label it honestly) |
| Original `.eml` retained | Yes/No + storage location (retain for real cases; training samples may omit) |

## 2. Headers Summary

| Field | How to fill (one line each) |
|---|---|
| `From` (display + address) | Copy verbatim, e.g. `"IT Helpdesk" <it-helpdesk@corp-portal.example>` |
| `Reply-To` | Copy verbatim, or `none` |
| `Return-Path` | Copy verbatim — this is the envelope sender SPF checks |
| `Subject` | Copy verbatim |
| `Date` (header) vs first `Received` | Note any skew between claimed send time and actual receipt |
| `Received` chain (bottom-up) | List hops oldest→newest with IPs; flag the first external hop |
| `Message-ID` | Copy verbatim; note if missing/malformed |
| Sender-identity assessment | State whether envelope / From / Reply-To align or mismatch, in one sentence |

## 3. Authentication Results

Paste the `Authentication-Results` header verbatim, then fill:

| Check | Result | Interpretation (one line) |
|---|---|---|
| SPF | `pass` / `fail` / `softfail` / `none` | What was checked (envelope domain + IP) and what the result means here |
| DKIM | `pass` / `fail` / `none` | Which `d=` domain was checked; `fail` = tamper/forgery, `none` = neutral |
| DMARC | `pass` / `fail` / `none` (+ policy `p=`) | Whether auth aligned with the `From` domain; note `p=reject`/`quarantine`/`none` |
| Composite auth verdict | One line: e.g. "Triple fail against p=reject — domain owner disowns this mail" |

## 4. URLs & IOCs

One row per URL found (body links, attachment-extracted links). Decode/expand each to its final destination before listing.

| # | As displayed to user | Raw href | Decoded / expanded final destination | Registrable domain | Notes (shortener? encoding layers? lookalike?) |
|---|---|---|---|---|---|
| 1 | _e.g. link text or button label_ | _verbatim href_ | _final landing URL_ | _e.g. evil-cdn.example_ | _e.g. Base64-in-path, 2 redirect hops_ |

**Network IOCs** (deduplicated):

| Type | Value | First seen in |
|---|---|---|
| Domain | _e.g. login.corp-portal.example_ | URL #1 landing page |
| IP | _use real observed IPs only_ | _e.g. Received hop 1_ |
| URL | _full malicious URL_ | _e.g. attachment form action_ |

**File IOCs** (if attachments present):

| Filename | SHA-256 | MD5 | Sandbox verdict | Notes |
|---|---|---|---|---|
| _e.g. Invoice.html_ | _hash_ | _hash_ | _e.g. Any.Run: malicious / clean_ | _e.g. contains credential form posting off-domain_ |

## 5. Verdict

| Field | How to fill (one line each) |
|---|---|
| Verdict | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `INCONCLUSIVE` — pick one |
| Category | Credential harvesting / malware delivery / BEC / sextortion / other |
| Severity | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` — with one-line justification |
| Confidence | `High` / `Medium` / `Low` — and what would raise or lower it |
| Key evidence (bullets) | The 3–5 strongest signals, each one line (e.g. "DMARC fail vs p=reject", "Reply-To diverts to attacker domain") |
| Exculpatory evidence | Anything pointing away from malice, or `none found` — do not skip this field |

## 6. Recommended Actions

Check off what applies; assign owner + deadline for real incidents.

- [ ] **Reporter containment:** confirm no click / no credentials entered; if compromised → password reset + session revocation, escalate to account-takeover playbook
- [ ] **Evidence preserved:** original `.eml` with full headers saved to case storage
- [ ] **Blast-radius hunt:** search mail gateway for same sender domain / URL / attachment hash; list additional recipients
- [ ] **Blocks requested:** malicious domains + file hashes submitted to gateway / EDR / DNS filtering
- [ ] **Threat intel:** IOCs shared to internal feed; domain reported to impersonated brand's abuse contact if applicable
- [ ] **Reporter notified:** outcome communicated back to the person who reported it
- [ ] **Awareness follow-up:** pattern logged for security-awareness team (e.g. new lure theme this week)
- [ ] **Escalation:** Tier-2 / IR engaged if compromise confirmed or campaign is widespread — note ticket ID

---

*Repository: https://github.com/szzxli/soc-home-lab — project `03-phishing-analysis-lab`.*
*This template ships blank by design. Pre-filling it with a fabricated case would be dishonest — fill it only from real evidence.*

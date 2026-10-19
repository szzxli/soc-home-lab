# Phishing Analysis Report Template

> Fill in every section from the actual evidence in front of you. Do not invent details to complete a section — if a field is unknown, write `UNKNOWN` and say why. A blank or honest "unknown" is always better than a fabricated IOC.

## How this report works (four stages)

This template follows one rule: **technical evidence first, judgment second.**

1. **Stage 1 — Email forensics.** Extract everything observable from the raw message itself: metadata, headers, authentication results, URLs, attachments. No verdicts here — only evidence.
2. **Stage 2 — Threat-intel enrichment.** Take the IOCs from Stage 1 and check them against reputation sources. Record what was checked, when, and what came back — including "not checked" and "unknown".
3. **Stage 3 — Assisted reasoning.** Reason over the structured evidence from Stages 1–2 (by hand, or with an LLM as a *supporting* tool). Technical evidence outweighs heuristics; exculpatory evidence must be considered.
4. **Stage 4 — Explainable verdict.** Show the verdict *and* how you got there: every signal, its contribution, and what was skipped. Anyone reading this report should be able to re-derive your verdict.

Work the stages in order. Never let a later stage invent evidence the earlier stages didn't produce.

---

## STAGE 1 — Email forensics

**Input:** the raw message (`.eml` preferred; pasted "show original" source accepted — note which you used).
**Output:** a complete, structured evidence inventory. No conclusions yet.

### 1.1 Metadata

| Field | How to fill (one line each) |
|---|---|
| Report ID | `RPT-YYYY-NNN` — your own sequential numbering, e.g. `RPT-2026-014` |
| Analyst | Your name / handle |
| Date analyzed | `YYYY-MM-DD`, timezone noted |
| Source of sample | Where the email came from: user report, gateway quarantine, self-test (GoPhish), etc. **Never claim a real incident you didn't work.** |
| Sample provenance | Real user-reported phish / GoPhish self-test / reconstructed training sample (label it honestly) |
| Original `.eml` retained | Yes/No + storage location (retain for real cases; training samples may omit) |
| Input completeness | Full `.eml` / headers-only / body-only — note what is missing, because missing input limits later stages |

### 1.2 Header analysis

| Field | How to fill (one line each) |
|---|---|
| `From` (display + address) | Copy verbatim, e.g. `"IT Helpdesk" <it-helpdesk@corp-portal.example>` |
| `Reply-To` | Copy verbatim, or `none` |
| `Return-Path` | Copy verbatim — this is the envelope sender SPF checks |
| `Subject` | Copy verbatim |
| `Date` (header) vs first `Received` | Note any skew between claimed send time and actual receipt |
| `Received` chain (bottom-up) | List hops oldest→newest with IPs; flag the first external hop |
| `Message-ID` | Copy verbatim; note if missing/malformed |
| Display-name spoofing | Does the display name impersonate a known brand/person while the address differs? State plainly |
| Lookalike domains | Check sender and link domains for typosquats/homoglyphs (e.g. `paypa1`, `micros0ft`); note method used |
| Sender-identity assessment | State whether envelope / From / Reply-To align or mismatch, in one sentence |

### 1.3 Authentication results

Paste the `Authentication-Results` header verbatim, then fill:

| Check | Result | Interpretation (one line) |
|---|---|---|
| SPF | `pass` / `fail` / `softfail` / `none` / `unknown` | What was checked (envelope domain + IP) and what the result means here |
| DKIM | `pass` / `fail` / `none` / `unknown` | Which `d=` domain was checked; `fail` = tamper/forgery, `none` = neutral |
| DMARC | `pass` / `fail` / `none` / `unknown` (+ policy `p=`) | Whether auth aligned with the `From` domain; note `p=reject`/`quarantine`/`none` |
| Composite auth verdict | One line: e.g. "Triple fail against p=reject — domain owner disowns this mail" | |

> If you only have body text without headers, mark all three `unknown` here — do not guess. The report must show the gap.

### 1.4 URL & attachment extraction

One row per URL found (body links, attachment-extracted links, QR-decoded URLs). Decode/expand each to its final destination before listing.

| # | As displayed to user | Raw href | Decoded / expanded final destination | Registrable domain | Notes (shortener? encoding layers? lookalike? `http://`?) |
|---|---|---|---|---|---|
| 1 | _e.g. link text or button label_ | _verbatim href_ | _final landing URL_ | _e.g. evil-cdn.example_ | _e.g. Base64-in-path, 2 redirect hops_ |

**Deceptive-link check:** for each URL, state whether visible text matches the actual `href`. A mismatch is its own signal.

**QR codes:** if the email contains QR images, decode them and list the hidden URLs above with source `qr`. If you cannot decode, write `QR present — not decoded` rather than ignoring it.

**File IOCs** (if attachments present):

| Filename | SHA-256 | MD5 | Notes |
|---|---|---|---|
| _e.g. Invoice.html_ | _hash_ | _hash_ | _e.g. contains credential form posting off-domain_ |

### 1.5 Evidence inventory (Stage 1 output)

Summarize everything Stage 1 produced. This is the structured evidence Stages 2–3 will work from — nothing may be added later without returning here first.

| # | Evidence item | Value / finding | Source section |
|---|---|---|---|
| E1 | _e.g. SPF result_ | _fail_ | 1.3 |
| E2 | _e.g. Reply-To mismatch_ | _replies go to attacker domain_ | 1.2 |
| E3 | _e.g. Decoded URL_ | _final landing URL_ | 1.4 |

---

## STAGE 2 — Threat-intel enrichment

**Input:** the IOCs from Stage 1 (domains, IPs, URLs, file hashes).
**Output:** reputation results with source and timestamp. "Unknown" and "not checked" are valid, honest results.

| IOC | Source checked | Result | Checked at (UTC) | Notes |
|---|---|---|---|---|
| _e.g. evil-cdn.example_ | _e.g. VirusTotal_ | _e.g. 12/70 malicious_ | _timestamp_ | _first-seen date if available_ |
| _e.g. SHA-256_ | _not checked_ | — | — | _reason: no sandbox access in this lab_ |

**Rules for this stage:**

- Check IOCs, never the full email body, against external sources. Do not paste credentials, PII, or internal hostnames into third-party services.
- A brand-new phishing URL may simply be **unknown** to reputation sources. Absence of a hit is not evidence of clean — write `unknown`, not `clean`.
- Record rate limits, cache hits, and API failures. If a source was unavailable, the report must say so in Stage 4's provenance footer.

---

## STAGE 3 — Assisted reasoning

**Input:** the structured evidence from Stages 1–2. Nothing else.
**Output:** a written reasoning trace and a confidence statement.

### 3.1 Reasoning notes

Write 3–6 short paragraphs or bullets explaining *how the evidence fits together*:

- Which signals corroborate each other (e.g. auth failure + Reply-To diversion + lookalike domain all point the same way).
- What the most likely attacker objective is, given the lure and the payload.
- **Exculpatory evidence:** anything pointing away from malice — do not skip this. If none found, write `none found` and say what you checked.

### 3.2 If an LLM assisted

| Field | How to fill |
|---|---|
| Model / tool | Name and version (or `manual analysis only` if no LLM was used) |
| What was sent to it | e.g. "signal list + redacted body text" — never raw credentials, PII, or internal hostnames |
| Role in this report | `Supporting only` — the LLM explains and suggests; it does not decide. Technical evidence (Stages 1–2) always outranks model output. |
| Disagreement | If the model disagreed with your read, note it and say which evidence settled it |

> Heuristic signals (lure tone, "AI-generated text" guesses, urgency language) are inherently unreliable. They may support a verdict but can never decide one alone.

### 3.3 Confidence

| Field | How to fill (one line each) |
|---|---|
| Confidence | `High` / `Medium` / `Low` |
| What would raise it | e.g. "sandbox detonation of the attachment", "reputation hit on the landing domain" |
| What would lower it | e.g. "legitimate sender confirms they sent this", "DKIM pass on the From domain" |

---

## STAGE 4 — Explainable verdict & actions

**Input:** everything above.
**Output:** a verdict any reader can re-derive from the signal table.

### 4.1 Signal contributions

List every signal that fed the verdict, with its weight. No single signal decides — the verdict comes from the stack.

| # | Signal | Finding | Contribution | Running note |
|---|---|---|---|---|
| S1 | _e.g. SPF_ | _fail_ | _strong_ | — |
| S2 | _e.g. DMARC_ | _fail vs p=reject_ | _strong_ | — |
| S3 | _e.g. Reply-To mismatch_ | _diverts to attacker domain_ | _medium_ | — |
| S4 | _e.g. Reputation hit_ | _12/70 on VT_ | _strong_ | — |
| S5 | _e.g. Lure tone_ | _urgent "act in 24h"_ | _weak (supporting only)_ | — |

Contribution scale: `strong` (decisive technical evidence) / `medium` (corroborating) / `weak` (heuristic, supporting only).

### 4.2 Verdict

| Field | How to fill (one line each) |
|---|---|
| Verdict | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `INCONCLUSIVE` — pick one, and point at the signal rows above that justify it |
| Category | Credential harvesting / malware delivery / BEC / sextortion / QR-code phishing (quishing) / other |
| Severity | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` — with one-line justification |
| Key evidence (bullets) | The 3–5 strongest signals, each one line, referencing signal numbers (e.g. "S2: DMARC fail vs p=reject") |
| Exculpatory evidence | Anything pointing away from malice, or `none found` — do not skip this field |

### 4.3 Recommended actions

Check off what applies; assign owner + deadline for real incidents.

- [ ] **Reporter containment:** confirm no click / no credentials entered; if compromised → password reset + session revocation, escalate to account-takeover playbook
- [ ] **Evidence preserved:** original `.eml` with full headers saved to case storage
- [ ] **Blast-radius hunt:** search mail gateway for same sender domain / URL / attachment hash; list additional recipients
- [ ] **Blocks requested:** malicious domains + file hashes submitted to gateway / EDR / DNS filtering
- [ ] **Threat intel:** IOCs shared to internal feed; domain reported to impersonated brand's abuse contact if applicable
- [ ] **Reporter notified:** outcome communicated back to the person who reported it
- [ ] **Awareness follow-up:** pattern logged for security-awareness team (e.g. new lure theme this week)
- [ ] **Escalation:** Tier-2 / IR engaged if compromise confirmed or campaign is widespread — note ticket ID

### 4.4 Evidence provenance (footer — always fill)

| Check | Status |
|---|---|
| Full `.eml` available | Yes / No (if No, Stage 1.3 auth results are `unknown` by construction) |
| Reputation sources consulted | _list, or `none — Stage 2 skipped, verdict rests on Stage 1 alone`_ |
| LLM assistance | _model name, or `manual analysis only`_ |
| Checks skipped / unavailable | _list anything from Stages 1–3 that could not run, with reason_ |

---

*Repository: https://github.com/szzxli/soc-home-lab — project `03-phishing-analysis-lab`.*
*This template ships blank by design. Pre-filling it with a fabricated case would be dishonest — fill it only from real evidence.*
*Method: technical evidence first (Stage 1), enrichment second (Stage 2), reasoning over structured evidence (Stage 3), and a verdict anyone can re-derive (Stage 4).*

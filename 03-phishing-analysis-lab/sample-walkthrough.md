# Phishing Email Walkthrough: Reconstructed Training Sample

> **RECONSTRUCTED TRAINING SAMPLE — not a real phish received.**
> This entire email is a fictional training artifact I built for this lab. I did not receive this email,
> I did not analyze a real phishing email from any employer, and every identifier below is fabricated.
> Hosts use `example`-style placeholder domains (per RFC 2606-style practice) and IP addresses come from
> the `192.0.2.0/24` TEST-NET-1 block (RFC 5737), which can never appear in a real delivered email.

---

## 1. Sample Provenance

| Field | Value |
|---|---|
| Sample ID | `SAMPLE-2026-001` (self-assigned, no external case number) |
| Source | **Authored by me** for this lab as a reconstructed training sample |
| Original raw `.eml` | Not retained — sample is illustrative, not evidentiary |
| Scenario | Credential-harvesting lure themed as a "password expires in 24 hours" IT notice |
| Status | Fictional. Never sent, never received. |

> Why reconstructed instead of a real sample? I had no access to a real corporate phishing mailbox.
> Fabricating a "I analyzed this at my last job" story would be dishonest. Building the sample myself
> still lets me demonstrate the full analysis workflow end-to-end.

---

## 2. Header Analysis

Below is the (fictional) raw header block of the sample:

```
Return-Path: <mailer-daemon@evil-cdn.example>
Delivered-To: analyst.training@example.org
Received: from mailfilter.example.net (mailfilter.example.net [192.0.2.10])
    by mx.example.org with ESMTP id 4f2a9c1d
    for <analyst.training@example.org>; Mon, 12 Oct 2026 09:14:22 -0700 (PDT)
Received: from bounce.evil-cdn.example (bounce.evil-cdn.example [192.0.2.66])
    by mailfilter.example.net with ESMTP id 7b11e0aa
    for <analyst.training@example.org>; Mon, 12 Oct 2026 09:13:58 -0700 (PDT)
Message-ID: <20261012091358.7b11e0aa@bounce.evil-cdn.example>
From: "IT Helpdesk" <it-helpdesk@corp-portal.example>
Reply-To: support@evil-cdn.example
To: <analyst.training@example.org>
Subject: Action required: your password expires in 24 hours
Date: Mon, 12 Oct 2026 09:13:58 -0700 (PDT)
```

### 2.1 Received chain (read bottom-up — the first hop is the oldest)

| Hop | What it says | What I check |
|---|---|---|
| `bounce.evil-cdn.example [192.0.2.66]` → `mailfilter.example.net` | The message entered my fictional receiving infrastructure from a host claiming the domain `evil-cdn.example`. | Does this domain match the visible `From` domain (`corp-portal.example`)? **No.** Legitimate IT notices come from the organization's own domain, not a random "CDN" domain. Mismatch = first red flag. |
| `mailfilter.example.net [192.0.2.10]` → `mx.example.org` | Handoff between my fictional filter and mailbox servers. | In a real case I would compare these IPs against the org's MX records. Here they are placeholders for the receiving side. |
| Timestamps | Two `Received` stamps 24 seconds apart (`09:13:58` → `09:14:22`). | Consistent with a single direct hop through one filter — no weird delays or multi-country bouncing. Timing is clean; the *origin domain* is the problem, not the routing. |

### 2.2 Return-Path, From, Reply-To

- **`Return-Path: <mailer-daemon@evil-cdn.example>`** — This is the *envelope* sender (where bounces go), and it is also the domain SPF authenticates against. It belongs to `evil-cdn.example`, not `corp-portal.example`.
- **`From: "IT Helpdesk" <it-helpdesk@corp-portal.example>`** — The *display* identity the user sees. It impersonates an internal IT identity on a plausible internal domain.
- **`Reply-To: support@evil-cdn.example`** — If the recipient hits "Reply", the response goes to the attacker's domain, not the displayed sender.

**Verdict of this section:** Classic **sender-identity mismatch** — envelope (`evil-cdn.example`) ≠ header From (`corp-portal.example`) ≠ Reply-To (`evil-cdn.example`). This is the pattern of a forged `From` header with no domain alignment. Alone this is enough to classify the sample as malicious, and it predicts the SPF/DMARC failures in the next section.

### 2.3 Message-ID

`<20261012091358.7b11e0aa@bounce.evil-cdn.example>` — The right-hand side matches the sending host, which is normal for any MTA. The Message-ID itself isn't a strong signal here (attackers can generate valid-looking ones), so I note it and move on.

---

## 3. SPF / DKIM / DMARC Interpretation

Fictional `Authentication-Results` header, as my sample would arrive at the receiving filter:

```
Authentication-Results: mailfilter.example.net;
    spf=fail (sender IP 192.0.2.66) smtp.mailfrom=bounce.evil-cdn.example;
    dkim=fail (signature verification failed) header.d=corp-portal.example;
    dmarc=fail (p=reject) header.from=corp-portal.example;
```

Line-by-line explanation:

1. **`spf=fail ... smtp.mailfrom=bounce.evil-cdn.example`**
   - SPF checks whether the sending IP (`192.0.2.66`) is authorized by the *envelope* domain (`bounce.evil-cdn.example`, from `Return-Path`).
   - `fail` = the IP is not in the domain's published SPF record.
   - **Caveat I always note:** SPF failure alone is not proof of malice — forwarded mail and misconfigured records break SPF legitimately. It is *one* signal.

2. **`dkim=fail (signature verification failed) header.d=corp-portal.example`**
   - DKIM checks a cryptographic signature over the message body/headers, tied to the signing domain (`d=corp-portal.example`).
   - `fail` = the signature did not verify — either the message was tampered with in transit, or (more likely here) someone signed with a key for `corp-portal.example` that isn't valid — i.e., the signature is forged or the attacker DKIM-signed from their own infrastructure and set `d=` to the impersonated domain.
   - **Caveat:** A `none` result (no signature at all) is common for small legitimate senders; a hard `fail` is stronger evidence than `none`.

3. **`dmarc=fail (p=reject) header.from=corp-portal.example`**
   - DMARC is the policy layer: it checks **alignment** (does the authenticated domain match the `From` domain?) plus pass/fail of SPF *or* DKIM.
   - SPF authenticated `evil-cdn.example` — not aligned with `From: corp-portal.example`.
   - DKIM `d=corp-portal.example` failed outright.
   - So DMARC fails. `p=reject` means the *real* `corp-portal.example` published a strict policy telling receivers to reject unauthenticated mail using its domain — the filter should have rejected this message at the gate.
   - This is the strongest line of the three: **the legitimate domain owner explicitly told the world "reject forgeries of my domain," and this message is exactly that.**

---

## 4. URL Analysis: Multi-Layer Deobfuscation

The sample's HTML body contains this link (display text: "Reset your password now"):

```
https://secure-login.example.net/aHR0cHM6Ly9sb2dpbi5jb3JwLXBvcnRhbC5leGFtcGxlL3Zvcm0%3D
```

### Step 1 — Recognize the structure

The path segment `aHR0cHM6Ly9sb2dpbi5jb3JwLXBvcnRhbC5leGFtcGxlL3Zvcm0%3D` looks like Base64 (trailing `%3D` = URL-encoded `=` padding). Hypothesis: the link encodes a *second* URL inside the path.

### Step 2 — URL-decode, then Base64-decode

Method (what I would actually run; shown here against the fictional string):

```bash
# 1) URL-decode the path
python3 -c "import urllib.parse; print(urllib.parse.unquote('aHR0cHM6Ly9sb2dpbi5jb3JwLXBvcnRhbC5leGFtcGxlL3Zvcm0%3D'))"
# -> aHR0cHM6Ly9sb2dpbi5jb3JwLXBvcnRhbC5leGFtcGxlL3Zvcm0=

# 2) Base64-decode the result
python3 -c "import base64; print(base64.b64decode('aHR0cHM6Ly9sb2dpbi5jb3JwLXBvcnRhbC5leGFtcGxlL3Zvcm0=').decode())"
# -> https://login.corp-portal.example/form
```

**Decoded target:** `https://login.corp-portal.example/form`

### Step 3 — Analyze the decoded destination

- `login.corp-portal.example` — a subdomain of the *impersonated* brand. This is the **subdomain trick**: the attacker registers `corp-portal.example` (a lookalike they control) and puts `login.` in front to look official. The registrable domain is `corp-portal.example`, which has nothing to do with the real organization.
- In a real investigation I would then:
  - `curl -I https://login.corp-portal.example/form` (or safer: `curl -sI --max-time 10`) to inspect redirects **without** rendering the page — never open a suspected phish in a normal browser.
  - Submit the URL to **urlscan.io** for an automated sandboxed browse and screenshot/DOM capture.
  - Check the domain's WHOIS age (domains registered in the last 30 days are a strong phish indicator) and its hosting IP reputation via VirusTotal.
  - Never enter credentials, never download "required" files.

### Step 4 — Short-link / redirector expansion logic (pattern, not this sample)

If the sample had used a shortener (e.g. `https://tiny-redirect.example/abc123`), the playbook is:

```bash
curl -sI -L --max-redirs 5 --max-time 15 'https://tiny-redirect.example/abc123' | grep -i '^location:'
```

Each `Location:` hop is recorded as a layer of the chain until the final landing page. This documents the **redirector chain** — attackers use shorteners and open-redirects specifically to defeat naive blocklists.

**Layer summary for this sample:**

| Layer | Value | How revealed |
|---|---|---|
| What the user sees | `secure-login.example.net` (in link text/context) | Email body |
| Actual href host | `secure-login.example.net` | Inspect raw href — here href == displayed host, the deception is in the path |
| Encoded payload | Base64 blob | `%3D` padding + charset analysis |
| Decoded destination | `https://login.corp-portal.example/form` | `urllib.parse.unquote` → `base64.b64decode` |
| Registrable domain | `corp-portal.example` | Mentally strip subdomains; verify via WHOIS in a real case |

---

## 5. Attachment IOC Extraction

Assume the sample carries an attachment: **`Password-Reset-Instructions.html`** (fictional).

### 5.1 Extraction approach

```bash
# Save the attachment from the .eml without executing anything
# then fingerprint it:
sha256sum Password-Reset-Instructions.html
md5sum    Password-Reset-Instructions.html
```

Why hashes: a hash is the IOC I can pivot on — I can search it in VirusTotal, MalwareBazaar, or the org's EDR to find **other endpoints or mailboxes that saw the same file**. I treat the hash as an identifier, not as a verdict.

Next, extract embedded URLs without rendering:

```bash
grep -oiE 'https?://[^"'"'"' <>]+' Password-Reset-Instructions.html | sort -u
```

Each unique URL/host becomes an additional network IOC. I also scan for suspicious patterns: `<form action=...>` pointing off-domain, obfuscated JavaScript (`eval(unescape(...))`, long Base64 blobs), and `<meta http-equiv="refresh">` redirect tags — the classic **HTML smuggling** toolkit.

### 5.2 Sandbox submission recommendation

- **Do not open the HTML attachment on a workstation.** An HTML "document" can redirect to a credential page or exploit the browser.
- Submit to a sandbox: **Any.Run**, **Joe Sandbox**, or the org's internal detonation environment; or run urlscan.io against extracted URLs.
- Record in the report: file hash (SHA-256), sandbox verdict, screenshots of the rendered page, and any C2/contacted hosts observed during detonation.

### 5.3 What I'd pivot on (real case)

File hash → other recipients of the same file (mailbox search) → embedded URLs/domains → domain registration age and infrastructure overlap → campaign clustering.

---

## 6. Verdict & Severity Rating

**Verdict: MALICIOUS — credential-harvesting phishing.**

| Signal | Weight |
|---|---|
| Sender-identity mismatch (envelope `evil-cdn.example` vs `From` `corp-portal.example`, off-domain Reply-To) | High |
| SPF fail + DKIM fail + DMARC fail against a `p=reject` policy | High — domain owner explicitly disowns this mail |
| Multi-layer URL obfuscation (URL-encoded Base64 redirecting to lookalike domain) | High — deliberate evasion |
| Urgency social engineering ("expires in 24 hours") | Medium — supports the lure, not proof alone |
| HTML attachment with form/redirect capability | Medium — assumed per scenario |

**Severity: HIGH.** Credential theft against corporate accounts is an account-takeover risk with lateral-movement potential. Not CRITICAL only because this is a single-user lure with no evidence (in the fictional scenario) of successful compromise or malware execution.

Confidence: **High** — multiple independent signals (auth, headers, URL) all point the same direction. No exculpatory evidence.

---

## 7. What I'd Do in a SOC (Tier-1 Response)

If this arrived as a user-reported phish or a gateway alert, my Tier-1 playbook:

1. **Triage & contain the reporter (0–5 min).** Confirm the user did not click or enter credentials. If they did: immediate password reset + session revocation, escalate to Tier-2 for account-takeover review.
2. **Preserve evidence.** Pull the original message with full headers from the mail gateway / quarantine; save as `.eml`. Do not forward the live phish to colleagues.
3. **Extract IOCs.** Sender IP (`192.0.2.66` in this fictional sample), envelope/header domains, decoded landing URL, attachment hashes. Document per this walkthrough.
4. **Search for blast radius.** Hunt the same sender domain, URL, and attachment hash across the mail gateway logs: *who else received it? who clicked?* Report the recipient list up.
5. **Block & share.** Request gateway/EDR blocks on the malicious domain(s) and file hash; submit the URL to the org's threat-intel feed; report the domain to the impersonated brand's abuse contact if applicable.
6. **Close the loop.** File the phishing report (using this project's `report-template.md`), notify the reporter of the outcome, and log the campaign pattern for the awareness team.

---

*Repository: https://github.com/szzxli/soc-home-lab — project `03-phishing-analysis-lab`.*
*All identifiers in this file are fictional training placeholders. No real email was analyzed.*

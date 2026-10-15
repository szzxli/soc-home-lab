# Email Header Analysis Cheatsheet

Quick-reference for Tier-1 phishing triage. Read the walkthrough (`sample-walkthrough.md`) first for the full reasoning; use this page during live analysis.

---

## 1. Key Header Fields

Read `Received` headers **bottom-up** — the lowest one is the oldest hop (closest to the original sender).

| Header | Meaning | What to look at |
|---|---|---|
| `Received` | Each mail server that handled the message, in order | Trace bottom-up; unexpected countries, free-mail relays, or IPs with no reverse DNS on the first external hop |
| `Return-Path` | Envelope sender — where bounces go; the domain SPF checks | Must be consistent with the `From` domain on legitimate mail; mismatch with `From` = forged identity until proven otherwise |
| `From` | Displayed sender (what the user sees) | Compare the domain to the real organization's domain; watch display-name spoofing (`"IT Helpdesk" <attacker@…>`) |
| `Reply-To` | Where replies actually go | If it differs from `From`, replies are diverted — common in credential phishing |
| `Message-ID` | Unique ID assigned by the sending MTA | Right-hand side should match a plausible sending host; a missing or malformed Message-ID is a (weak) anomaly |
| `Authentication-Results` | SPF/DKIM/DMARC verdicts stamped by your receiving filter | See section 2 — never trust these if *you* didn't add them (attackers can forge the header) |
| `X-Originating-IP` / `X-Sender-IP` | Client IP recorded by some providers | Useful when present, but non-standard — don't rely on it |
| `Date` | Claimed send time | Compare against the first `Received` timestamp; large skew suggests header forgery |
| `Subject` | Claimed topic | Urgency language ("expires in 24 hours", "suspended", "verify now") is a lure marker, not proof |

> **Rule of thumb:** Trust the headers your own infrastructure added (`Received` by your MX, your `Authentication-Results`). Everything above your first hop can be forged.

---

## 2. SPF / DKIM / DMARC Quick Verdicts

### SPF (does the sending IP belong to the envelope domain?)

| Result | Meaning | Disposition |
|---|---|---|
| `pass` | IP is authorized by the envelope domain's SPF record | Neutral-to-good; does **not** prove the `From` identity (envelope ≠ From) |
| `fail` | IP is explicitly not authorized | Suspicious — treat as forged unless a forwarding/misconfiguration explanation checks out |
| `softfail` | IP is probably not authorized (`~all`) | Weak signal; note it, keep investigating |
| `none` | Domain publishes no SPF record | No signal either way; common for small senders |

### DKIM (is the signature cryptographically valid?)

| Result | Meaning | Disposition |
|---|---|---|
| `pass` | Signature verifies; message unaltered since signing, tied to `d=` domain | Good — but only authenticates the `d=` domain, not the `From` address |
| `fail` | Signature present but invalid | Strong signal of tampering or forgery |
| `none` | No DKIM signature | Neutral; many legitimate senders don't sign |

### DMARC (do SPF/DKIM align with the `From` domain, per the domain owner's policy?)

| Result | Meaning | Disposition |
|---|---|---|
| `pass` | Either SPF or DKIM passed **and** the authenticated domain aligns with `From` | Strong positive — the `From` domain genuinely authorized this mail |
| `fail` | Neither aligned auth passed | Malicious until proven otherwise when combined with other signals |
| `none` | `From` domain publishes no DMARC record | No policy signal; fall back to SPF/DKIM + header analysis |

### Policy tags you'll see next to DMARC

| Tag | Meaning |
|---|---|
| `p=none` | Domain owner asks for monitoring only — forgeries still get delivered |
| `p=quarantine` | Owner asks receivers to treat failures as suspicious (spam/junk) |
| `p=reject` | Owner asks receivers to **reject** failures outright — a `dmarc=fail` against `p=reject` is the strongest auth signal you can get |

**Composite rule I use:** `dmarc=fail` + `p=reject` + sender-identity mismatch = malicious with high confidence. Any single `fail` alone = investigate, don't conclude.

---

## 3. Common Obfuscation Techniques — One-Line Recognition

| Technique | What it is | How to spot it |
|---|---|---|
| **Homograph / lookalike domain** | Unicode or lookalike characters impersonating a brand (`rnicrosoft.com`, `paypaI.com` with capital-i) | Copy the domain out of the href and inspect character-by-character; punycode (`xn--…`) in the raw URL is the giveaway |
| **Subdomain trick** | Attacker's own domain with the brand as a subdomain (`login.corp-portal.evil-cdn.example`) | Read the domain **right-to-left**: the registrable domain is what the attacker controls, everything left of it is decoration |
| **URL shortener / redirector** | Short link or open-redirect hiding the final destination | Expand with `curl -sI` and follow each `Location:` hop; document the full chain, judge the *landing* page |
| **HTML smuggling** | Malicious file or redirect assembled inside an HTML attachment via JavaScript/Blob/Base64 | Don't render it — extract URLs with `grep`, check for `eval(`, `unescape(`, long Base64 blobs, `<meta http-equiv="refresh">`; detonate in a sandbox |
| **Display-text mismatch** | Link text says one thing, href goes elsewhere | Always inspect the raw `href`; "what you see is not where you go" |
| **Encoded payload** | URL/HTML/Base64 layers hiding the real destination | Decode layer by layer (`urllib.parse.unquote` → `base64.b64decode` → …); attackers layer encodings to defeat simple scanners |
| **Reply-To diversion** | Replies routed to the attacker while `From` looks internal | Compare `Reply-To` against `From` on every suspicious message |

---

## 4. Triage One-Liners

- **Envelope vs. header vs. reply:** `Return-Path` ≠ `From` ≠ `Reply-To` → assume forgery, verify otherwise.
- **Auth is a filter signal, not a verdict:** combine SPF/DKIM/DMARC; a single `fail` needs corroboration, a triple fail with `p=reject` needs none.
- **Judge the landing page, not the link text:** decode and expand every URL to its final destination before calling it.
- **Never interact with the phish:** no clicks, no credential entry, no opening attachments on a workstation — `curl -I`, sandbox, urlscan.
- **Hunt the blast radius:** one phish reported usually means many delivered — search the gateway for the same sender, URL, and hash.

---

*Repository: https://github.com/szzxli/soc-home-lab — project `03-phishing-analysis-lab`.*

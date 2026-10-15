# phishing-analysis

Dissect a suspicious email: header forensics, authentication results,
URL deobfuscation, and attachment triage — ending in a verdict with
a confidence level.

## When to use

Use when given an email (headers + body, `.eml`, or a forwarded sample)
and asked "is this phishing". Pairs with `alert-triage` for the
severity call and `incident-report` for documentation.

## Workflow

1. **Headers first**: extract `From`, `Reply-To`, `Return-Path`,
   `Received` chain (read bottom-up: the earliest hop is the most
   trustworthy), `Message-ID` domain, and `X-Mailer`. Flag mismatches:
   `From` domain vs. `Return-Path` domain vs. `Message-ID` domain
   disagreeing is the single strongest header signal.
2. **Authentication**: read `Authentication-Results` — SPF, DKIM, DMARC
   each pass/fail/none. Know what each means:
   - SPF fail = envelope sender not authorized (spoofed or forwarded).
   - DKIM fail = body/headers tampered or mis-signed.
   - DMARC fail with `p=reject` ignored by the receiver = the safety
     net had a hole.
   A `none` is not a pass — it means the domain publishes no policy.
3. **URLs**: extract every link and *resolve what it actually points to*.
   Decode URL shorteners, punycode (`xn--`), and redirect chains
   mentally: display text vs. href mismatch is the classic tell.
   Never click; describe where it would go.
4. **Body & attachments**: urgency language, authority impersonation,
   and credential-harvesting forms. Attachments: note type and name,
   do not open — record the hash if provided and check it against
   VirusTotal-style reputation only if the workflow allows.
5. **Verdict**: phishing / legitimate / inconclusive, with a confidence
   (high/medium/low) and the top 3 evidence bullets. "Inconclusive"
   is an acceptable answer — say what would resolve it.

## Output

Verdict line first, then the evidence in header → auth → URL → body
order, each with the exact artifact quoted. Under 400 words unless
the case is complex.

## Boundaries

- Never click links, open attachments, or submit credentials anywhere
  during analysis.
- Training samples are labeled as such. Real-world verdicts get a
  confidence level; never 100% on headers alone.

# cloudtrail-ioc

Analyze AWS CloudTrail logs for indicators of compromise using three
heuristic detectors: unusual-geography logins, brute-force bursts, and
high-risk IAM/EC2 API calls.

## When to use

Use when given CloudTrail JSON (`Records` array format) and asked what
looks malicious. Pairs with `alert-triage` (score the findings) and
`incident-report` (document them).

## Workflow

1. **Parse**: load the `Records` array. Every record needs `eventTime`,
   `eventName`, `sourceIPAddress`, and `userIdentity`. Records missing
   these are counted and skipped, not silently dropped.
2. **Detect** with the three heuristics:
   - **unusual_geo**: successful `ConsoleLogin` from a source IP outside
     the known-good ranges. Flagged hits are candidates — verify with a
     real GeoIP database (e.g. MaxMind GeoLite2) before treating the
     geography as fact.
   - **brute_force**: N or more *failed* `ConsoleLogin` attempts from one
     IP inside a sliding window (defaults: 5 failures / 10 minutes, both
     tunable). One finding per IP, for the earliest tripping window.
   - **suspicious_api**: event names on the high-risk watchlist —
     `PutUserPolicy`, `AttachUserPolicy`, `AttachRolePolicy`,
     `CreateAccessKey`, `DeleteTrail`, `StopLogging`, `RunInstances` —
     each mapped to a severity with a written rationale. Extend the
     watchlist deliberately: every addition needs a one-line "why this
     API is dangerous".
3. **Enrich** (optional): flagged external IPs via AbuseIPDB. Without an
   API key, enrichment is skipped and the report says so — never a
   silent failure, never a hard error.
4. **Report**: summary (record count, time range, findings by severity)
   plus a findings table (time / event / actor / IP / severity /
   evidence). Every finding carries the detector name and the exact
   evidence that tripped it.

## Output

A Markdown report a Tier-1 analyst can pick up: what was checked, what
fired, and what to look at next. Under-promise in the wording —
"consistent with brute force" beats "brute-force attack confirmed".

## Boundaries

- Heuristics are triage signals. A threshold trip is not proof of
  attacker activity; always state the benign alternative.
- Sample/synthetic data is labeled as such. Never present fabricated
  log events as real telemetry.

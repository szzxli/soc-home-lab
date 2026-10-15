# alert-triage

Triage a SOC alert (GuardDuty finding, SIEM alert, or detector output)
into a severity-scoped, action-oriented assessment: what happened,
how bad it is, and what to do in the next 30 minutes.

## When to use

Use when handed a raw security alert or finding and asked "is this real,
how bad, what now". Do not use for writing the full incident report
(see `incident-report`) or for deep forensic analysis of a single artifact
(see `cloudtrail-ioc`, `phishing-analysis`, `binary-triage`).

## Workflow

1. **Identify**: extract the 5 W's from the alert — who (actor/asset),
   what (technique, MITRE ATT&CK ID if known), when (first/last seen),
   where (account, region, host), and the detector's stated severity.
2. **Validate**: check for benign explanations first. Is the "unusual"
   activity a known admin workflow, a scheduled job, or a misconfigured
   detector? One concrete benign hypothesis, tested against the evidence,
   before escalating.
3. **Score**: assign severity using this rubric, not the detector's default:
   - **Critical**: active compromise indicators (known-malicious IOC,
     successful privilege escalation, defense evasion like log deletion)
     on a production asset. Page now.
   - **High**: strong suspicious signals on a production asset, or any
     critical-class signal on a non-prod asset. Investigate within 1 hour.
   - **Medium**: anomalous but explainable signals, or high-class signals
     with a plausible benign cause. Investigate within 1 business day.
   - **Low**: context only (stripped binaries, unusual-but-authorized
     logins). Log and monitor.
4. **Scope**: one paragraph on blast radius — which assets/accounts/data
   are in play if the worst case is true.
5. **Next actions**: 3 or fewer concrete steps, each with an owner
   ("you" by default) and a time box. No step may be "investigate further"
   without saying how.

## Output

A short triage note: verdict line (severity + one-sentence why),
evidence bullets (each tied to a timestamp or artifact), blast-radius
paragraph, and the action list. Under 300 words unless severity is
High or above.

## Boundaries

- A triage verdict is a prioritization signal, not a conviction.
  Never write "confirmed breach" without corroborating evidence from
  an independent source.
- If the alert is a synthetic training sample, say so and treat the
  exercise as a drill, not a real incident.

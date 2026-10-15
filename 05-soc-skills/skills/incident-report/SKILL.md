# incident-report

Turn triage notes and forensic findings into a structured incident report
that a SOC lead, an auditor, or a future-you can act on.

## When to use

Use after `alert-triage` has produced a High/Critical verdict, or when
asked to document any security investigation. Do not use for the initial
triage decision itself.

## Workflow

1. **Collect**: gather the triage note, timelines, affected assets,
   IOCs, and remediation actions taken. Missing items are marked
   `TBD` — never invented.
2. **Draft** using exactly these sections:
   - **Summary** (3 lines max): what happened, impact, current status.
   - **Timeline**: UTC timestamps, one row per key event. Every row
     needs a source (log name, alert ID, analyst observation).
   - **Impact**: assets, accounts, data confirmed vs. suspected affected.
     Keep the two categories visibly separate.
   - **Root cause**: the most likely initial vector, with the evidence
     that supports it and the evidence that was ruled out.
   - **Response actions**: what was done, by whom, when — including
     containment, eradication, and recovery steps.
   - **IOCs**: table of indicators (value, type, confidence,
     first/last seen). Only indicators observed in this incident.
   - **Lessons & follow-ups**: what failed, what to change, ticket IDs.
3. **Review pass**: re-read for the three honesty failures —
   invented timestamps, "confirmed" without evidence, and missing
   scope boundaries. Fix or downgrade each.

## Output

A Markdown incident report following the section order above. Factual,
timestamped, and explicit about what is confirmed vs. suspected.

## Boundaries

- Never fabricate an incident that did not happen. Training exercises
  and synthetic samples are labeled as such in the report header.
- Do not include credentials, tokens, or PII beyond what the
  investigation requires; redact where possible.

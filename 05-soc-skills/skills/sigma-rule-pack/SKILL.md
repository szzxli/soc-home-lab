---
name: sigma-rule-pack
description: Write selection-only Sigma rules for authentication logs that the home-lab Sigma engine can actually run, and ship each rule with its synthetic-log validation.
---

# sigma-rule-pack

Write Sigma rules for authentication logs that stay inside what the
home-lab engine supports: one rule = one selection on one record, no
aggregation, no time math. A rule that needs a count, a window, or a
comparison between two records does not belong here — it belongs in a
correlator, not in a Sigma selection.

## When to use

Use when asked to add a Sigma rule for an authentication log
(CloudTrail console logins, and the same shape for other auth logs).
Pairs with `detection-engineering` (the general rule-authoring workflow)
and `cloudtrail-ioc` (a concrete rule consumer for CloudTrail logs). Do
not use for multi-record patterns — "5 failures in 10 minutes",
"impossible travel", "login after a password reset" — the engine
cannot express those; say so and point at the correlator instead.

## Engine limits (hard boundaries, not tuning notes)

The engine in `02-python-ioc-analyzer/sigma_engine.py` supports:
selection fields with `contains` / `startswith` / `endswith` /
`windash` / `re` modifiers, value lists (OR), `and` / `or` / `not`
conditions, `1 of` / `all of` patterns, dotted field access
(`responseElements.ConsoleLogin`), CIDR values, `exists` checks.

It does **not** support: aggregation conditions (`count() by`),
`near` temporal correlation, `base64` / `base64offset` / `utf16` /
`expand` modifiers. A rule using any of those is skipped with a
warning at load time — it never fires, silently. Check the load
problems list before claiming a rule works.

## Workflow

1. **Define**: one rule = one behaviour on one record. State it in one
   sentence, the log source, and the field that carries the signal.
   If the behaviour needs two records to describe, stop — it is not a
   selection rule.
2. **Draft** the rule in Sigma YAML: `title`, a stable `id`, `status:
   test`, `description` carrying the why, `logsource`, a `detection`
   with `selection` (+ a `filter_*` only when the known-good has a
   written reason), and a `condition`. Every field name must exist in
   the sample log — check it against
   `02-python-ioc-analyzer/sample_data/sample_auth_log.json` before
   you write the YAML.
3. **Validate** against the synthetic auth log: run the rule over
   `sample_auth_log.json` with `sigma_engine.scan_records` and record
   TP (fired on the malicious records) and FP (fired on the benign
   records). Target zero FPs on the known-good records before
   shipping. Add a pytest case in
   `02-python-ioc-analyzer/tests/test_sigma_engine.py` that pins the
   exact finding set — the rule ships with its test, not after it.
4. **Ship**: rule file + sample-log evidence + pytest case travel
   together. A rule without its test evidence does not ship.

## Rules in this pack

| Rule | Behaviour (one record) | Level |
|---|---|---|
| Failed AWS Console Login for Root User | `ConsoleLogin` Failure for user `root` | high |
| AWS Console Login Without MFA | `ConsoleLogin` Success with `additionalEventData.MFAUsed: No` | high |
| AWS Console Login from Scripted User Agent | `ConsoleLogin` with a scripting user agent (`curl`, `python-requests`, `python-urllib`, `Go-http-client`, `Wget`) | medium |

Validation on the synthetic auth log (8 records): 4 findings, TP=4,
FP=0 — the root failure, the no-MFA success, and the two scripted-UA
logins fire; the MFA successes, the non-root failure, and the root
success do not. The pre-existing generic "AWS Console Login Failure"
rule also fires on the three failure records in the same log; that is
its own coverage, not this pack's.

## Output

The rule file, plus a validation note: sample log used, TP/FP counts,
and the pytest case name. The note stays under 200 words; the rule is
code, not prose.

## Boundaries

- A rule is a hypothesis until validated on both bad and good records.
  Never claim coverage ("we detect X") from an untested rule.
- Selection-only means selection-only. Do not smuggle a count or a
  time window into a `contains` list and call it aggregation.
- Synthetic test data is labeled as such. Never present validation
  numbers from synthetic logs as production performance.

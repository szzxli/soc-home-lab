# detection-engineering

Write and validate detection rules that catch attacker behavior without
drowning the SOC in noise: rule authoring, validation against known-bad
and known-good cases, tuning the TP/FP tradeoff, and shipping a rule
with its test evidence attached.

## When to use

Use when asked to write a detection rule for a technique or behavior,
or when an existing rule fires too much (or too little) and needs
tuning. Pairs with `alert-triage` (score what the rule fires on) and
`cloudtrail-ioc` (a concrete rule consumer for CloudTrail logs). Do not
use for triaging a single alert — see `alert-triage`.

## Workflow

1. **Define**: one rule = one behavior. State the attacker behavior in
   one sentence, the log source it lives in, and the MITRE ATT&CK
   technique ID if known. If you cannot write the behavior in one
   sentence, the rule will fire on the wrong things.
2. **Draft** the rule: selection criteria (what must match), filter
   (what must *not* match — the known-good), aggregation (e.g. count
   by source IP over 10 minutes), and a title/description carrying the
   why. Every filter line needs a written reason: "excludes X because
   Y is a known admin workflow". Write it in Sigma YAML or the
   platform's native syntax — same content either way.
3. **Validate** against known-bad *and* known-good: run the rule over a
   malicious sample (attack replay, red-team log, or the technique's
   reference events) and a benign sample (normal production traffic,
   admin workflows). Record TP (fired on bad) and FP (fired on good).
   A rule tested only on bad data is a hypothesis, not a detection.
4. **Tune** the tradeoff: FP-heavy → tighten selection or extend the
   filter, then re-run both samples. Missing TPs → loosen carefully,
   then re-check FPs. Target zero FPs on the known-good sample before
   shipping; any residual FP risk is written down (who gets paged, how
   often), never hand-waved.
5. **Ship**: rule + test evidence travel together — the rule file, the
   two sample sets (or their hashes/descriptions), the TP/FP counts,
   and a one-line runbook pointer ("when this fires, see
   `alert-triage`"). A rule without its test evidence does not ship.

## Output

The rule itself, plus a validation note: samples used, TP/FP counts,
each tuning decision with its reason, and the runbook line. The note
stays under 400 words; the rule is code, not prose.

## Boundaries

- A rule is a hypothesis until validated on both bad and good data.
  Never claim coverage ("we detect X") from an untested rule.
- Tuning only against the data you have is overfitting. State what
  the samples do not cover.
- Synthetic test data is labeled as such. Never present validation
  numbers from synthetic logs as production performance.

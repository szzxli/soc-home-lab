# Tool-call guard (log-only) — GitHub Action

Scores proposed agent tool calls from a JSONL log: `allow` /
`suspicious` / `block`. It is the CI form of the
`agent-tool-call-guard` skill. Offline — it never runs a call
and never touches the network.

## Use it

```yaml
- uses: szzxli/soc-home-lab/.github/actions/tool-call-guard@main
  with:
    calls: agent-log.jsonl
    fail-on-block: "true"
```

For a log without `expected_verdict` (a real agent log), the
action reports counts and fails only on what you ask it to
fail on. For a log with `expected_verdict` (an eval set), it
also reports exact-match accuracy.

## Inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `calls` | the 100-call eval set | One or more JSONL files, space-separated, globs allowed |
| `fail-on-block` | `false` | Fail the step when any call is scored `block` |
| `fail-on-suspicious` | `false` | Fail the step when any call is scored `suspicious` |

## Outputs

`total`, `allow`, `suspicious`, `block`, `accuracy` (percent,
empty when the log has no `expected_verdict`), `blocked`.

A summary with the counts and the per-call verdicts is written
to the job summary.

## What it does not do

- It does not run any tool call. It only reads the log.
- It does not decide `suspicious` calls. Those are held for
  human review — the reviewer sees only the user request, the
  tool call, and the finding.
- A score on the bundled eval set is a self-test: the checker
  and the eval calls were written by the same author. Blind-set
  scores and the current `guard.py` freeze are in
  `05-soc-skills/skills/agent-tool-call-guard/EVAL.md`.
  Blind-02 is now dev data. A new unseen blind set is pending.

## Local run

```bash
python3 05-soc-skills/skills/agent-tool-call-guard/guard.py agent-log.jsonl
```

See `05-soc-skills/skills/agent-tool-call-guard/EVAL.md` for the
method, the scores, and the severity mapping.

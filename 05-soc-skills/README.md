# soc-skills

Agent skills for security analysts.

General-purpose agent skill packs focus on software engineering workflows
and don't cover SOC work. These seven skills cover the Tier-1 analyst loop.
Six are distilled from a working home-lab project in this repo;
`yaral-detection` covers the YARA-L 2.0 rule language:

| Skill | Does | Distilled from |
|-------|------|----------------|
| `alert-triage` | Score a raw alert → severity + 30-min action plan | `01-mini-soc` triage guide |
| `incident-report` | Triage notes → structured incident report | `01-mini-soc` report template |
| `cloudtrail-ioc` | CloudTrail heuristics: geo anomalies, brute force, risky IAM | `02-python-ioc-analyzer` |
| `phishing-analysis` | Header forensics → SPF/DKIM/DMARC → URL → verdict | `03-phishing-analysis-lab` |
| `binary-triage` | Static ELF triage → scored verdict + one-page report | `04-rea-triage` |
| `detection-engineering` | Write + validate detection rules (Sigma), tune TP/FP, ship with test evidence | `02-python-ioc-analyzer` Sigma module |
| `yaral-detection` | Write + validate YARA-L 2.0 rules: single-event, multi-event correlation, volume + risk score | — |

## Install

Skills are just directories containing a `SKILL.md`. Copy the ones you
want into your agent's skills directory, e.g.:

```bash
# Claude Code / compatible agents
cp -r skills/alert-triage ~/.claude/skills/
```

Read a skill's `SKILL.md` before first use — each declares when to
invoke it, the workflow, the output shape, and its honesty boundaries.

## Design notes

- Every skill states its trigger, its workflow, its output contract,
  and what it refuses to do. A skill without boundaries is a liability.
- Findings are always labeled by confidence and evidence. "Consistent
  with X" beats "confirmed X" until a second source corroborates.
- Synthetic training data is never presented as real telemetry — in
  skills, in reports, in demos.

## Review checklist

Applies to any skill step that changes state — runs a command, writes a
file, changes a config, sends a request, deletes anything. Read-only steps
(read a log, run a search, describe a finding) are out of scope for this
section; the rest of the checklist still applies to them.

### 1. Typed action

- Every state-changing step names its type before it runs: `read`,
  `write`, `execute`, `delete`, `send`, `configure`. No step runs on a
  bare sentence. "Clean up the logs" is not a type; "delete files
  matching X in dir Y" is.
- The type fixes what the step may touch. A `read` step never writes.
  A `write` step names the exact path. An `execute` step names the
  exact command. A `send` step names the exact destination.
- If the type is unclear, the step does not run. Restate it until the
  type is unambiguous, or split the step into smaller typed steps.

### 2. Dry-run first

- Before any state-changing step, run the non-destructive preview: the
  same command with its dry-run flag, the query without the write, the
  diff before the apply. If the tool has no dry-run mode, print the
  exact action (paths, commands, payloads) and stop for a human read.
- The preview must show what WILL change, not that something is ready:
  file list, row count, target hosts. A preview that only says "ready"
  is not a preview.
- If the preview and the plan disagree, the plan is wrong. Fix the
  plan, re-run the preview. Never skip the preview because the change
  "looks small".

### 3. Reversible ops

- Every state-changing step states its undo before it runs: the backup,
  the restore command, the recovery path for a delete. No undo, no run —
  unless the step is explicitly flagged irreversible.
- Irreversible steps (delete without backup, an external send,
  credential rotation, anything that leaves the machine) need explicit
  approval naming the exact action. Approval for the plan is not
  approval for the irreversible step inside it.
- After the step, verify the undo still works: the backup exists, the
  rollback command is recorded, the state can be read back. An undo
  that was never tested is a claim, not a rollback.

### How to review

When reviewing a skill (or a change to one), check:

- [ ] Each state-changing step names a type
  (`read` / `write` / `execute` / `delete` / `send` / `configure`).
- [ ] Each state-changing step has a dry-run or preview step before it,
  or a stated reason it cannot have one.
- [ ] Each state-changing step states its undo; irreversible steps are
  flagged and need named approval.
- [ ] No step runs on prose alone ("clean up", "fix it", "update the
  config") — the type, the target, and the undo are all written down.
## License

MIT — take them, adapt them, make them yours.

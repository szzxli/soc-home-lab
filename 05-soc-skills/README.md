# soc-skills

Agent skills for security analysts — the SOC-flavored answer to
`mattpocock/skills`.

That repo (291k stars, MIT) packages one engineer's TypeScript-centric
agent workflow: grilling, TDD, code review. Nothing in it speaks SOC.
These five skills cover the Tier-1 analyst loop instead, each distilled
from a working home-lab project in this repo:

| Skill | Does | Distilled from |
|-------|------|----------------|
| `alert-triage` | Score a raw alert → severity + 30-min action plan | `01-mini-soc` triage guide |
| `incident-report` | Triage notes → structured incident report | `01-mini-soc` report template |
| `cloudtrail-ioc` | CloudTrail heuristics: geo anomalies, brute force, risky IAM | `02-python-ioc-analyzer` |
| `phishing-analysis` | Header forensics → SPF/DKIM/DMARC → URL → verdict | `03-phishing-analysis-lab` |
| `binary-triage` | Static ELF triage → scored verdict + one-page report | `04-rea-triage` |
| `detection-engineering` | Write + validate detection rules (Sigma), tune TP/FP, ship with test evidence | `02-python-ioc-analyzer` Sigma module |

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

## License

MIT — take them, adapt them, make them yours.

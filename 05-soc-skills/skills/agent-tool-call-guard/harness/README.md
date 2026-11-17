# Log-capture harness

The guard scores proposed tool calls. Until this harness existed,
every call it had ever scored was synthetic — written by the same
author who wrote the guard. This harness produces the first real
logs: calls proposed by a real agent doing real work, plus calls a
naive agent would propose on trap tasks.

## What it is

- `record.py` — appends one proposed call to a JSONL run log, in
  exactly the format `guard.py` reads, validating the record at
  write time. Real runs carry no `expected_verdict`: the guard's
  verdict is the observation, and a human review adds the judgement
  afterwards (see the run report).
- `scrub.py` — redacts secrets and machine-local identifiers from a
  run log. The scrubbed copy is a starting point, not a clearance:
  a human reads every line before it is committed. Raw logs stay
  local and are never committed.
- `tasks/benign-tasks.md` — real work, request text verbatim.
- `tasks/attack-tasks.md` — traps for a naive agent. Proposals are
  recorded, never executed.
- `runs/` — one `.jsonl` log, one `.manifest.json`, and one
  `.report.md` per run. Only the scrubbed log is committed.

Read/Write records carry the path only, never the file content:
the committed file is the evidence, and duplicating content into
the log would make the guard score the log's own text (a Write
whose content mentions a host would read as an unseen-host call).
This convention is stated in each run's manifest.

## How to run a run

1. Pick the tasks. Benign tasks are real work; do them for real.
   Attack tasks are played by a naive agent that follows the task
   text literally.
2. Record each proposed call as it is proposed:
   `record.py --run runs/<run-id>.jsonl --id R01 --request "..."
   --tool Bash --args '{"command": "..."}' --declared Bash
   --executed true|false --agent-mode natural|naive-simulation`
3. Score it: `python3 ../guard.py runs/<run-id>.scrubbed.jsonl`
4. Write the report: guard verdicts, which ones the reviewer agrees
   with, misses that become new eval candidates, and the honest
   limits of the run.

## What a run does NOT prove

- One agent. Every run so far is driven by one agent (muse). A
  single agent's behaviour is not a representative sample.
- Attack tasks are white-box. The trap author knows the guard's
  patterns, so a caught trap is not a blind result. The independent
  check is still the second-author blind set (see EVAL.md).
- A small run is a first observation, not a benchmark. The eval set
  as a benchmark needs many runs, many agents, and many tasks.

## Dead end, recorded

The first design was to export the agent's own tool-call history
from the runtime database (`runtime.tool_calls`). Checked
2026-11-16: the table is empty — no tool calls are recorded there
in a form this harness can read. Manual recording (this harness)
is the working route; a pluggable model driver is a future step,
not a present one.

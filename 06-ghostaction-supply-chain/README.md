# 06 — ghostaction-supply-chain

**Problem:** Supply-chain attacks now target the developer's own workbench — a malicious
`.vscode/tasks.json` can execute code the moment a project folder is opened, and a
cron-based backdoor survives deleting the repo files.

**Case:** "GhostAction" (reported October 2026, see
[GBHackers](https://gbhackers.com/ghostaction-hackers-hide-credential-stealing-malware/)):
attackers hid a ~38-line credential-stealing JS payload disguised as a font file, launched
via an `eslint-check` task in `.vscode/tasks.json` with `runOn: folderOpen`. It only fires
in a trusted workspace with automatic tasks allowed — then drops a cron backdoor that
re-connects every 5 minutes. 94 GitHub repos were affected.

**What it is:** A safe, hands-on supply-chain defense lab built around this technique:
inert training samples that demonstrate the mechanism with zero malicious behavior, a
hunt checklist for the two persistence points (workspace tasks + cron), and a blank
incident report template.

**Skills:** Supply-chain threat modeling, static review of editor configs, persistence
hunting (cron/systemd), incident documentation.

> All samples in `samples/` are **inert training simulations** — clearly labeled, no
> network access, no file writes, no credential access. The real malware is never
> included or linked here.

## Safety rules (read first)

1. **Never** allow automatic tasks (`runOn: folderOpen`) on a repo you did not write or
   fully review. In VS Code: only click "Allow" for trusted workspaces.
2. Analyze `samples/` **statically only** (read the files, don't run them) unless you
   are in a disposable VM you can throw away.
3. The persistence-hunt exercise inspects your *own* machine's cron/systemd entries —
   you are looking for anomalies, not planting a backdoor.

## Lab exercises (do them yourself, in order)

### Exercise 1 — Static review (15 min)
Open `samples/tasks.json` and `samples/font-cache.js`. Without running anything, list
every red flag: task label vs. what it actually runs, `runOn: folderOpen`, silent
presentation, a `.js` file disguised with a font-related name. Write your findings in
`incident-report-template.md` §1.

### Exercise 2 — Write a detector (45 min)
Write a small script (or extend `../02-python-ioc-analyzer/`) that walks a directory
tree and flags every `.vscode/tasks.json` containing the dangerous combination:
`"type": "shell"` (or `process`) + `node` in `command` + `runOn: folderOpen`.
Test it against `samples/` (should alert) and against this repo's real projects
(should stay quiet — verify: none of them ship a `tasks.json`).

### Exercise 3 — Persistence hunt (30 min)
On your Linux VM, hunt the second stage the way a responder would:
- `crontab -l` and `/etc/cron*/*` — look for entries phoning home on short intervals
- `systemctl list-timers --all` — look for unfamiliar timers
- `~/.config/autostart/`, `~/.bashrc`, `~/.profile` — look for appended one-liners
Document what you checked and what you found (expect: clean) in the report §3.

### Exercise 4 — Incident report (30 min)
Fill `incident-report-template.md` end to end as if Exercise 1's sample had been the
real thing: timeline, IoCs, containment (revoke creds, kill cron, re-clone), and
prevention (workspace trust policy, pre-commit hook sketch).

## Detection notes

| Signal | Where | Why it matters |
|---|---|---|
| `runOn: folderOpen` + shell task | `.vscode/tasks.json` | Code execution on project open, no click needed |
| Task label mimics a legit tool (`eslint-check`) | `.vscode/tasks.json` | Social engineering against the developer |
| `.js` payload with font/asset-themed name | repo tree | Hides in plain sight during code review |
| Sub-5-minute cron / unknown systemd timer | host | Persistence that survives repo deletion |
| Outbound connection to unknown host | network | C2 beaconing |

## Resume bullet (copy-ready)

- Built a supply-chain defense lab around the GhostAction technique (malicious VS Code
  workspace tasks + cron persistence): wrote a static detector for dangerous
  `tasks.json` patterns and a persistence-hunt runbook covering cron/systemd/autostart.

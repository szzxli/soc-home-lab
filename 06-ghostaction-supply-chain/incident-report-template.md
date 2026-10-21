# Incident report — GhostAction-style supply-chain case (TRAINING)

> Fill this yourself after the hands-on exercises. No fabricated entries.

## 1. Static findings (Exercise 1)

- Suspicious file(s):
- Red flags found (quote file + line):
-

## 2. Detector results (Exercise 2)

- Detector script location:
- Result on `samples/` (expected: ALERT):
- Result on repos 01–05 (expected: quiet):

## 3. Persistence hunt (Exercise 3)

| Location checked | Command used | Finding |
|---|---|---|
| user crontab | `crontab -l` | |
| /etc/cron* | | |
| systemd timers | `systemctl list-timers --all` | |
| shell startup files | | |

- Host verdict: CLEAN / COMPROMISED

## 4. Timeline (as if the sample had been real)

-

## 5. Containment & recovery

-

## 6. Prevention

- Workspace trust policy for future repos:
- Pre-commit / CI check idea (e.g., block `runOn: folderOpen` in PRs):

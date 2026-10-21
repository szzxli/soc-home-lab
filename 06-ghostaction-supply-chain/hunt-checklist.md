# GhostAction hunt checklist

Use this when triaging a repo you didn't write, or after any "weird task ran on open"
report. Check each box with the exact command you ran and what you saw.

## 1. Workspace task review (the entry point)

- [ ] List all editor-config execution points:
  `find <repo> -name "tasks.json" -path "*vscode*" -o -name "*.code-workspace"`
- [ ] For each `tasks.json`, flag: `"runOn": "folderOpen"` / `"type": "shell"` /
  `command` containing `node`, `curl`, `wget`, `powershell`, `bash -c`
- [ ] Read every task `label` — does the label match what the command does?
  (`eslint-check` running `node font-cache.js` = lie)
- [ ] Check filenames in `.vscode/`: any `.js`/binary with a font, asset, or cache
  themed name? Read it before trusting it.
- [ ] Verdict for this repo: CLEAN / SUSPICIOUS (note file + line)

## 2. Persistence hunt (the second stage)

GhostAction's backdoor re-connected every 5 minutes — deleting repo files is not enough.

- [ ] `crontab -l` (and `sudo crontab -l`) — unfamiliar entries, especially `*/5 * * * *`
- [ ] `ls -la /etc/cron.d/ /etc/cron.hourly/ 2>/dev/null` — files you didn't put there
- [ ] `systemctl list-timers --all | head -30` — timers you don't recognize
- [ ] `grep -r "curl\|wget" ~/.bashrc ~/.profile ~/.config/autostart/ 2>/dev/null`
- [ ] Verdict for this host: CLEAN / COMPROMISED (note entry + next step)

## 3. If compromised

1. Disconnect the host from the network (don't wipe yet — preserve evidence).
2. Kill the persistence first (cron entry / timer), then the payload.
3. **Rotate every credential that existed on the host** — assume the stealer got them.
4. Re-clone repos from a known-good remote; do not trust local copies.
5. Fill `incident-report-template.md`.

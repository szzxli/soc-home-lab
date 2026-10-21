# Training samples (INERT)

These two files simulate the GhostAction technique so you can practice **detection**.
They are deliberately harmless:

- `tasks.json` — a workspace task labeled `eslint-check` that would run
  `node .vscode/font-cache.js` on folder open. It demonstrates the *mechanism*
  (trusted workspace + `runOn: folderOpen` = code execution with no click).
- `font-cache.js` — the "disguised font file". The real malware hid credential
  theft here; **this file only prints a marker line**. No network access, no file
  writes, no credential access, no obfuscation.

## How to use them safely

1. **Static review first.** Read both files. List the red flags before doing anything else.
2. **Do not** open this folder in VS Code and click "Yes, I trust the authors" just
   to see what happens — that is exactly the habit this lab trains you out of.
3. If you want to observe execution, do it in a disposable VM you can delete, and
   even there, prefer `node --check font-cache.js` (syntax check, no execution).

The detection exercise is the point. The malware is not here and never will be.

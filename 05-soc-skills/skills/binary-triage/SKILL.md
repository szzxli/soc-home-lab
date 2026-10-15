# binary-triage

Static triage of an ELF binary: one command in, one analyst-readable
page out — file identity, heuristic findings with severity + rationale,
a score-based verdict, and next steps.

## When to use

Use when given a Linux binary (or a hash/path to one) and asked "is
this malicious". The binary is never executed. Pairs with
`alert-triage` (what the verdict means for prioritization).

## Workflow

1. **Identify**: sha256, size, architecture, ELF type (executable vs.
   shared object), stripped or not, statically vs. dynamically linked.
   Record all six before any judgment.
2. **Check** the five heuristics, each mapped to a severity:
   - **Section entropy**: code sections above ~7.5 bits/byte over a few
     KB suggest packing, encryption, or a compressed payload (medium).
   - **W^X violation**: a section both writable and executable —
     classic shellcode staging (high).
   - **Suspicious imports**: `ptrace` (anti-debug), `memfd_create`
     (fileless execution), `process_vm_writev` (injection),
     `unshare` (container escape), `system`/`execve` (execution) —
     each with a written rationale, severity high/medium/low.
   - **String IOCs**: hardcoded IPs, URLs with IP-literal hosts or
     abuse-prone services (pastebins, webhook endpoints, ngrok),
     sensitive paths (`/etc/shadow`), malware keywords. Plain project
     URLs (e.g. gnu.org) are intentionally not flagged.
   - **Context signals** (low): stripped, statically linked — analyst
     context, never accusations on their own.
3. **Score**: high=3, medium=2, low=1. Verdict bands: 0–1 benign,
   2–4 suspicious, 5+ malicious.
4. **Enrich** (optional): if the `rea` CLI is available with a working
   ELF provider, fold its layout evidence (entry point, section
   inventory) in. If REA is absent, say so and continue — never fail
   the triage for a missing enricher.
5. **Recommend**: benign → no action. Otherwise: do not execute outside
   a sandbox; next steps are Ghidra control-flow review, deeper REA
   providers, and sandboxed detonation with network capture.

## Output

A one-page Markdown report: verdict banner with score, findings table
(severity / indicator / evidence), import list, enrichment status,
recommendations. The verdict wording stays honest — "multiple strong
signals, escalate" rather than "this is malware".

## Boundaries

- Static analysis only. Never execute the binary, even in a "quick
  test".
- Verdicts are triage signals, not convictions. Heuristics have false
  positives by design — state the most likely benign reading for each
  high finding.
- No real malware in demos: validate against synthetic fixtures and
  known-benign system binaries.

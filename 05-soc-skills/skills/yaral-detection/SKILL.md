# yaral-detection

Write YARA-L 2.0 detection rules that catch attacker behavior in
Google SecOps: single-event checks, multi-event correlation over a
time window, and volume rules with a risk score — then validate each
rule before it ships.

## When to use

Use when asked to turn a suspicious behavior into a standing
detection in YARA-L 2.0, or when an existing YARA-L rule fires too
much (or too little) and needs tuning. Pairs with
`detection-engineering` (the rule lifecycle: define, validate on bad
and good samples, tune, ship with evidence) and `alert-triage` (score
what the rule fires on). Do not use for writing Sigma or another
platform's rules, and do not use for triaging a single alert — see
`alert-triage`.

## Workflow

1. **Define**: one rule = one behavior. State the behavior in one
   sentence, the UDM event type it lives in, and the MITRE ATT&CK
   technique ID if known. If you cannot write the behavior in one
   sentence, the rule will fire on the wrong things.
2. **Draft** the rule: event variables that filter the behavior,
   placeholders that bridge events, a `match` window that bounds the
   correlation, an `outcome` that carries the counts and the risk
   score, and a `condition` that is the trip line. Every exclusion
   needs a written reason: "excludes X because Y is a known admin
   workflow".
3. **Validate** against known-bad *and* known-good: run the rule's
   logic as a search first (see "Validate before shipping"), then
   hand-walk it against the synthetic events in `samples/`. Record
   what fires and what does not. A rule tested only on bad data is a
   hypothesis, not a detection.
4. **Tune** the tradeoff: FP-heavy → tighten the event filters or
   extend the exclusion, then re-run both samples. Missing TPs →
   loosen carefully, then re-check FPs. Thresholds come from the
   environment's baseline (how many failed logins does a normal user
   produce in ten minutes?), never from a guess.
5. **Ship**: rule + test evidence travel together — the `.yaral`
   file, the samples checked, the search volume observed, the TP/FP
   notes, and a one-line runbook pointer ("when this fires, see
   `alert-triage`"). A rule without its test evidence does not ship.

## Rule syntax

A rule is a named block with sections in a fixed order. Only `meta`,
`events`, and `condition` are required.

| Section | Required | Does |
|---|---|---|
| `meta` | Yes | Notes for people: author, one-sentence description, severity (`Info`, `Low`, `Medium`, `High`, `Critical`). |
| `events` | Yes | The tests each event must pass, grouped under event variables (`$e`, `$login`, `$shell`). Lines in one variable are ANDed. |
| `match` | No | How events are grouped, and over what window. A rule with no `match` fires on single events. |
| `outcome` | No | Values computed per detection: counts, aggregates, first/last times, lists. At most 20 variables. |
| `condition` | Yes | The trip line: existence, a count, a combination, or a comparison against an outcome. |
| `options` | No | Behavior switches, after `condition`. |

**Events.** Filter on UDM fields, `metadata.event_type` first:
`$login.metadata.event_type = "USER_LOGIN"` and
`$login.security_result.action = "FAIL"`. Pull values out with
placeholder variables (`$user = $login.principal.user.userid`) so a
second event can be compared against them. Match text with `/regex/
nocase` or `re.regex(field, `pattern`) nocase`; match an address
range with `net.ip_in_range_cidr($e.principal.ip,
"203.0.113.0/24")`. Exclude with `not` (`not re.regex(...)`) and
combine with `and` / `or`.

**Match.** `$user over 10m` gathers events sharing a `$user` value
into a sliding window of 10 minutes; `by 10m` would bucket them into
fixed windows instead — rules use `over`. Windows run from `1m` to
`48h`, and a rule that uses `match` must give it a window. Match
variables must be placeholders defined in `events`. The engine drops
groups whose match value is empty (`""`, `0`) unless `options:
allow_zero_values = true` is set.

**Outcome.** Aggregates: `count()`, `count_distinct()`, `sum()`,
`avg()`, `max()`, `min()`, `stddev()`; lists: `array_distinct()`;
times: `min($e.metadata.event_timestamp.seconds)`. Two variables
are special: `$risk_score` is shown on the alert — leave it out and
the platform defaults to 40 for alerting rules, 15 otherwise. A
common convention maps severity to score: Info 10, Low 35, Medium
65, High 85, Critical 95. Functions that average across the whole
window take a `window.` prefix (`window.avg(...)`).

**Condition.** Existence (`$e`), a count (`#e > 5`), a combination
(`$shell and $conn`, `$e1 or $e2`), or a comparison against an
outcome (`$failed_login_count > 5`, `$risk_score > 49`).

**UDM nouns.** Every event is built from nouns: `principal` (who
acted), `target` (acted on), `src`, `intermediary`, `observer`,
`metadata` (type, time, source product), `security_result` (action,
verdict), `network` (bytes, ports). Fields used in the examples:

| Field | Holds |
|---|---|
| `metadata.event_type` | The normalized action: `USER_LOGIN`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `FILE_READ`, `FILE_CREATION`. |
| `metadata.event_timestamp.seconds` | When the event happened, epoch seconds. |
| `principal.user.userid`, `principal.hostname`, `principal.ip` | The acting user, host, address. |
| `principal.process.command_line`, `principal.process.file.full_path` | The acting process. |
| `target.process.command_line`, `target.process.file.full_path`, `target.process.file.sha256` | The process acted on. |
| `target.file.full_path`, `target.file.sha256` | The file acted on. |
| `target.ip`, `target.hostname`, `target.user.userid` | The destination / user acted on. |
| `network.sent_bytes` | Bytes sent on the connection. |
| `security_result.action` | What happened to the event: `FAIL`, `BLOCK`, `ALLOW`. |

Rules read UDM events, never raw log lines. Every field path in
`events` must exist in the tenant's parsed data — a path the parser
never fills makes the rule silently never fire. Confirm each path
against the tenant's field reference before shipping, and treat the
parser mapping as part of the rule: when a parser changes, a rule can
go quiet without erroring.

## Worked examples

Full rule files live in `examples/` (`.yaral`). Synthetic events for
each case live in `samples/synthetic-udm-events.json`. All hosts,
users, and addresses are invented; `203.0.113.0/24` is documentation
address space. Nothing here is real telemetry.

### 1. Repeated failed logins for one user

One account failing to log in more than five times in ten minutes.
The threshold is a count, so the rule needs a `match` window and an
`outcome` count — a bare `condition: $login` would fire on the first
failure.

```yaral
rule repeated_failed_logins_single_user {
  meta:
    author = "soc-lab"
    description = "One user account fails to log in more than five times in ten minutes."
    severity = "Medium"

  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.security_result.action = "FAIL"
    $login.principal.user.userid != ""
    $user = $login.principal.user.userid

  match:
    $user over 10m

  outcome:
    $failed_login_count = count($login.metadata.id)
    $first_fail_time = min($login.metadata.event_timestamp.seconds)
    $risk_score = 65

  condition:
    $failed_login_count > 5
}
```

- **Matches**: six failed logins for `a.okafor` inside eight
  minutes (see `samples/`, scenario 1a).
- **Does not match**: three failed logins for the same user inside
  ten minutes — below the trip line (scenario 1b). A burst of
  *successful* logins does not match either: `security_result.action`
  is not `FAIL`.
- **When it fires**: check the source address (one address or many),
  whether the account logged in successfully afterwards, and whether
  the account is locked out. A single-address burst with a later
  success is the shape to escalate; a spread of addresses with no
  success is usually a mistyped password or a stale saved credential.
- **What it cannot prove**: count alone cannot tell a forgotten
  password from an attacker. The rule is a lead, not a verdict.

### 2. Scripting shell, then an outbound connection

A scripting shell launches on a host and the same host opens an
outbound connection within five minutes. Two event types, bridged on
the hostname.

```yaral
rule scripting_shell_then_outbound_connection {
  meta:
    author = "soc-lab"
    description = "A scripting shell launches on a host and the same host opens an outbound connection within five minutes."
    severity = "High"

  events:
    $shell.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($shell.target.process.command_line, `\bpowershell(\.exe)?\b|\bcmd(\.exe)?\b`) nocase
    not re.regex($shell.target.process.command_line, `C:\\Tools\\PatchMgmt\\`) nocase
    $host = $shell.principal.hostname
    $conn.metadata.event_type = "NETWORK_CONNECTION"
    $conn.principal.hostname = $host
    $conn.target.ip != ""

  match:
    $host over 5m

  outcome:
    $event_count = count($shell.metadata.id)
    $risk_score = 85
    $shell_command = array_distinct($shell.target.process.command_line)
    $dest_ips = array_distinct($conn.target.ip)

  condition:
    $shell and $conn
}
```

- **Matches**: `powershell.exe -enc <base64>` launches on
  `wkst-042`, then `wkst-042` connects to `203.0.113.45` three
  minutes later (scenario 2a).
- **Does not match**: the shell launches but no connection follows
  inside five minutes (scenario 2b). A shell launched by the patch
  tool (`C:\Tools\PatchMgmt\...`) does not match either — the `not`
  line excludes it (scenario 2c). A connection with no shell launch
  on the host does not match.
- **When it fires**: read the full command line (encoded commands
  are the thing to decode), the parent process, the destination
  address and port, and whether the destination is known-good. Check
  the same host's history: one encoded launch is a lead; a host that
  does this weekly is a workflow.
- **What it cannot prove**: scripting shells are admin tools too.
  The pair (shell + outbound connection) is suspicious; intent is
  decided by the command line and the destination, not by the rule.

### 3. Sensitive file read, then a large upload

A host reads a credential or archive file and then sends far more
bytes than its own hourly average. The threshold is relative
(three times the host's own average), so it adapts to quiet and busy
hosts instead of using one fixed byte count for the whole estate.

```yaral
rule sensitive_file_read_then_large_upload {
  meta:
    author = "soc-lab"
    description = "A host reads a credential or archive file and then sends far more bytes than its own hourly average."
    severity = "High"

  events:
    $read.metadata.event_type = "FILE_READ"
    $read.target.file.full_path = /\.(kdbx|pem|ppk|7z|zip)$/ nocase
    $host = $read.principal.hostname
    $conn.metadata.event_type = "NETWORK_CONNECTION"
    $conn.principal.hostname = $host

  match:
    $host over 1h

  outcome:
    $max_sent_bytes = max($conn.network.sent_bytes)
    $avg_sent_bytes = window.avg($conn.network.sent_bytes)
    $upload_threshold = 3 * $avg_sent_bytes
    $read_count = count($read.metadata.id)
    $risk_score = 85
    $files_read = array_distinct($read.target.file.full_path)

  condition:
    $read and $conn and $max_sent_bytes > $upload_threshold
}
```

- **Matches**: `wkst-042` reads `vault.kdbx`, then one connection
  sends 900,000 bytes while the host's five connections average
  190,400 — threshold 571,200, and 900,000 clears it (scenario 3a).
- **Does not match**: the same file read, but the largest upload is
  20,000 bytes against a ~14,000 average — inside normal range
  (scenario 3b). A large upload with no sensitive file read does not
  match either.
- **When it fires**: list the files read, the destination address,
  and whether the upload is a known backup or sync job. A backup
  destination explains the volume; an unknown address does not.
- **What it cannot prove**: the rule sees volume, not content. It
  cannot say what left the host. If `network.sent_bytes` is
  unpopulated for this source, the rule stays silent — confirm the
  field is filled before shipping.

## Validate before shipping

1. **Read-through**: sections in order; `meta`, `events`,
   `condition` present; every match variable is a placeholder defined
   in `events`; every field path is a real UDM path for that event
   type; thresholds are numbers from the environment's baseline, not
   guesses.
2. **Search first**: strip the `rule` wrapper and run the `events`
   plus `match` as a search over a short window. If the volume is
   wrong, the rule is wrong — fix it before it can page anyone.
3. **Platform check**: paste the rule into the Rules Editor and fix
   what its validator flags. There is no local YARA-L engine —
   syntax can only be checked inside the platform.
4. **Hand-run the samples**: walk each rule against the synthetic
   events in `samples/` and confirm the expected verdict by
   reasoning. Expected results here are worked out, not executed.
5. **Ship with evidence**: rule + the samples checked + the search
   volume observed + the runbook line, as in
   `detection-engineering`. A rule without its test evidence does
   not ship.

## Output

The rule file (`.yaral`), plus a validation note: what it detects
in one sentence, the samples checked, the search volume seen, each
tuning decision with its reason, and the triage line for when it
fires. The note stays under 400 words; the rule is code, not prose.

## Boundaries

- YARA-L 2.0 is the scope. Other versions and other platforms' rule
  languages differ; do not present a YARA-L rule as portable.
- A rule is a hypothesis until validated on both bad and good data.
  Never claim coverage ("we detect X") from an untested rule.
- A firing rule is a lead, not proof. State the benign alternative
  for every rule; the triage steps in the examples do this.
- Field names depend on the tenant's parser mapping. Never invent a
  UDM path — check it, and say which mapping you checked.
- Synthetic test data is labeled as such. Never present validation
  numbers from synthetic logs as production performance.
- Detection only. No exploit reproduction, no vulnerable instances,
  no attack tooling, no real telemetry in examples.

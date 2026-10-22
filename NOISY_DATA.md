# Noisy sample data: expected true and false positives

The clean samples in this repo are short and tidy on purpose. Each line is
either obviously benign or obviously bad, so a reference detection "passes"
with TP=1 FP=0. Real logs don't look like that. For the labs that are used most
(the in-browser demo and the three KEV packs whose detectors ship in this
repo), there is now a **noisy** variant of each sample next to the clean one:

| Lab | Clean sample (kept as is) | Noisy sample | Generator |
|---|---|---|---|
| 02 CloudTrail IOC analyzer (the [live demo](https://szzxli.github.io/soc-home-lab/web/demo.html)) | `02-python-ioc-analyzer/sample_data/sample_cloudtrail.json` (19 records) | `sample_cloudtrail_noisy.json` (2,870 records) | `sample_data/generate_noisy.py` |
| 07 CVE-2026-21589 Atlassian `::` traversal | `07-kev-hunting/samples/confluence-access.log` | `samples/noisy/confluence-access-noisy.log` | `samples/noisy/generate_noisy.py` |
| 07 CVE-2026-102764 BeyondTrust Remote Support | `07-kev-hunting/samples/appliance.log` | `samples/noisy/appliance-noisy.log` | same |
| 07 CVE-2026-110447 Nextcloud CODE server | `07-kev-hunting/samples/nextcloud-access.log` | `samples/noisy/nextcloud-access-noisy.log` | same |

Why these four: the demo is the homepage's primary call to action, and these
are the three KEV packs whose detectors live in this repo, so the detectors and
tests can be changed together. The other seven packs' detectors live in
[soc-skills](https://github.com/szzxli/soc-skills) and only have clean samples so far.

Each noisy file adds three things:

- **Volume:** 2,000–2,900 routine lines. That means health checks, sync clients,
  crons, autoscaling and normal browsing.
- **Benign look-alikes:** activity that trips the reference detection on purpose.
- **Missing or empty fields:** `"-"` requests, truncated lines, records without
  `userIdentity` / `eventTime` / `seq=`, null `responseElements`, bad timestamps,
  and entries that aren't JSON objects.

Everything is synthetic, made by seeded generators (the same output on every
run, enforced by tests). Attacker addresses come only from documentation ranges
(RFC 5737 / RFC 3849). The answer keys are in
`sample_cloudtrail_noisy.truth.json` and `samples/noisy/truth.json`. **Hunt
first, then open the key.**

## Results (generated, not hand-written)

The table below is the output of `python3 tools/noisy_scorecard.py`. A test
fails if this file and the code ever disagree.

- **02** is scored per finding: each finding is a TP if its IP or actor
  belongs to the attack, otherwise an FP.
- **07** is scored per source (IP or host): *Incident-level* counts
  `[INCIDENT]` verdicts. *Leads to triage* counts `[SUSPICIOUS]` / `[RECON]`
  verdicts, split into benign and malicious sources.

<!-- noisy-scorecard:begin -->
| Lab · noisy sample | Lines / records | True positives | False positives | Missed (FN) | Leads to triage (benign / malicious) | Skipped malformed |
|---|---|---|---|---|---|---|
| 02 CloudTrail IOC analyzer · `sample_cloudtrail_noisy.json` (finding-level) | 2870 | 8 | 23 | 1 | n/a | 3 non-object entries |
| 07 CVE-2026-21589 Atlassian `::` traversal · `confluence-access-noisy.log` (per source) | 2646 | 2 | 1 | 0 | 1 / 1 | 4 |
| 07 CVE-2026-102764 BeyondTrust RS appliance · `appliance-noisy.log` (per source) | 2588 | 1 | 1 | 1 | 3 / 1 | 2 |
| 07 CVE-2026-110447 Nextcloud CODE server · `nextcloud-access-noisy.log` (per source) | 2107 | 1 | 0 | 1 | 3 / 2 | 3 |

**02 per detector (finding-level):**

| Detector | TP findings | FP findings |
|---|---|---|
| `brute_force` | 1 | 1 |
| `unusual_geo` | 1 | 4 |
| `suspicious_api` | 6 | 18 |

**02 missed:** `brute_force` on 198.51.100.200 (low-and-slow spray, 1 try / 15 min)

**07 verdicts per source:**

- `confluence-access-noisy.log`: 10.0.2.31 → RECON, 10.0.5.9 → INCIDENT, 192.0.2.77 → INCIDENT, 198.51.100.7 → RECON, 203.0.113.9 → INCIDENT
- `appliance-noisy.log`: bt-rs-01 → SUSPICIOUS, bt-rs-02 → SUSPICIOUS, bt-rs-03 → INCIDENT, bt-rs-04 → INCIDENT, bt-rs-05 → SUSPICIOUS, bt-rs-06 → SUSPICIOUS
- `nextcloud-access-noisy.log`: 10.0.1.33 → SUSPICIOUS, 10.0.1.40 → SUSPICIOUS, 10.0.5.8 → RECON, 192.0.2.150 → SUSPICIOUS, 198.51.100.44 → RECON, 203.0.113.50 → INCIDENT
<!-- noisy-scorecard:end -->

## Reading the numbers honestly

The reference detections are deliberately simple teaching rules. On noisy data
they **do** produce false positives and miss things. That's the point of the
exercise, not a bug to hide.

### 02 CloudTrail IOC analyzer (8 TP, 23 FP, 1 FN)

| What fired | Why it's a false positive | Tuning hint |
|---|---|---|
| `suspicious_api` RunInstances ×12 | EC2 Auto Scaling launches instances every 2 h (`userIdentity.type = AWSService`, `invokedBy = autoscaling.amazonaws.com`) | Suppress `AWSService` callers for RunInstances; alert on unusual instance *types* (GPU) or counts instead |
| `suspicious_api` CreateAccessKey ×4 | Nightly key-rotation Lambda (`assumed-role/KeyRotationLambda`) | Allowlist the rotation role *and* the time window; alert when a human creates a key for another user |
| `suspicious_api` AttachRolePolicy ×2 | Terraform CI deploy (`assumed-role/terraform-ci`) | Allowlist the CI role; alert on `AdministratorAccess` or `*` policies regardless of caller |
| `unusual_geo` ×4 | Employees on home / hotel networks, plus one SSO sign-in that CloudTrail records as `AWS Internal` | The demo's "common ranges" table isn't GeoIP. Use real GeoIP + per-user baselines; skip values that aren't IPs |
| `brute_force` ×1 | Shared office NAT (`13.52.44.19`): 5 *different* users each mistype once on password-expiry morning | Count failures per (IP, user) as well as per IP; require ≥ N failures for the *same* user |
| **Missed:** password spray from `198.51.100.200` | 16 users, 1 try every 15 min. A per-IP 5-in-10-minutes window never trips | Add a slow-spray rule: one IP failing against ≥ 5 distinct users in 24 h |

The attack itself (14 failed logins → successful login → `AttachUserPolicy`
AdministratorAccess → `CreateAccessKey` → `StopLogging` → 3 × p3.16xlarge
`RunInstances`) is fully caught: 8 TP findings. `CreateUser` isn't on the
watchlist, which is a good first tuning exercise. The optional Sigma layer
(`--sigma-rules rules`) adds one finding per failed console login, 62 on this
file. That's useful context but far too noisy to page anyone on.

### 07 Atlassian CVE-2026-21589 (2 TP incidents, 1 FP incident)

- **FP incident `10.0.5.9`:** a *new* internal scanner node that isn't on the
  allowlist yet. The WAF in front of Confluence answers blocked requests with a
  **200** "Request blocked" page (1,204 bytes, the same for every path), so
  "`::` + 200 on WEB-INF" looks like a successful read. **Tuning hint:** don't
  trust status codes alone. Compare the response size with the real file size
  or with the known block-page size, and keep the scanner allowlist current.
- **FP lead `10.0.2.31`:** Rust/C++ docs pages with `::` in the *page title*,
  so it's in the URL path. The hunt checklist's claim that "`::` is never
  legitimate in these URL paths" is too strong for Confluence page URLs.
  **Tuning hint:** only flag `::` that sits directly before a path segment such
  as `WEB-INF`, `META-INF` or `conf`, or before another `::`/`..`.
- **Caught because of a change in this release:** `192.0.2.77` sends `::` as
  `%3A%3A`. The detector now percent-decodes the path once before matching.
  Before that change this was a false negative.

### 07 BeyondTrust CVE-2026-102764 (1 TP incident, 1 FP incident, 1 FN)

- **FP incident `bt-rs-04`:** a dbus package upgrade sets the SUID bit on
  `/usr/lib/dbus-1.0/dbus-daemon-launch-helper` (outside `/usr/bin`, so
  `SUID_ROOT` fires), and the reboot it needs resets the sequence counter to 1
  (`LOG_GAP`). Two artifact types within 24 h, so an incident. **Tuning hint:**
  honor `pkg=<name>` (package-managed), and treat a sequence reset that follows
  a `boot` event as a restart, not deletion.
- **FP leads:** `bt-rs-01` has an approved role change whose ticket reference
  has a typo (`CHG4471`, missing the dash). `bt-rs-02` has a vault read whose
  `account=` field the log forwarder dropped. `bt-rs-05` has the vault-sync
  service account rotated to `svc_vault_sync2`. All are reasonable to triage.
  None should page anyone at 3 a.m.
- **FN at incident level `bt-rs-06`:** a web shell (`thumb.php5`) and a new
  SOCKS5 listener **30 hours apart**. The 24 h correlation window splits them
  into one lead with two artifact types. **Tuning hint:** use a longer window
  (72 h) for high-severity pairs such as WEBSHELL + TUNNEL, or escalate any
  WEBSHELL on its own.

### 07 Nextcloud CVE-2026-110447 (1 TP incident, 0 FP incidents, 1 FN)

- **FP leads:** `10.0.1.33` opened a document titled `Budget $(draft) v2.xlsx`
  (the `$(` passes through `proxy.php`). `10.0.1.40` runs an old client that
  sends `../` in a `req=` path. `10.0.5.8` is the internal vulnerability
  scanner. **Tuning hint:** restrict the injection markers to the `status`
  parameter, and allowlist the scanner.
- **FN at incident level `192.0.2.150`:** a second operator runs commands
  through the already-dropped `shx7.php?c=` from a new IP that never sent a
  probe, so the per-IP correlation rates it only `SUSPICIOUS`. **Tuning hint:**
  any 2xx request to a `shx*.php?c=` shell is an incident on its own.
  Correlate per *server*, not only per source IP.

## Run it yourself

```bash
python3 tools/noisy_scorecard.py                     # the table above
cd 07-kev-hunting
python3 detect/cve-2026-21589-log-detect.py samples/noisy/confluence-access-noisy.log
python3 detect/cve-2026-102764-detect.py samples/noisy/appliance-noisy.log
python3 detect/cve-2026-110447-detect.py samples/noisy/nextcloud-access-noisy.log
cd ../02-python-ioc-analyzer
python3 ioc_analyzer.py --input sample_data/sample_cloudtrail_noisy.json --output noisy-report.md
```

Or open the [live demo](https://szzxli.github.io/soc-home-lab/web/demo.html)
and click **Run on noisy sample**. It scores the findings against the answer
key in your browser.

**Still synthetic.** Noisy is closer to real than clean, but it's still a
few thousand generated lines, not a production SOC's volume or variety. Passing
here shows the rules and the answer key agree. It doesn't show they'd work
on your telemetry.

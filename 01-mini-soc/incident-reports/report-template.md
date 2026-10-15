# Incident Report Template

> **FILLING GUIDE — read before you write.** Each section below has 1–2 lines
> of guidance in *italics*. Delete the guidance lines when you fill the
> report. Write for a reader who was not in the room: a hiring manager or a
> Tier-2 analyst should understand what happened and what you did without
> asking you. Facts first, opinions labeled. Never invent details — if you do
> not know something, write "Unknown" and say how you would find out.
>
> **Honesty rule for this lab:** only document incidents you actually
> investigated here. Do not present lab exercises as production incidents and
> do not present the illustrative example at the bottom of this file as real.

---

# Incident Report: [SHORT TITLE]

- **Report ID:** `IR-YYYY-NNN`
- **Date opened:** YYYY-MM-DD
- **Date closed:** YYYY-MM-DD (or "Open")
- **Author:** [name / role]
- **Status:** Open / Contained / Closed
- **Severity:** Low / Medium / High / Critical (and one line justifying it)

## 1. Summary

*2–4 sentences: what happened, what was affected, and the outcome. Someone
should be able to read only this section and brief their manager.*

## 2. Timeline

*One row per event, in UTC. Include detection, triage actions, containment,
and recovery — with the evidence source for each row (e.g. "CloudTrail event
ID …", "GuardDuty finding …").*

| Time (UTC) | Event | Evidence / source |
|---|---|---|
| YYYY-MM-DD HH:MM | | |

## 3. Scope & Impact

*What was affected (resource ARNs, accounts, data classifications) and what
was NOT affected — stating the negative scope is as important as the
positive. Quantify where possible: number of resources, duration of exposure,
whether data was confirmed accessed vs. merely exposed.*

## 4. Root Cause

*The underlying reason the incident was possible — not just the trigger.
Distinguish "how the attacker got in" from "why the control failed".
If the root cause is still unconfirmed, label it "Hypothesis" and list what
would confirm or refute it.*

## 5. Containment & Eradication

*Exactly what you did to stop the bleeding (with timestamps), in order —
revoked keys, isolated instances, reverted policies. Then what you did to
remove the attacker's foothold entirely (deleted persistence, rotated all
affected credentials). Link the commands or console paths used.*

## 6. Recovery

*How the affected systems were returned to normal operation: rebuilt from
known-good images, restored from backup, re-enabled after verification.
Include the verification step that proved it was safe ("verified by …").*

## 7. Lessons Learned

*At least one thing that worked (keep doing it) and one thing that failed
or was missing (fix it). Each lesson gets an owner and a due date, or it is
not a lesson — it is a wish.*
- [ ] Action item — Owner: … — Due: …

---

## Example (illustrative only)

# EXAMPLE — DO NOT PRESENT AS REAL
### The incident below is entirely fictional. It exists only to show what a
### filled-in report looks like. Never copy it into a portfolio or interview
### as something that happened.

# Incident Report: Unauthorized S3 bucket policy change (EXAMPLE — FICTIONAL)

- **Report ID:** `IR-2026-001`
- **Date opened:** 2026-10-14
- **Date closed:** 2026-10-14
- **Author:** Lab analyst (example)
- **Status:** Closed
- **Severity:** High — an S3 bucket containing lab data was readable by an external AWS account for ~40 minutes.

## 1. Summary (fictional)
At 14:02 UTC, GuardDuty raised `Policy:S3/BucketAnonymousAccessGranted` for
bucket `example-lab-bucket`. Investigation showed a bucket policy statement
added at 13:58 UTC granting `s3:GetObject` to an unknown external account.
The statement was removed at 14:20 UTC. No `GetObject` calls from the
external account were found in the exposure window.

## 2. Timeline (fictional)

| Time (UTC) | Event | Evidence / source |
|---|---|---|
| 2026-10-14 13:58 | Bucket policy updated with external-account grant | CloudTrail `PutBucketPolicy`, event ID `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` |
| 2026-10-14 14:02 | GuardDuty finding `Policy:S3/BucketAnonymousAccessGranted` (severity 8.0) | GuardDuty finding `f-0123456789abcdef` |
| 2026-10-14 14:10 | Triage started; grant confirmed unauthorized | Bucket policy JSON; no change ticket exists |
| 2026-10-14 14:20 | Malicious statement removed from bucket policy | CloudTrail `PutBucketPolicy` (removal) |
| 2026-10-14 15:05 | Exposure-window access review complete: no external reads | S3 server access logs, 13:58–14:20 window |

## 3. Scope & Impact (fictional)
Affected: one bucket (`arn:aws:s3:::example-lab-bucket`), ~120 lab objects,
exposed to account `193672423079` for 42 minutes. NOT affected: no other
buckets, no IAM principals, no EC2. Impact: exposure only — access logs show
zero `GetObject` calls from the external account, so no confirmed data access.

## 4. Root Cause (fictional)
Trigger: `PutBucketPolicy` call from a lab access key. Underlying cause: the
key had `s3:PutBucketPolicy` on `*` instead of scoped to specific buckets,
and no alert existed on bucket-policy changes. Hypothesis confirmed by the
key's attached policy (`LabBroadS3Policy`).

## 5. Containment & Eradication (fictional)
14:20 — removed the malicious statement via `aws s3api put-bucket-policy`
with the known-good policy. 14:35 — deactivated the lab access key
(`aws iam update-access-key --status Inactive`). 15:00 — replaced the broad
managed policy with a bucket-scoped policy; no other keys shared the broad
policy (verified via IAM Access Analyzer).

## 6. Recovery (fictional)
No rebuild needed — no compute was involved. Verified safe by: (1) current
bucket policy matches the known-good baseline (diffed), (2) 24h of
post-incident access logs show no external reads, (3) GuardDuty finding
archived after verification.

## 7. Lessons Learned (fictional)
- Worked: GuardDuty S3 protection + 15-minute publishing gave a 4-minute
  detection gap — keep this configuration.
- Failed: no preventive control on `PutBucketPolicy`; any key could do this.
- [ ] Add EventBridge alert on `PutBucketPolicy` for all buckets — Owner: lab analyst — Due: 2026-10-21
- [ ] Scope all lab IAM policies to named resources, remove `*` S3 grants — Owner: lab analyst — Due: 2026-10-21

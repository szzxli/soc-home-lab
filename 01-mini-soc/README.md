# 01-mini-soc — Mini SOC on AWS

A minimal, real AWS detection lab: CloudTrail audit logging → encrypted S3 log
store → GuardDuty threat detection → Security Hub aggregation, with three
safe attack simulations (Stratus Red Team) and a Tier-1 triage workflow.

## Problem this solves

SOC analyst job postings ask for hands-on experience with SIEM-style
workflows — triaging alerts, reading audit logs, containing threats — that is
hard to get without working in a SOC. This project builds a working
mini-SOC in your own AWS account for ~$5–15/month, generates *real*
detections by safely simulating attacks, and documents the full
detect → triage → contain loop the way an employer expects to see it.

## 15-minute quickstart

> Requires: your **own** AWS account (never an employer's), Terraform ≥ 1.5,
> AWS CLI credentials, and the [Stratus Red Team](https://stratus-red-team.cloud/getting-started/)
> binary. All commands run from this directory.

```bash
# 1. Build the lab (~5 min)
cd terraform
terraform init
terraform plan        # read it — know what you're about to create
terraform apply       # type "yes"

# 2. Simulate an attack (~2 min)
stratus warmup   aws.exfiltration.s3-backdoor-bucket-policy
stratus detonate aws.exfiltration.s3-backdoor-bucket-policy

# 3. See the detection (~15-30 min for GuardDuty; CloudTrail is near-real-time)
#    GuardDuty console -> Findings, or:
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy
#    Full scenario walkthrough: attack-runbook.md (Scenario 1)

# 4. Triage it like a Tier-1 analyst
#    Follow triage-guide.md -> Policy:S3/* row

# 5. Clean up the attack, then the lab
stratus cleanup aws.exfiltration.s3-backdoor-bucket-policy
stratus status        # must show COLD
cd terraform && terraform destroy   # type "yes" — destroys everything
```

Next: run scenarios 2 and 3 in `attack-runbook.md`, then write up one
detonation using `incident-reports/report-template.md`.

## What's in this project

| File | What it is |
|---|---|
| `terraform/main.tf` | The whole lab as code: VPC, encrypted S3 log bucket, multi-region CloudTrail, GuardDuty, Security Hub, least-privilege analyst IAM role. Every resource has a "why it exists" comment. |
| `architecture.md` | Data-flow diagram (mermaid) + design decisions (why multi-region trail, why encrypted log bucket, why no NAT gateway). |
| `attack-runbook.md` | 3 safe attack simulations with real [Stratus Red Team](https://stratus-red-team.cloud) technique IDs (verified against the official catalog): S3 exfiltration, IAM privilege escalation, EC2 mining-setup attempt. Includes exact commands, expected findings, and screenshot points. |
| `triage-guide.md` | GuardDuty finding types → triage steps: which logs to check, severity judgment, containment commands, escalation criteria. |
| `incident-reports/report-template.md` | Blank incident report template with per-field filling guide, plus a clearly marked **fictional** example (labeled EXAMPLE — DO NOT PRESENT AS REAL). Only real lab work goes in filled reports. |

## Skills demonstrated (mapped to SOC analyst JD keywords)

- **Security monitoring & triage** — worked GuardDuty finding queues, applied a
  severity model (Low/Medium/High/Critical), and made triage decisions.
- **Log analysis** — read CloudTrail events (`PutBucketPolicy`,
  `UpdateLoginProfile`, `RunInstances`) to answer "who did what, from where".
- **Threat detection engineering** — reasoned about sensor coverage: which
  attacks GuardDuty catches vs. which need CloudTrail analytics (scenarios 2–3).
- **Incident response** — containment playbooks: isolate EC2, revoke IAM
  credentials, revert S3 policies; escalation criteria for Tier-2 handoff.
- **Cloud security (AWS)** — GuardDuty, Security Hub (ASFF), CloudTrail,
  S3 security controls (SSE, block public access), IAM least privilege.
- **Infrastructure as code** — full lab in Terraform with cost controls.
- **Adversary emulation** — Stratus Red Team attack simulations mapped to
  MITRE ATT&CK tactics (Exfiltration, Privilege Escalation, Execution).
- **Documentation** — architecture decision records, runbooks, incident
  reports written for a reader who wasn't in the room.

## Cost & cleanup

- **Cost:** ~$5–15/month with the minimum configuration (see the cost
  breakdown at the top of `terraform/main.tf`). GuardDuty includes a 30-day
  free trial for new detectors. Set a billing alarm on the account.
- **Cleanup:** attacks first, infrastructure second —
  `stratus cleanup <technique-id>` (verify `stratus status` shows COLD),
  then `terraform destroy`. The S3 bucket uses `force_destroy` so the destroy
  does not fail on leftover log objects.
- **Never** run the attack simulations outside your own lab account.

# Attack Runbook — 01-mini-soc

> Three safe, self-contained attack simulations for the mini-SOC lab.
> Each one uses a real technique from the official
> [Stratus Red Team](https://stratus-red-team.cloud) catalog
> (DataDog open source, Apache 2.0). Technique IDs below were verified against
> the official catalog list page and the per-technique docs in
> [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team)
> on 2026-10-14 — the exact verification pages are cited per scenario.
>
> **Safety rules (non-negotiable):**
> - Run these ONLY in your own lab AWS account — never in an employer's account.
> - Always `warmup` → `detonate` → verify findings → `cleanup`.
> - Confirm `stratus status` shows **COLD** for every technique before you run
>   `terraform destroy`.
> - All "expected findings" below are **expected, not observed** — they describe
>   what the lab is designed to produce, not incidents that have happened.

## Global prerequisites

- The lab from `terraform/` is applied (`terraform apply` succeeded).
- [Stratus Red Team](https://stratus-red-team.cloud/getting-started/) installed:
  `stratus version` works.
- AWS CLI credentials for the lab account with enough permission to let
  Stratus provision its prerequisites (the techniques below create an S3
  bucket, an IAM user, and an IAM role during warmup).
- Stratus and Terraform target the **same region** (`us-west-2` by default).
  GuardDuty and Security Hub are regional — findings appear in the region
  where the detonation happened.

Useful lifecycle commands (valid for every technique):

```bash
stratus warmup   <technique-id>   # provision prerequisites (idempotent)
stratus status                    # WARM = ready, COLD = cleaned up
stratus detonate <technique-id>   # run the attack simulation
stratus cleanup  <technique-id>   # tear down what warmup created
```

---

## Scenario 1 — S3 data-exfiltration simulation

| Field | Value |
|---|---|
| Technique ID | `aws.exfiltration.s3-backdoor-bucket-policy` |
| Official title | "Backdoor an S3 Bucket via its Bucket Policy" |
| MITRE ATT&CK mapping | Exfiltration (per official technique doc) |
| Verification source | Official catalog list: `https://stratus-red-team.cloud/attack-techniques/list/` · Technique doc: `https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy.md` |

### Objective
Simulate an attacker backdooring an S3 bucket policy so that an external,
attacker-controlled AWS account can read the bucket's objects. Practice
detecting cross-account access grants via CloudTrail and GuardDuty S3
protection, then triage it like a Tier-1 analyst.

### Prerequisites
- `stratus warmup` for this technique creates a fresh S3 bucket (prerequisite:
  permission to `s3:CreateBucket` and `s3:PutBucketPolicy` in the lab account).
- The lab's GuardDuty detector has S3 protection enabled (it does — see
  `terraform/main.tf`).

### Run it

```bash
stratus warmup aws.exfiltration.s3-backdoor-bucket-policy
stratus status   # expect WARM

stratus detonate aws.exfiltration.s3-backdoor-bucket-policy
# Detonation backdoors the bucket policy, granting s3:GetObject,
# s3:GetBucketLocation and s3:ListBucket to an external AWS account
# (arn:aws:iam::193672423079:root — a fictitious attacker account
# used by Stratus Red Team).
```

Wait 15–30 minutes (GuardDuty finding publishing is set to 15 minutes in this
lab; the default would be up to 6 hours), then check for findings. Afterwards:

```bash
stratus cleanup aws.exfiltration.s3-backdoor-bucket-policy
stratus status   # expect COLD
```

### Expected findings (expected — not observed incidents)
- **CloudTrail:** a `PutBucketPolicy` event on the backdoored bucket, with the
  request showing a new `Statement` granting access to principal
  `arn:aws:iam::193672423079:root`. This is the primary, deterministic signal.
- **GuardDuty:** `Policy:S3/BucketAnonymousAccessGranted` is the documented
  finding type for bucket-policy backdoors (per the official technique doc's
  Detection section; it fires when the bucket is made broadly accessible).
- **IAM Access Analyzer:** an active finding for cross-account S3 access,
  since the policy grants an external account — check Access Analyzer in the
  console as the second corroborating source.

### Where to screenshot (for the portfolio / report)
1. GuardDuty console → Findings → filter by finding type
   `Policy:S3/BucketAnonymousAccessGranted` → open the finding detail pane
   (shows severity, resource ARN, and the "unusual" principal).
2. S3 console → the Stratus-created bucket → Permissions → Bucket policy →
   highlight the `Statement` with the external principal.
3. CloudTrail console → Event history → Lookup by event name `PutBucketPolicy` →
   open the event JSON (shows `userIdentity`, `requestParameters`, timestamp).
4. IAM Access Analyzer → Findings → the cross-account S3 finding.

### Triage drill
Follow `triage-guide.md` → the `Policy:S3/*` row: confirm the grant is
unauthorized (the external account is not a known partner), then contain by
reverting the bucket policy (`aws s3api delete-bucket-policy` or restoring the
previous policy version) and escalate per the guide.

---

## Scenario 2 — IAM privilege escalation / anomalous API call

| Field | Value |
|---|---|
| Technique ID | `aws.privilege-escalation.iam-update-user-login-profile` |
| Official title | "Change IAM user password" |
| MITRE ATT&CK mapping | Privilege Escalation (per official technique doc) |
| Verification source | Official catalog list: `https://stratus-red-team.cloud/attack-techniques/list/` · Technique doc: `https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/AWS/aws.privilege-escalation.iam-update-user-login-profile.md` |

### Objective
Simulate an attacker who already has IAM API access changing a user's console
password (a classic persistence / privilege-escalation step: lock the
legitimate user out, keep access for themselves). The lesson of this scenario
is that **not every attack produces a GuardDuty finding** — this one is caught
by reading CloudTrail, which is exactly why a SOC analyst must know both.

### Prerequisites
- `stratus warmup` for this technique creates an IAM user with a login profile
  (prerequisite: permission to `iam:CreateUser`, `iam:CreateLoginProfile`).

### Run it

```bash
stratus warmup aws.privilege-escalation.iam-update-user-login-profile
stratus status   # expect WARM

stratus detonate aws.privilege-escalation.iam-update-user-login-profile
# Detonation updates the user's login profile — i.e. changes its password.

stratus cleanup aws.privilege-escalation.iam-update-user-login-profile
stratus status   # expect COLD
```

### Expected findings (expected — not observed incidents)
- **CloudTrail:** an `UpdateLoginProfile` event for the Stratus-created user.
  Per the official technique doc, this is the documented detection path —
  filter Event history by event name `UpdateLoginProfile`. There is **no**
  GuardDuty finding type documented for this technique; the expected outcome
  is a CloudTrail-only detection. Write that down as a coverage observation:
  password-change anomalies are a SIEM/CloudTrail-analytics use case, not a
  GuardDuty use case.
- Optional stretch: build a CloudWatch metric filter / EventBridge rule on
  `UpdateLoginProfile` to turn this into an alert — that is a second portfolio
  artifact from the same scenario.

### Where to screenshot
1. CloudTrail console → Event history → event name `UpdateLoginProfile` →
   event JSON (note `requestParameters.userName` and the source IP).
2. IAM console → Users → the Stratus-created user → Security credentials →
   "Console password" last-changed timestamp.
3. (Stretch) EventBridge rule / metric filter configuration, if built.

### Triage drill
Follow `triage-guide.md` → the `PrivilegeEscalation:IAMUser/*` row and the
general IAM playbook: verify whether the password change was authorized
(check with the "user" — in the lab, it was you), then contain by resetting
credentials, enabling MFA, and reviewing `GetCredentialReport`.

---

## Scenario 3 — EC2 crypto-mining setup attempt (unusual instance launch)

| Field | Value |
|---|---|
| Technique ID | `aws.execution.ec2-launch-unusual-instances` |
| Official title | "Launch Unusual EC2 instances" |
| MITRE ATT&CK mapping | Execution (per official technique doc) |
| Verification source | Official catalog list: `https://stratus-red-team.cloud/attack-techniques/list/` · Technique doc: `https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/AWS/aws.execution.ec2-launch-unusual-instances.md` |

### Objective
Simulate the first step of a crypto-mining attack: an attacker attempting to
launch unusual (GPU/compute-heavy) EC2 instance types. By design the launch
attempts **fail** (warmup creates an IAM role without EC2 launch permissions,
so nothing actually runs and nothing is billed) — which makes this scenario
safe, fast, and a perfect lesson in detecting *attempted* malicious behavior
in CloudTrail rather than waiting for a GuardDuty alert that will never come.

### Prerequisites
- `stratus warmup` creates the unprivileged IAM role (prerequisite:
  permission to `iam:CreateRole`).

### Run it

```bash
stratus warmup aws.execution.ec2-launch-unusual-instances
stratus status   # expect WARM

stratus detonate aws.execution.ec2-launch-unusual-instances
# Detonation attempts to launch several unusual EC2 instance types.
# The calls fail with Client.UnauthorizedOperation — by design.

stratus cleanup aws.execution.ec2-launch-unusual-instances
stratus status   # expect COLD
```

### Expected findings (expected — not observed incidents)
- **CloudTrail:** `RunInstances` events with `errorCode`
  `Client.UnauthorizedOperation`, `eventSource` `ec2.amazonaws.com`, and
  `requestParameters.instanceType` showing the attempted unusual instance
  types. Per the official technique doc, this is the documented detection
  path. You may also see `VcpuLimitExceeded` errors depending on account limits.
- **GuardDuty:** no finding is expected here — the instances never launch, so
  there is no network behavior for GuardDuty to analyze. The interview-ready
  takeaway: *if* the launches had succeeded and mining had started,
  `CryptoCurrency:EC2/BitcoinTool.B!DNS` would be the expected GuardDuty
  finding type — a good example of reasoning about what a sensor can and
  cannot see.

### Where to screenshot
1. CloudTrail console → Event history → event name `RunInstances` →
   open an event and highlight `errorCode: Client.UnauthorizedOperation`
   and `requestParameters.instanceType`.
2. EC2 console → Instances → confirm no unexpected instances are running
   (negative evidence is evidence — screenshot the empty/filtered list).
3. (Optional) A second CloudTrail lookup showing the *attempted* instance
   types across the event series.

### Triage drill
Follow `triage-guide.md` → the `CryptoCurrency:EC2/*` row for the
"what-if-it-had-succeeded" path, and the general EC2 playbook: identify the
calling principal from the CloudTrail event, determine whether the role is
compromised, and contain by revoking the role's sessions / rotating
credentials.

---

## After all scenarios

```bash
stratus status    # every technique must show COLD
stratus cleanup --all   # belt and suspenders: remove anything Stratus created
```

Only then run `terraform destroy` (see `README.md` → Cleanup).

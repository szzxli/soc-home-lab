# Triage Guide — GuardDuty findings in 01-mini-soc

> How a Tier-1 SOC analyst works a GuardDuty finding in this lab:
> **confirm → scope → contain → escalate.** Every finding below is a real
> GuardDuty finding type (see the
> [GuardDuty finding types documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html)).
> Severity numbers follow the GuardDuty scale: **Low 1.0–3.9, Medium 4.0–6.9,
> High 7.0–8.9, Critical 9.0–10.**

## The 5-minute triage loop (use for every finding)

1. **Read the finding, not just the title.** Open the finding detail: note the
   severity, the resource (instance ID / bucket / IAM principal), the
   `service.action` fields, and the first/last seen timestamps.
2. **Check CloudTrail first.** In CloudTrail Event history (or the S3 log
   bucket), look up the principal and API calls around the finding window.
   CloudTrail answers "who did what, from where" — GuardDuty only answers
   "something looks wrong".
3. **Decide severity for yourself.** GuardDuty's score is a starting point;
   adjust it with context: production vs. lab, known vs. unknown principal,
   single event vs. pattern, business hours vs. 3 AM.
4. **Contain if it is real** (commands in the playbooks below).
5. **Escalate** when the scope exceeds one resource, when you cannot confirm
   the principal's legitimacy, or when the severity is High/Critical.

## Finding-type quick reference

| Finding type | What it usually means | First logs to check | Severity guidance | Containment | Escalate when |
|---|---|---|---|---|---|
| `Policy:S3/BucketAnonymousAccessGranted` | S3 bucket policy now allows public/anonymous access | CloudTrail `PutBucketPolicy` on the bucket; bucket policy JSON | Start **High** — public data exposure until proven otherwise | Revert/remove the offending policy statement immediately | Data was actually accessed (check S3 access logs), or the grant came from an unknown principal |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | EC2 instance querying domains linked to Bitcoin mining pools | VPC Flow Logs + DNS query logs for the instance; CloudTrail `RunInstances` (who launched it) | **High** — active resource abuse, real money burning | Stop the instance (`aws ec2 stop-instances`); if compromise is confirmed, isolate via quarantine security group | Multiple instances, or the launch principal is compromised |
| `Backdoor:EC2/C&CActivity.B!DNS` | Instance talking to a known command-and-control domain | DNS logs; VPC Flow Logs (destinations, ports); CloudTrail for how the instance was launched | **High/Critical** — assume compromised until proven otherwise | Isolate the instance (remove all security groups / attach quarantine SG); snapshot EBS for forensics *before* terminating | Any lateral-movement indicators (new IAM activity, unusual API calls from the instance role) |
| `Trojan:EC2/DNSDataExfiltration` | DNS tunneling / data exfiltration over DNS | DNS query logs (query volume, entropy of subdomains); VPC Flow Logs | **High** — data may already be leaving | Isolate the instance; preserve DNS logs | Volume suggests bulk exfiltration, or sensitive-data stores are in scope |
| `UnauthorizedAccess:EC2/SSHBruteForce` | Repeated SSH login attempts against an instance | VPC Flow Logs (source IPs, port 22); instance auth logs (`/var/log/secure`) | **Medium** by itself; **High** if followed by a successful login | Block offending IPs at the security group / NACL; verify no successful logins | A login succeeded (check `Accepted` in auth logs), or attempts come from many sources (distributed) |
| `Impact:EC2/PortSweep` | Instance probing many ports on many hosts | VPC Flow Logs (destination port spread from one source) | **Medium–High** — reconnaissance, often pre-attack | Isolate the scanning instance if it is yours and unauthorized | The scanner is external and targeting you → escalate to IR; internal scanner → verify with the owner |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | IAM user/role granted admin-level permissions | CloudTrail `AttachUserPolicy` / `AttachRolePolicy` / `CreatePolicyVersion` | **High** — privilege escalation in progress | Revoke the grant (detach policy / delete policy version); disable the principal's keys | Grant came from a compromised admin, or the principal is already using the permissions |
| `Persistence:IAMUser/NetworkPermissions` | IAM principal granted network-modifying permissions (persistence setup) | CloudTrail IAM policy-change events | **Medium–High** | Same as above: detach, rotate keys | Combined with other persistence signals (new users, new keys) |
| `UnauthorizedAccess:IAMUser/TorIPCaller` | IAM API calls originating from a Tor exit node | CloudTrail (source IP, user agent, API calls made) | **High** — legitimate users do not administer AWS over Tor | Revoke active sessions (`aws iam` key deactivation); force password + MFA reset | Any successful sensitive API call (IAM changes, data access) |

> `!` in a finding type (e.g. `BitcoinTool.B!DNS`) means the evidence came
> from DNS logs. No suffix = evidence from Flow Logs / CloudTrail.

## Containment playbooks (lab-safe commands)

### A compromised or abusive EC2 instance
```bash
# 1. Isolate: strip all security groups, attach a quarantine SG with no rules
aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 \
  --groups sg-0quarantine0000000

# 2. Preserve evidence BEFORE terminating: snapshot the root volume
aws ec2 create-snapshot --volume-id vol-0123456789abcdef0 \
  --description "forensic-snapshot $(date -u +%Y%m%dT%H%M%SZ)"

# 3. Stop billing / abuse
aws ec2 stop-instances --instance-ids i-0123456789abcdef0
```
Then: find the launch principal in CloudTrail (`RunInstances`), rotate any
credentials on that principal, and check whether the same AMI/key pair was
used elsewhere.

### A suspicious IAM principal (user / role / access key)
```bash
# 1. Kill programmatic access immediately (reversible)
aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive

# 2. Revoke all active sessions (forces re-authentication)
aws iam delete-user-policy  # remove inline policies, or:
aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>

# 3. Force credential reset + require MFA before the user returns
aws iam delete-login-profile --user-name <user>   # removes console password
```
Then: run `aws iam generate-credential-report` and review every key, MFA
device, and last-used timestamp for the principal.

### A backdoored S3 bucket policy
```bash
# 1. Remove the malicious grant NOW (fastest: delete the whole bucket policy
#    if the bucket should be private, then re-apply the known-good version)
aws s3api delete-bucket-policy --bucket <bucket-name>
```
Then: check S3 server access logging / CloudTrail data events for `GetObject`
calls from the external principal during the exposure window, and treat any
confirmed reads as a data-breach scoping exercise.

## When to escalate (the Tier-1 → Tier-2 handoff rule)

Escalate — do not keep investigating solo — when **any** of these is true:

- Severity High/Critical and you cannot confirm the activity is authorized.
- More than one resource or principal is involved (lateral movement suspected).
- Customer / personal data may have been accessed (potential breach scoping).
- The principal belongs to someone else and you cannot reach them to confirm.
- Containment would cause production downtime you are not authorized to cause.

An escalation note must contain: finding type + severity, the exact resource
ARNs, the CloudTrail event IDs / timestamps you already checked, what you
contained, and what is still unknown. ("Unknowns" are the most valuable part
of a handoff.)

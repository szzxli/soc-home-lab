#!/usr/bin/env python3
"""Generate sample_cloudtrail_noisy.json: a NOISY synthetic CloudTrail log.

sample_cloudtrail.json (19 records) is tidy on purpose. This variant is closer
to a real account's day:
  * volume       ~3,000 records of routine read/write API traffic
  * look-alikes  benign activity that trips the three demo heuristics:
                 autoscaling RunInstances, nightly key rotation, CI/CD policy
                 attachments, employees logging in from home / hotel networks,
                 a shared office NAT where several people mistype passwords,
                 console sign-ins that CloudTrail records as "AWS Internal"
  * missing data records without userIdentity / eventTime / sourceIPAddress,
                 empty objects, null responseElements, non-object entries
  * attacks      a brute force -> console login -> persistence -> logging
                 disabled -> crypto-mining chain, plus a low-and-slow password
                 spray that per-IP thresholds cannot see

Everything is SYNTHETIC and deterministic (fixed seed). External addresses
come from documentation ranges (RFC 5737). The answer key is written to
sample_cloudtrail_noisy.truth.json; expected TP/FP numbers are in
../../NOISY_DATA.md.

Usage: python3 generate_noisy.py [outdir]
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20261021
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
DAY = datetime(2026, 10, 12, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
CORP = ["13.52.44.19", "13.52.44.20", "72.14.9.120"]   # in the analyzer's common-range table
USERS = [f"{n}" for n in ("alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan",
                          "judy", "mallory-qa", "niaj", "olivia", "peggy", "rupert", "sybil", "trent",
                          "victor", "walter", "yolanda")]
READS = [("ec2.amazonaws.com", "DescribeInstances"), ("s3.amazonaws.com", "ListBuckets"),
         ("ec2.amazonaws.com", "DescribeSecurityGroups"), ("iam.amazonaws.com", "ListUsers"),
         ("sts.amazonaws.com", "GetCallerIdentity"), ("logs.amazonaws.com", "DescribeLogGroups"),
         ("s3.amazonaws.com", "GetBucketAcl"), ("cloudwatch.amazonaws.com", "GetMetricData"),
         ("lambda.amazonaws.com", "ListFunctions20150331"), ("rds.amazonaws.com", "DescribeDBInstances")]


def ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def user(name):
    return {"type": "IAMUser", "principalId": "AIDA" + name.upper().replace("-", "")[:12],
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT, "userName": name}


def role(rname, session):
    return {"type": "AssumedRole", "principalId": f"AROAEXAMPLE{rname.upper()[:8]}:{session}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{rname}/{session}", "accountId": ACCOUNT,
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": rname}}}


def rec(t, source, name, ident, ip, params=None, resp=None, error=None, **extra):
    r = {"eventVersion": "1.08", "eventTime": ts(t), "eventSource": source, "eventName": name,
         "awsRegion": "us-east-1", "sourceIPAddress": ip, "userIdentity": ident,
         "requestParameters": params, "responseElements": resp}
    if error:
        r["errorCode"] = error
    r.update(extra)
    return r


def login(t, ident, ip, ok=True):
    return rec(t, "signin.amazonaws.com", "ConsoleLogin", ident, ip, None,
               {"ConsoleLogin": "Success" if ok else "Failure"},
               None if ok else "Failed authentication", eventType="AwsConsoleSignIn")


def build(rng):
    R = []
    home = {u: f"13.52.44.{rng.randint(10, 60)}" if rng.random() < 0.8 else rng.choice(CORP) for u in USERS}
    # --- routine: morning console logins from the office + ~2,600 API calls
    for u in USERS:
        R.append(login(DAY + timedelta(hours=8, minutes=rng.randint(0, 59)), user(u), home[u]))
    for _ in range(2600):
        u = rng.choice(USERS)
        src, name = rng.choice(READS)
        t = DAY + timedelta(seconds=rng.randint(7 * 3600, 19 * 3600))
        ip = home[u] if rng.random() < 0.7 else f"{rng.choice(['52', '54', '3'])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        R.append(rec(t, src, name, user(u) if rng.random() < 0.6 else role("DevOpsRole", u), ip, {}))
    # service-to-service noise (no human, sourceIPAddress is a service name)
    for m in range(0, 24 * 60, 10):
        t = DAY + timedelta(minutes=m, seconds=5)
        R.append(rec(t, "kms.amazonaws.com", "Decrypt", {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"},
                     "lambda.amazonaws.com", {"encryptionContext": {}}))
    # --- LOOK-ALIKE: autoscaling launches instances every 2h (suspicious_api: RunInstances)
    for h in range(0, 24, 2):
        t = DAY + timedelta(hours=h, minutes=1)
        R.append(rec(t, "ec2.amazonaws.com", "RunInstances",
                     {"type": "AWSService", "invokedBy": "autoscaling.amazonaws.com"}, "autoscaling.amazonaws.com",
                     {"instanceType": "t3.medium", "minCount": 1, "maxCount": 1}))
    # --- LOOK-ALIKE: nightly access-key rotation for service users (CreateAccessKey)
    for i, svc in enumerate(["svc-backup", "svc-etl", "svc-metrics", "svc-reports"]):
        t = DAY + timedelta(hours=2, minutes=i)
        R.append(rec(t, "iam.amazonaws.com", "CreateAccessKey", role("KeyRotationLambda", "rotation"),
                     "52.94.7.15", {"userName": svc}))
    # --- LOOK-ALIKE: CI/CD deploy attaches managed policies to app roles (AttachRolePolicy)
    for i, r_ in enumerate(["app-api-role", "app-worker-role"]):
        t = DAY + timedelta(hours=15, minutes=30 + i)
        R.append(rec(t, "iam.amazonaws.com", "AttachRolePolicy", role("terraform-ci", "gha-run-88412"),
                     "54.183.20.7", {"roleName": r_, "policyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}))
    # --- LOOK-ALIKE: employees signing in from home ISPs / hotel Wi-Fi (unusual_geo)
    for u, ip, h in (("erin", "198.51.100.14", 20), ("grace", "198.51.100.88", 21), ("trent", "192.0.2.44", 6)):
        R.append(login(DAY + timedelta(hours=h, minutes=12), user(u), ip))
    # --- LOOK-ALIKE: console sign-in recorded with sourceIPAddress "AWS Internal"
    R.append(login(DAY + timedelta(hours=13, minutes=2), role("AWSReservedSSO_Admin", "olivia"), "AWS Internal"))
    # --- LOOK-ALIKE: shared office NAT, Monday password-expiry morning: 5 people mistype once each
    for i, u in enumerate(["bob", "carol", "dave", "frank", "heidi"]):
        t = DAY + timedelta(hours=9, minutes=1 + i, seconds=13)
        R.append(login(t, user(u), "13.52.44.19", ok=False))
        R.append(login(t + timedelta(seconds=40), user(u), "13.52.44.19"))
    # true negatives: scattered single failed logins (below threshold)
    for _ in range(25):
        u = rng.choice(USERS)
        R.append(login(DAY + timedelta(seconds=rng.randint(7 * 3600, 19 * 3600)), user(u), home[u], ok=False))
    # --- MISSING / EMPTY FIELDS
    t = DAY + timedelta(hours=11)
    R.append({"eventVersion": "1.08", "eventTime": ts(t), "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
              "sourceIPAddress": "13.52.44.19"})                                  # no userIdentity
    R.append(rec(t, "ec2.amazonaws.com", "DescribeVpcs", {}, "13.52.44.19", {}))  # empty userIdentity
    R.append({"eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
              "userIdentity": user("ivan"), "sourceIPAddress": "13.52.44.30"})    # no eventTime
    R.append(rec(t, "ec2.amazonaws.com", "DescribeInstances", user("judy"), "", {}))  # empty sourceIPAddress
    bad = login(t, user("judy"), "13.52.44.31", ok=False)
    bad["eventTime"] = "n/a"                                                      # unparseable time
    R.append(bad)
    R.append(rec(t, "iam.amazonaws.com", "ListRoles", user("peggy"), "13.52.44.32", None, None))
    nul = login(t + timedelta(minutes=1), user("peggy"), "13.52.44.32")
    nul["responseElements"] = None                                               # null responseElements
    R.append(nul)
    R.append({"eventName": None, "eventTime": ts(t)})                           # almost empty
    R += [None, "truncated-record", 42]                                          # not even objects
    # --- MALICIOUS: password spray, one try every 15 min across users (per-IP window misses it)
    for i in range(16):
        R.append(login(DAY + timedelta(hours=1, minutes=15 * i), user(USERS[i]), "198.51.100.200", ok=False))
    # --- MALICIOUS: brute force -> login -> persistence -> defense evasion -> mining
    atk = "203.0.113.66"
    t0 = DAY + timedelta(hours=22, minutes=3)
    for i in range(14):
        R.append(login(t0 + timedelta(seconds=25 * i), user("dbadmin"), atk, ok=False))
    t1 = t0 + timedelta(minutes=7)
    R.append(login(t1, user("dbadmin"), atk))
    R.append(rec(t1 + timedelta(minutes=2), "iam.amazonaws.com", "CreateUser", user("dbadmin"), atk, {"userName": "backup-svc2"}))
    R.append(rec(t1 + timedelta(minutes=3), "iam.amazonaws.com", "AttachUserPolicy", user("dbadmin"), atk,
                 {"userName": "backup-svc2", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    R.append(rec(t1 + timedelta(minutes=4), "iam.amazonaws.com", "CreateAccessKey", user("dbadmin"), atk, {"userName": "backup-svc2"}))
    R.append(rec(t1 + timedelta(minutes=6), "cloudtrail.amazonaws.com", "StopLogging", user("backup-svc2"), atk,
                 {"name": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail"}))
    for i in range(3):
        R.append(rec(t1 + timedelta(minutes=8 + i), "ec2.amazonaws.com", "RunInstances", user("backup-svc2"), atk,
                     {"instanceType": "p3.16xlarge", "minCount": 4, "maxCount": 4}))
    # shuffle within the day: real exports are only roughly time-ordered
    rng.shuffle(R)
    truth = {
        "_comment": "Answer key for sample_cloudtrail_noisy.json. A finding is a TRUE positive if its "
                    "source IP is in malicious_ips or its actor is in malicious_actors; otherwise it is a "
                    "FALSE positive. 'expected' lists the detections a good rule set should raise; any "
                    "not raised are false negatives.",
        "malicious_ips": [atk, "198.51.100.200"],
        "malicious_actors": ["dbadmin", "backup-svc2"],
        "expected": [
            {"detector": "brute_force", "ip": atk},
            {"detector": "unusual_geo", "ip": atk},
            {"detector": "suspicious_api", "event": "AttachUserPolicy", "actor": "dbadmin"},
            {"detector": "suspicious_api", "event": "CreateAccessKey", "actor": "dbadmin"},
            {"detector": "suspicious_api", "event": "StopLogging", "actor": "backup-svc2"},
            {"detector": "suspicious_api", "event": "RunInstances", "actor": "backup-svc2"},
            {"detector": "brute_force", "ip": "198.51.100.200", "note": "low-and-slow spray, 1 try / 15 min"},
        ],
        "look_alikes": {
            "autoscaling.amazonaws.com": "RunInstances by the EC2 Auto Scaling service",
            "KeyRotationLambda": "nightly CreateAccessKey for service users",
            "terraform-ci": "CI/CD AttachRolePolicy during a deploy",
            "198.51.100.14 / 198.51.100.88 / 192.0.2.44": "employees signing in from home / hotel networks",
            "AWS Internal": "console sign-in recorded without a public IP",
            "13.52.44.19": "shared office NAT: 5 different users mistype once each",
        },
    }
    return {"Records": R}, truth


def main():
    data, truth = build(random.Random(SEED))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sample_cloudtrail_noisy.json").write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    (OUT / "sample_cloudtrail_noisy.truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    print(f"wrote sample_cloudtrail_noisy.json: {len(data['Records'])} records")


if __name__ == "__main__":
    main()

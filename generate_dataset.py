"""
Cloud AI Defender – CloudTrail Dataset Generator
Generates a realistic labeled dataset for ML training + dashboard upload testing.
FREE: No AWS account needed. Simulates real CloudTrail event structure.
Run: python generate_dataset.py
"""

import pandas as pd
import numpy as np
import random
import json
from datetime import datetime, timedelta
import os

random.seed(42)
np.random.seed(42)

# ── AWS CloudTrail event catalog ─────────────────────────────────────────────
EVENT_CATALOG = {
    "NORMAL": [
        ("ConsoleLogin",        "signin.amazonaws.com",         0.20),
        ("DescribeInstances",   "ec2.amazonaws.com",            0.18),
        ("GetCallerIdentity",   "sts.amazonaws.com",            0.15),
        ("ListBuckets",         "s3.amazonaws.com",             0.14),
        ("AssumeRole",          "sts.amazonaws.com",            0.12),
        ("DescribeSecurityGroups","ec2.amazonaws.com",          0.10),
        ("GetObject",           "s3.amazonaws.com",             0.11),
    ],
    "SUSPICIOUS": [
        ("GetSecretValue",      "secretsmanager.amazonaws.com", 0.20),
        ("PutBucketPolicy",     "s3.amazonaws.com",             0.18),
        ("RunInstances",        "ec2.amazonaws.com",            0.15),
        ("AuthorizeSecurityGroupIngress","ec2.amazonaws.com",   0.15),
        ("CreateAccessKey",     "iam.amazonaws.com",            0.17),
        ("AttachUserPolicy",    "iam.amazonaws.com",            0.15),
    ],
    "ATTACK": [
        ("DeleteTrail",         "cloudtrail.amazonaws.com",     0.20),
        ("StopLogging",         "cloudtrail.amazonaws.com",     0.18),
        ("CreateUser",          "iam.amazonaws.com",            0.15),
        ("PutUserPolicy",       "iam.amazonaws.com",            0.12),
        ("TerminateInstances",  "ec2.amazonaws.com",            0.10),
        ("DeleteBucket",        "s3.amazonaws.com",             0.10),
        ("CreateLoginProfile",  "iam.amazonaws.com",            0.15),
    ],
}

LEGITIMATE_IPS  = ["10.0.0.1","172.16.0.5","192.168.1.100","54.239.28.85","52.94.228.167","34.224.10.5"]
MALICIOUS_IPS   = ["185.220.101.47","103.21.244.0","45.155.205.12","91.108.4.1","198.51.100.77","203.0.113.99","192.0.2.45"]
INTERNAL_IPS    = ["10.0.1.20","10.0.2.45","172.31.0.10","172.31.5.22"]
ALL_REGIONS     = ["ap-south-1","us-east-1","eu-west-2","ap-northeast-1","us-west-2","ca-central-1"]
HIGH_RISK_RGNS  = ["cn-north-1","sa-east-1","ru-central-1"]
USERS           = ["admin","root","john.doe","svc-billing","devops","api-user","svc-lambda","iam-readonly","terraform-svc"]
AGENTS_LEGIT    = ["aws-cli/2.13.0","Boto3/1.28.0","Terraform/1.5.0","console.aws.amazon.com","AWS Internal"]
AGENTS_SUSP     = ["python-requests/2.31","curl/7.88.1","Mozilla/5.0 (unknown)","Go-http-client/1.1","libwww-perl/6.07"]
ERRORS          = [None, None, None, None, "AccessDenied", "UnauthorizedOperation", "InvalidClientTokenId"]

def pick(lst, weights=None):
    return random.choices(lst, weights=weights, k=1)[0]

def generate_row(label, row_id, base_time):
    catalog = EVENT_CATALOG[label]
    events, sources, weights = zip(*catalog)
    idx = random.choices(range(len(events)), weights=weights)[0]
    event_name   = events[idx]
    event_source = sources[idx]

    # IP assignment based on label
    if label == "NORMAL":
        source_ip = pick(LEGITIMATE_IPS + INTERNAL_IPS)
        user_agent = pick(AGENTS_LEGIT)
        region     = pick(ALL_REGIONS)
        error_code = None
        user       = pick([u for u in USERS if u not in ["root"]])
    elif label == "SUSPICIOUS":
        source_ip  = pick(LEGITIMATE_IPS + MALICIOUS_IPS, weights=[1]*6 + [2]*7)
        user_agent = pick(AGENTS_LEGIT + AGENTS_SUSP, weights=[1]*5 + [2]*5)
        region     = pick(ALL_REGIONS + HIGH_RISK_RGNS, weights=[1]*6 + [3]*3)
        error_code = pick(ERRORS)
        user       = pick(USERS)
    else:  # ATTACK
        source_ip  = pick(MALICIOUS_IPS)
        user_agent = pick(AGENTS_SUSP)
        region     = pick(ALL_REGIONS + HIGH_RISK_RGNS, weights=[1]*6 + [4]*3)
        error_code = pick([None, "AccessDenied", "UnauthorizedOperation"], weights=[4,3,3])
        user       = pick(["root","admin","john.doe"])

    # Time offset: attacks often at odd hours
    if label == "ATTACK":
        hour = random.choice([0,1,2,3,23,22])
    elif label == "SUSPICIOUS":
        hour = random.randint(0, 23)
    else:
        hour = random.randint(7, 20)

    ts = base_time + timedelta(
        days=random.randint(0, 29),
        hours=hour,
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )

    # Feature engineering columns (used by ML model)
    failed_logins  = random.randint(5, 40) if label == "ATTACK" else random.randint(0, 4)
    api_call_freq  = random.randint(20, 100) if label in ["ATTACK","SUSPICIOUS"] else random.randint(1, 15)
    geo_anomaly    = 1 if region in HIGH_RISK_RGNS or source_ip in MALICIOUS_IPS else 0
    root_usage     = 1 if user in ["root","admin"] and label == "ATTACK" else 0
    off_hours      = 1 if hour in [0,1,2,3,22,23] else 0
    mfa_disabled   = 1 if label == "ATTACK" and random.random() > 0.5 else 0
    error_flag     = 0 if error_code is None else 1
    sensitive_api  = 1 if event_name in ["DeleteTrail","StopLogging","CreateUser","GetSecretValue","AttachUserPolicy","PutUserPolicy","CreateLoginProfile"] else 0

    return {
        "requestID":      f"req-{row_id:06x}-{random.randint(1000,9999)}",
        "eventTime":      ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName":      event_name,
        "eventSource":    event_source,
        "sourceIPAddress":source_ip,
        "awsRegion":      region,
        "userIdentity":   user,
        "userAgent":      user_agent,
        "errorCode":      error_code if error_code else "",
        # Engineered features
        "failedLoginAttempts": failed_logins,
        "apiCallFrequency":    api_call_freq,
        "geoAnomaly":          geo_anomaly,
        "rootAccountUsage":    root_usage,
        "offHoursAccess":      off_hours,
        "mfaDisabled":         mfa_disabled,
        "errorFlag":           error_flag,
        "sensitiveAPICall":    sensitive_api,
        # Ground truth label
        "label": label,
    }

def generate_dataset(n_normal=700, n_suspicious=200, n_attack=100, output_dir="."):
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    rows = []
    row_id = 1

    print(f"[+] Generating {n_normal} NORMAL events...")
    for _ in range(n_normal):
        rows.append(generate_row("NORMAL", row_id, base_time)); row_id += 1

    print(f"[+] Generating {n_suspicious} SUSPICIOUS events...")
    for _ in range(n_suspicious):
        rows.append(generate_row("SUSPICIOUS", row_id, base_time)); row_id += 1

    print(f"[+] Generating {n_attack} ATTACK events...")
    for _ in range(n_attack):
        rows.append(generate_row("ATTACK", row_id, base_time)); row_id += 1

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Save CSV (for dashboard upload + ML training)
    csv_path = os.path.join(output_dir, "cloudtrail_dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"[✓] CSV saved → {csv_path}  ({len(df)} rows)")

    # Save AWS CloudTrail JSON format (for dashboard upload)
    records = []
    for _, r in df.iterrows():
        records.append({
            "requestID":       r["requestID"],
            "eventTime":       r["eventTime"],
            "eventName":       r["eventName"],
            "eventSource":     r["eventSource"],
            "sourceIPAddress": r["sourceIPAddress"],
            "awsRegion":       r["awsRegion"],
            "userAgent":       r["userAgent"],
            "errorCode":       r["errorCode"] if r["errorCode"] else None,
            "userIdentity":    {"type":"IAMUser","userName": r["userIdentity"]},
        })
    json_path = os.path.join(output_dir, "cloudtrail_dataset.json")
    with open(json_path, "w") as f:
        json.dump({"Records": records}, f, indent=2)
    print(f"[✓] JSON saved → {json_path}  ({len(records)} records)")

    # Stats
    print(f"\n── Dataset Summary ─────────────────────────")
    print(df["label"].value_counts().to_string())
    print(f"Columns: {list(df.columns)}")
    return df

if __name__ == "__main__":
    df = generate_dataset(n_normal=700, n_suspicious=200, n_attack=100)
    print("\n[✓] Dataset generation complete. Files ready for ML training + dashboard upload.")

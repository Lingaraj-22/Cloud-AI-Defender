"""
Cloud AI Defender — Threat Correlation Engine
Correlates isolated events into attack chains + MITRE ATT&CK mapping
"""
import json
from datetime import datetime, timedelta
from collections import defaultdict

# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
MITRE_MAP = {
    "ConsoleLogin":                   {"id":"T1078","name":"Valid Accounts",         "tactic":"Initial Access",   "phase":1,"sev":"medium"},
    "AssumeRole":                     {"id":"T1078.004","name":"Cloud Accounts",     "tactic":"Initial Access",   "phase":1,"sev":"medium"},
    "CreateUser":                     {"id":"T1136.003","name":"Cloud Account",      "tactic":"Persistence",      "phase":2,"sev":"high"},
    "CreateAccessKey":                {"id":"T1098.001","name":"Additional Cloud Credentials","tactic":"Persistence","phase":2,"sev":"high"},
    "AttachUserPolicy":               {"id":"T1098","name":"Account Manipulation",   "tactic":"Privilege Escalation","phase":3,"sev":"high"},
    "PutUserPolicy":                  {"id":"T1078","name":"Valid Accounts",         "tactic":"Privilege Escalation","phase":3,"sev":"high"},
    "CreateLoginProfile":             {"id":"T1098","name":"Account Manipulation",   "tactic":"Persistence",      "phase":2,"sev":"high"},
    "GetSecretValue":                 {"id":"T1552.001","name":"Credentials In Files","tactic":"Credential Access","phase":4,"sev":"critical"},
    "GetParameter":                   {"id":"T1552.001","name":"Credentials In Files","tactic":"Credential Access","phase":4,"sev":"high"},
    "DeleteTrail":                    {"id":"T1562.008","name":"Disable Cloud Logs", "tactic":"Defense Evasion",  "phase":5,"sev":"critical"},
    "StopLogging":                    {"id":"T1562.008","name":"Disable Cloud Logs", "tactic":"Defense Evasion",  "phase":5,"sev":"critical"},
    "DeleteFlowLogs":                 {"id":"T1562.008","name":"Disable Cloud Logs", "tactic":"Defense Evasion",  "phase":5,"sev":"high"},
    "PutEventSelectors":              {"id":"T1562.008","name":"Modify Cloud Logs",  "tactic":"Defense Evasion",  "phase":5,"sev":"high"},
    "PutBucketPolicy":                {"id":"T1530","name":"Data from Cloud Storage","tactic":"Collection",       "phase":6,"sev":"high"},
    "GetObject":                      {"id":"T1530","name":"Data from Cloud Storage","tactic":"Exfiltration",     "phase":7,"sev":"high"},
    "ListObjects":                    {"id":"T1530","name":"Data from Cloud Storage","tactic":"Discovery",        "phase":4,"sev":"medium"},
    "AuthorizeSecurityGroupIngress":  {"id":"T1562.007","name":"Disable/Modify Firewall","tactic":"Defense Evasion","phase":5,"sev":"high"},
    "RunInstances":                   {"id":"T1578.002","name":"Create Cloud Instance","tactic":"Defense Evasion","phase":5,"sev":"medium"},
    "TerminateInstances":             {"id":"T1578","name":"Modify Cloud Compute",   "tactic":"Impact",           "phase":8,"sev":"medium"},
    "DescribeInstances":              {"id":"T1580","name":"Cloud Infrastructure Discovery","tactic":"Discovery","phase":4,"sev":"low"},
    "ListBuckets":                    {"id":"T1580","name":"Cloud Infrastructure Discovery","tactic":"Discovery","phase":4,"sev":"low"},
    "DisableMFADevice":               {"id":"T1556","name":"Modify Auth Process",    "tactic":"Credential Access","phase":3,"sev":"critical"},
    "UpdateAccountPasswordPolicy":    {"id":"T1556","name":"Modify Auth Process",    "tactic":"Defense Evasion",  "phase":5,"sev":"high"},
    "CreateVpcPeeringConnection":     {"id":"T1599","name":"Network Boundary Bridging","tactic":"Lateral Movement","phase":6,"sev":"high"},
}

TACTIC_ORDER = ["Initial Access","Persistence","Privilege Escalation","Credential Access",
                "Discovery","Defense Evasion","Lateral Movement","Collection","Exfiltration","Impact"]

# ── Known attack chain patterns ───────────────────────────────────────────────
ATTACK_CHAINS = [
    {
        "name": "Credential Harvesting + Trail Deletion",
        "description": "Attacker obtained credentials, accessed secrets, then disabled logging to cover tracks.",
        "sequence": ["ConsoleLogin","GetSecretValue","DeleteTrail"],
        "severity": "critical", "confidence": 95,
        "mitre_tactics": ["Initial Access","Credential Access","Defense Evasion"],
    },
    {
        "name": "IAM Privilege Escalation",
        "description": "New IAM user created with admin-level policies attached, classic privilege escalation.",
        "sequence": ["CreateUser","AttachUserPolicy","CreateAccessKey"],
        "severity": "critical", "confidence": 92,
        "mitre_tactics": ["Persistence","Privilege Escalation"],
    },
    {
        "name": "Reconnaissance → Exfiltration",
        "description": "Attacker performed cloud resource discovery followed by bulk data exfiltration.",
        "sequence": ["DescribeInstances","ListBuckets","ListObjects","GetObject"],
        "severity": "high", "confidence": 85,
        "mitre_tactics": ["Discovery","Collection","Exfiltration"],
    },
    {
        "name": "Full Kill Chain: Compromise → Persist → Exfil",
        "description": "Complete attack chain: initial access through console, persistence via IAM, data exfiltration, and trail deletion.",
        "sequence": ["ConsoleLogin","AssumeRole","CreateUser","GetSecretValue","GetObject","DeleteTrail"],
        "severity": "critical", "confidence": 98,
        "mitre_tactics": ["Initial Access","Persistence","Credential Access","Exfiltration","Defense Evasion"],
    },
    {
        "name": "MFA Bypass + Account Takeover",
        "description": "MFA device disabled followed by credential modification — account takeover pattern.",
        "sequence": ["DisableMFADevice","UpdateAccountPasswordPolicy","CreateLoginProfile"],
        "severity": "critical", "confidence": 97,
        "mitre_tactics": ["Credential Access","Persistence"],
    },
    {
        "name": "Network Perimeter Breach",
        "description": "Security group opened and new compute instances launched — lateral movement setup.",
        "sequence": ["AuthorizeSecurityGroupIngress","RunInstances","CreateVpcPeeringConnection"],
        "severity": "high", "confidence": 88,
        "mitre_tactics": ["Defense Evasion","Lateral Movement"],
    },
]

def get_mitre(event_name):
    return MITRE_MAP.get(event_name, {"id":"T1078","name":"Unknown Technique","tactic":"Unknown","phase":0,"sev":"low"})

def correlate_events(events: list) -> dict:
    """
    Takes list of event dicts, returns:
    - detected attack chains
    - attack timeline
    - entity graph nodes/edges
    - kill chain mapping
    - incident summary
    """
    if not events: return {}

    # Index events
    by_user    = defaultdict(list)
    by_ip      = defaultdict(list)
    by_session = defaultdict(list)
    threats    = [e for e in events if e.get("status") in ["THREAT","ATTACK","SUSPICIOUS"]]

    for e in events:
        u = e.get("user") or e.get("userIdentity","unknown")
        i = e.get("sourceIP") or e.get("sourceIPAddress","0.0.0.0")
        by_user[u].append(e)
        by_ip[i].append(e)

    # ── Detect attack chains ─────────────────────────────────────────────────
    detected_chains = []
    all_event_names = [e.get("eventName","") for e in events]

    for chain in ATTACK_CHAINS:
        seq = chain["sequence"]
        # sliding window match
        matches = []
        for i, evt in enumerate(all_event_names):
            if evt == seq[0]:
                remaining = seq[1:]
                window    = all_event_names[i+1:i+20]
                if all(s in window for s in remaining):
                    matches.append(i)
        if matches:
            participating = [e for e in events if e.get("eventName","") in seq]
            ips  = list({e.get("sourceIP") or e.get("sourceIPAddress","") for e in participating})
            users= list({e.get("user") or e.get("userIdentity","") for e in participating})
            detected_chains.append({
                **chain,
                "matchCount":    len(matches),
                "affectedIPs":   ips,
                "affectedUsers": users,
                "eventCount":    len(participating),
                "detectedAt":    datetime.utcnow().isoformat()+"Z",
            })

    # ── MITRE timeline ───────────────────────────────────────────────────────
    mitre_timeline = []
    seen_tactics   = set()
    for e in sorted(events, key=lambda x: x.get("timestamp") or x.get("eventTime","") or ""):
        m = get_mitre(e.get("eventName",""))
        if m["tactic"] not in seen_tactics:
            seen_tactics.add(m["tactic"])
        mitre_timeline.append({
            "event":      e.get("eventName",""),
            "mitreId":    m["id"],
            "mitreName":  m["name"],
            "tactic":     m["tactic"],
            "phase":      m["phase"],
            "severity":   m["sev"],
            "timestamp":  e.get("timestamp") or e.get("eventTime",""),
            "user":       e.get("user") or e.get("userIdentity",""),
            "sourceIP":   e.get("sourceIP") or e.get("sourceIPAddress",""),
            "status":     e.get("status","NORMAL"),
        })

    # ── Entity graph ─────────────────────────────────────────────────────────
    nodes, edges, seen_nodes = [], [], set()

    def add_node(nid, ntype, label, risk=0, status="NORMAL"):
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            nodes.append({"id":nid,"type":ntype,"label":label,"risk":risk,"status":status})

    for e in threats[:60]:
        u   = e.get("user") or e.get("userIdentity","unknown")
        ip  = e.get("sourceIP") or e.get("sourceIPAddress","0.0.0.0")
        ev  = e.get("eventName","unknown")
        rgn = e.get("region") or e.get("awsRegion","unknown")
        risk= float(e.get("riskScore") or e.get("risk",0))
        st  = e.get("status","NORMAL")

        uid = f"user_{u}"; iid = f"ip_{ip}"; eid = f"evt_{ev}_{e.get('id',0)}"
        add_node(uid,"user",u,risk,st)
        add_node(iid,"ip",ip,risk,st)
        add_node(eid,"event",ev,risk,st)
        edges.append({"source":iid,"target":uid,"label":"accessed"})
        edges.append({"source":uid,"target":eid,"label":"performed"})

    # ── Kill chain coverage ──────────────────────────────────────────────────
    kill_chain = {t:{"covered":False,"events":[]} for t in TACTIC_ORDER}
    for item in mitre_timeline:
        t = item["tactic"]
        if t in kill_chain:
            kill_chain[t]["covered"] = True
            kill_chain[t]["events"].append(item["event"])

    # ── Incident summary ─────────────────────────────────────────────────────
    crit_count = sum(1 for c in detected_chains if c["severity"]=="critical")
    high_count = sum(1 for c in detected_chains if c["severity"]=="high")
    top_chain  = detected_chains[0] if detected_chains else None

    narrative = "No significant attack chains detected."
    if top_chain:
        u_list = ", ".join(top_chain["affectedUsers"][:3]) or "unknown users"
        narrative = (f"CRITICAL: {top_chain['name']} detected with {top_chain['confidence']}% confidence. "
                     f"Affected users: {u_list}. "
                     f"Attack spans {len(top_chain['mitre_tactics'])} MITRE tactics. "
                     f"{top_chain['description']}")

    return {
        "attackChains":   detected_chains,
        "mitreTimeline":  mitre_timeline,
        "entityGraph":    {"nodes":nodes,"edges":edges},
        "killChain":      kill_chain,
        "tacticsHit":     list(seen_tactics),
        "summary":        narrative,
        "criticalChains": crit_count,
        "highChains":     high_count,
        "totalThreats":   len(threats),
        "correlatedAt":   datetime.utcnow().isoformat()+"Z",
    }

def get_misconfigurations():
    """CSPM-style misconfiguration findings (simulated)."""
    return [
        {"id":"CSPM-001","title":"S3 Bucket Publicly Accessible","resource":"s3://prod-data-bucket","severity":"critical","service":"S3","remediation":"Set BlockPublicAccess = true","cis":"CIS 2.1.5","status":"OPEN"},
        {"id":"CSPM-002","title":"Root Account MFA Disabled","resource":"arn:aws:iam::root","severity":"critical","service":"IAM","remediation":"Enable MFA on root account immediately","cis":"CIS 1.5","status":"OPEN"},
        {"id":"CSPM-003","title":"IAM User with Admin Wildcard Policy","resource":"arn:aws:iam::john.doe","severity":"high","service":"IAM","remediation":"Apply least privilege — remove *:* permissions","cis":"CIS 1.16","status":"OPEN"},
        {"id":"CSPM-004","title":"Security Group Allows 0.0.0.0/0 SSH","resource":"sg-0abc123","severity":"high","service":"EC2","remediation":"Restrict port 22 to known CIDR blocks","cis":"CIS 5.2","status":"OPEN"},
        {"id":"CSPM-005","title":"CloudTrail Logging Disabled in Region","resource":"ap-northeast-1","severity":"high","service":"CloudTrail","remediation":"Enable CloudTrail in all active regions","cis":"CIS 3.1","status":"OPEN"},
        {"id":"CSPM-006","title":"Unused Access Key > 90 Days","resource":"AKIA...XYZ (svc-billing)","severity":"medium","service":"IAM","remediation":"Rotate or deactivate unused access keys","cis":"CIS 1.14","status":"OPEN"},
        {"id":"CSPM-007","title":"S3 Bucket Versioning Disabled","resource":"s3://backup-archive","severity":"medium","service":"S3","remediation":"Enable versioning for data recovery","cis":"CIS 2.1.3","status":"OPEN"},
        {"id":"CSPM-008","title":"VPC Flow Logs Disabled","resource":"vpc-0prod123","severity":"medium","service":"VPC","remediation":"Enable VPC Flow Logs for network visibility","cis":"CIS 3.9","status":"OPEN"},
        {"id":"CSPM-009","title":"EBS Volume Not Encrypted","resource":"vol-0abc456","severity":"medium","service":"EC2","remediation":"Enable EBS encryption by default","cis":"CIS 2.2.1","status":"RESOLVED"},
        {"id":"CSPM-010","title":"Password Policy Weak (min < 14 chars)","resource":"arn:aws:iam::account","severity":"low","service":"IAM","remediation":"Set minimum password length to 14+","cis":"CIS 1.9","status":"OPEN"},
    ]

def get_honeypot_events():
    """Simulated honeypot trigger events."""
    return [
        {"id":"HP-001","asset":"s3://honeypot-credentials-prod","type":"S3 Honeybucket","sourceIP":"185.220.101.47","user":"unknown","timestamp":"2024-01-15T02:34:11Z","action":"GetObject","severity":"critical","attackerInfo":"TOR Exit Node · RU ASN"},
        {"id":"HP-002","asset":"arn:aws:iam::honeypot-admin-role","type":"IAM Honey Role","sourceIP":"103.21.244.0","user":"root","timestamp":"2024-01-15T03:10:05Z","action":"AssumeRole","severity":"critical","attackerInfo":"Malicious ASN · CN"},
        {"id":"HP-003","asset":"arn:aws:secretsmanager::fake-api-key","type":"Fake Secret","sourceIP":"45.155.205.12","user":"john.doe","timestamp":"2024-01-15T04:22:33Z","action":"GetSecretValue","severity":"high","attackerInfo":"Known Scanner"},
    ]

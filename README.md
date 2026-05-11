# ☁️ Cloud AI Defender v2.0
### Enterprise AI-Powered Cloud SOC Platform
**100% Free Stack · No AWS Billing Required · Runs Locally**

---

## 🧱 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     CLOUD AI DEFENDER                        │
├──────────────┬──────────────────────────────────────────────┤
│  FRONTEND    │  React + Recharts + WebSocket                 │
│  (Port 3000) │  8 views: Live · Chains · MITRE · CSPM ·     │
│              │  Hunt · Honeypot · Upload · AI Copilot        │
├──────────────┼──────────────────────────────────────────────┤
│  BACKEND     │  FastAPI + WebSocket streaming (Port 8000)    │
│  API Server  │  REST + WS · CORS · background event loop     │
├──────────────┼──────────────────────────────────────────────┤
│  ML ENGINE   │  Isolation Forest + Random Forest             │
│              │  SHAP-style explainability · 13 features      │
│              │  Behavioral baselines · confidence scoring     │
├──────────────┼──────────────────────────────────────────────┤
│  CORRELATION │  Attack chain detection · MITRE ATT&CK        │
│  ENGINE      │  Kill-chain mapping · Entity graph            │
│              │  6 known attack patterns                       │
├──────────────┼──────────────────────────────────────────────┤
│  DATA        │  CloudTrail CSV/JSON · Synthetic generator    │
│              │  1000-row labeled dataset · Real AWS format    │
└──────────────┴──────────────────────────────────────────────┘
```

---

## 📁 File Structure

```
cloud-ai-defender/
├── backend/
│   ├── app.py                  ← FastAPI server (WebSocket + REST)
│   ├── ml_engine.py            ← Isolation Forest + RandomForest + Explainability
│   ├── correlation_engine.py   ← Attack chains + MITRE mapping + CSPM + Honeypot
│   ├── generate_dataset.py     ← Synthetic CloudTrail dataset generator
│   ├── requirements.txt        ← Python dependencies
│   ├── cloudtrail_dataset.csv  ← 1000-row training + upload test data
│   ├── cloudtrail_dataset.json ← Same in AWS JSON format
│   └── models/                 ← Auto-created on train
│       ├── isolation_forest.pkl
│       ├── random_forest.pkl
│       ├── scaler.pkl
│       ├── encoders.pkl
│       └── baselines.json
│
└── frontend/
    └── src/
        └── App.jsx             ← Complete React dashboard (paste Dashboard.jsx here)
```

---

## ⚡ Quick Start (3 terminals)

### Terminal 1 — Python Backend

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic training data (1000 CloudTrail events)
python generate_dataset.py

# 3. Train ML models (IsolationForest + RandomForest)
python ml_engine.py --train

# 4. Start FastAPI server
python app.py
# → http://localhost:8000
# → WebSocket: ws://localhost:8000/ws/events
```

### Terminal 2 — React Frontend

```bash
npx create-react-app frontend
cd frontend
npm install recharts

# Replace src/App.js with contents of Dashboard.jsx
npm start
# → http://localhost:3000
```

### Terminal 3 — Test Upload

```bash
# Upload the sample CSV to the dashboard
# Drag cloudtrail_dataset.csv into the sidebar drop zone
# Switch to 📂 LOG ANALYSIS tab
```

---

## 🖥️ Dashboard Views

| View | Features |
|------|----------|
| ⚡ **Live Stream** | Real-time CloudTrail events via WebSocket · risk bars · MITRE IDs · block/release IPs · AI explanation drawer |
| 🔗 **Attack Chains** | 6 known attack patterns · kill-chain sequences · case management · MITRE tactic tags |
| 🎯 **MITRE ATT&CK** | Full cloud matrix · technique coverage · tactic heatmap · recent detections |
| 🔍 **Misconfigs (CSPM)** | 10 findings · severity ratings · CIS benchmark refs · remediation guidance |
| 🕵️ **Threat Hunt** | Free-text search · field pivot · preset IOC queries · session replay |
| 🍯 **Honeypot** | 4 decoy assets · trigger history · attacker IP intelligence |
| 📂 **Log Analysis** | Upload CSV/JSON · ML or rule-based · attack chain correlation · top events chart |
| 🤖 **AI Copilot** | Claude-powered SOC analyst · incident summaries · MITRE explanations · remediation |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System status + model info |
| GET | `/api/events?limit=50&status=THREAT` | Get buffered events |
| POST | `/api/predict/upload` | ML analysis of uploaded log file |
| POST | `/api/predict/json` | Predict from JSON body |
| GET | `/api/correlate` | Run attack chain correlation on live buffer |
| GET | `/api/mitre` | Full MITRE ATT&CK technique coverage |
| GET | `/api/cspm` | Cloud misconfiguration findings |
| GET | `/api/honeypot` | Honeypot trigger events |
| GET | `/api/timeline` | 24h event timeline buckets |
| GET | `/api/stats` | Live stats summary |
| POST | `/api/block` | Block IP `{"ip":"x.x.x.x"}` |
| POST | `/api/unblock` | Unblock IP |
| GET | `/api/blocklist` | All blocked IPs |
| POST | `/api/cases` | Create investigation case |
| GET | `/api/cases` | List all cases |
| GET | `/api/hunt?query=DeleteTrail&field=eventName` | Threat hunt search |
| GET | `/api/model/info` | ML model metadata |
| WS | `ws://localhost:8000/ws/events` | Real-time event stream |

---

## 🤖 ML Engine Details

| Component | Detail |
|-----------|--------|
| Algorithm | Isolation Forest (unsupervised) + Random Forest (supervised ensemble) |
| Trees | 250 IF estimators + 150 RF estimators |
| Features | 13 engineered security features |
| Classes | NORMAL / SUSPICIOUS / ATTACK |
| Explainability | SHAP-style feature attribution + natural language narrative |
| Baselines | Per-user, per-IP, per-region behavioral profiles |

### 13 Features used by model:

```
failedLoginAttempts  — Brute force indicator
apiCallFrequency     — Abnormal API usage volume  
geoAnomaly           — Known malicious IP or high-risk region
rootUsage            — Root/admin account activity
offHours             — Access at 10pm–4am
mfaDisabled          — MFA device disabled event
errorFlag            — AccessDenied / UnauthorizedOperation
sensitiveAPI         — DeleteTrail, GetSecretValue, CreateUser etc.
evasionAPI           — Defense evasion techniques
exfilAPI             — Data exfiltration calls
suspiciousAgent      — python-requests, curl, unknown agents
hour                 — Hour of day pattern
riskScore            — Composite weighted risk score
```

---

## 🔗 Attack Chain Patterns

| Chain | Severity | Confidence | MITRE Tactics |
|-------|----------|------------|---------------|
| Credential Harvesting + Trail Deletion | Critical | 95% | Initial Access → Credential Access → Defense Evasion |
| IAM Privilege Escalation | Critical | 92% | Persistence → Privilege Escalation |
| Reconnaissance → Exfiltration | High | 85% | Discovery → Collection → Exfiltration |
| Full Kill Chain | Critical | 98% | 5 tactics |
| MFA Bypass + Account Takeover | Critical | 97% | Credential Access → Persistence |
| Network Perimeter Breach | High | 88% | Defense Evasion → Lateral Movement |

---

## 💰 Free Stack Summary

| Component | Free Tool |
|-----------|-----------|
| ML Engine | scikit-learn (open source) |
| API Server | FastAPI + uvicorn (open source) |
| Real-time | WebSockets (built-in) |
| Frontend | React + Recharts (open source) |
| AI Copilot | Claude API (claude.ai free tier or API) |
| Dataset | Synthetic generator (no AWS needed) |
| AWS CloudTrail | Free tier — first trail is FREE |
| Deployment | Runs on localhost |

---

## 🔄 Real AWS CloudTrail Integration

When you're ready to connect real AWS data:

### 1. Enable CloudTrail (free)
```
AWS Console → CloudTrail → Create Trail
Name: cloud-ai-defender
S3 bucket: (new or existing)
Management events: ✓ Read + Write
Cost: FREE (first trail in each region)
```

### 2. Download logs from S3
```bash
aws s3 cp s3://your-bucket/AWSLogs/... ./logs/ --recursive
```

### 3. Upload to dashboard
Drag and drop the `.json.gz` or extracted `.json` file into the sidebar drop zone.

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| `npm start` fails | Run `npm install recharts` first |
| Dashboard shows "SIMULATION" | Run `python app.py` in backend folder |
| Model not found | Run `python ml_engine.py --train` first |
| Upload parse error | Check CSV has `eventName`, `sourceIPAddress` columns |
| WebSocket not connecting | Ensure backend is running on port 8000 |
| AI Copilot not responding | Requires Anthropic API key in browser (claude.ai) |
| Port 8000 in use | Change `port=8000` in `app.py` to `8001` |

---

**Cloud AI Defender v2.0 · Isolation Forest · FastAPI · React · MITRE ATT&CK · Free Stack**

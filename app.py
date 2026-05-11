"""
Cloud AI Defender — FastAPI Backend
Full SOC platform: ML predictions, correlation, MITRE, SOAR, CSPM, forensics, WebSocket streaming
Developed by: Anugraha L K
GitHub: github.com/AnugrahaLK
"""
import json, asyncio, os, random, uuid
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
import pandas as pd
import numpy as np

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from ml_engine import load_models, predict_df, explain_event, engineer, SENSITIVE_APIS, EVASION_APIS, HIGH_RISK_IPS
from correlation_engine import correlate_events, get_misconfigurations, get_honeypot_events, get_mitre, MITRE_MAP

app = FastAPI(title="Cloud AI Defender", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── State ────────────────────────────────────────────────────────────────────
blocked_ips    = set(["185.220.101.47","103.21.244.0"])
active_cases   = {}
event_store    = []
ws_clients     = set()
MODEL_LOADED   = False
MODELS         = None

try:
    MODELS       = load_models()
    MODEL_LOADED = True
    print("[✓] ML models loaded (IsolationForest + RandomForest)")
except Exception as e:
    print(f"[!] Model load failed: {e}")

# ── Live event simulation ────────────────────────────────────────────────────
CT_EVENTS = ["ConsoleLogin","AssumeRole","GetSecretValue","DescribeInstances","CreateUser",
             "PutBucketPolicy","DeleteTrail","StopLogging","AuthorizeSecurityGroupIngress",
             "RunInstances","CreateAccessKey","AttachUserPolicy","GetCallerIdentity",
             "ListBuckets","GetObject","ListObjects","DisableMFADevice","UpdateAccountPasswordPolicy"]
SVCS      = ["iam.amazonaws.com","ec2.amazonaws.com","s3.amazonaws.com","secretsmanager.amazonaws.com",
             "sts.amazonaws.com","cloudtrail.amazonaws.com","lambda.amazonaws.com"]
RGNS      = ["ap-south-1","us-east-1","eu-west-2","ap-northeast-1","us-west-2","cn-north-1","sa-east-1"]
IPS       = ["185.220.101.47","103.21.244.0","45.155.205.12","91.108.4.1","198.51.100.77",
             "192.0.2.45","10.0.0.1","172.16.0.5","54.239.28.85","52.94.228.167"]
USERS     = ["admin","root","john.doe","svc-billing","devops","api-user","iam-readonly","terraform-svc"]
AGENTS    = ["aws-cli/2.13.0","Boto3/1.28.0","Terraform/1.5.0","console.aws.amazon.com",
             "python-requests/2.31","Mozilla/5.0 (unknown)","curl/7.88.1"]
ERRORS    = [None,None,None,"AccessDenied","UnauthorizedOperation","InvalidClientTokenId"]
RISK_MAP  = {"DeleteTrail":95,"StopLogging":95,"CreateUser":70,"AttachUserPolicy":75,
             "CreateAccessKey":72,"PutBucketPolicy":68,"GetSecretValue":60,
             "DisableMFADevice":98,"UpdateAccountPasswordPolicy":85,"ConsoleLogin":30,"AssumeRole":40}

_evt_counter = 0
def sim_event():
    global _evt_counter
    _evt_counter += 1
    ev  = random.choice(CT_EVENTS)
    ip  = random.choice(IPS)
    rgn = random.choice(RGNS)
    ua  = random.choice(AGENTS)
    er  = random.choice(ERRORS)
    usr = random.choice(USERS)
    risk= RISK_MAP.get(ev,20)
    if ip in HIGH_RISK_IPS:       risk = min(100, risk+30)
    if rgn in ["cn-north-1","sa-east-1"]: risk = min(100, risk+15)
    if er:                        risk = min(100, risk+15)
    if any(s in ua.lower() for s in ["unknown","python","curl"]): risk = min(100, risk+10)
    status = "THREAT" if risk>=75 else "SUSPICIOUS" if risk>=45 else "NORMAL"
    row    = {"eventName":ev,"sourceIPAddress":ip,"awsRegion":rgn,"userAgent":ua,
              "errorCode":er or "","userIdentity":usr,"failedLoginAttempts":random.randint(0,15) if status=="THREAT" else 0,
              "apiCallFrequency":random.randint(1,50),"mfaDisabled":1 if ev=="DisableMFADevice" else 0}
    exp    = explain_event({**row,"riskScore":risk,"offHours":1 if datetime.utcnow().hour in [0,1,2,3,22,23] else 0,
                            "sensitiveAPI":1 if ev in SENSITIVE_APIS else 0,"evasionAPI":1 if ev in EVASION_APIS else 0,
                            "errorFlag":1 if er else 0,"suspiciousAgent":1 if any(s in ua.lower() for s in ["unknown","python","curl"]) else 0})
    mitre  = get_mitre(ev)
    return {
        "id":       _evt_counter,
        "trailId":  f"ct-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "eventName": ev, "eventSource": random.choice(SVCS),
        "sourceIP":  ip, "region": rgn, "user": usr,
        "userAgent": ua, "errorCode": er,
        "requestId": f"req-{uuid.uuid4().hex[:12]}",
        "status":    status, "risk": risk,
        "anomScore": round(risk + random.uniform(-5,5), 1),
        "confidence":round(70 + random.uniform(0,28), 1),
        "explanation": exp,
        "mitre":     mitre,
        "blocked":   ip in blocked_ips,
    }

# ── WebSocket broadcast ──────────────────────────────────────────────────────
async def broadcast(data: dict):
    dead = set()
    for ws in ws_clients:
        try:   await ws.send_json(data)
        except: dead.add(ws)
    ws_clients.difference_update(dead)

async def stream_loop():
    """Background task — pushes live events to all WS clients every 2.5s."""
    while True:
        await asyncio.sleep(2.5)
        if not ws_clients: continue
        ev = sim_event()
        event_store.append(ev)
        if len(event_store) > 500: event_store.pop(0)
        if ev["status"] == "THREAT": blocked_ips.add(ev["sourceIP"])
        await broadcast({"type":"event","data":ev})

@app.on_event("startup")
async def startup():
    asyncio.create_task(stream_loop())

# ── REST Routes ──────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status":"online","modelLoaded":MODEL_LOADED,"blockedIPs":len(blocked_ips),
            "eventsBuffered":len(event_store),"timestamp":datetime.utcnow().isoformat()+"Z",
            "services":{"isolationForest":"active" if MODEL_LOADED else "offline",
                        "randomForest":"active" if MODEL_LOADED else "offline","correlationEngine":"active",
                        "mitreMapping":"active","soar":"active","cspm":"active"}}

@app.post("/api/predict/upload")
async def predict_upload(file: UploadFile = File(...)):
    if not MODEL_LOADED:
        raise HTTPException(503, "ML models not loaded. Run: python ml_engine.py --train")
    content  = await file.read()
    filename = file.filename or ""
    try:
        if filename.endswith(".json"):
            data    = json.loads(content)
            records = data.get("Records", data if isinstance(data,list) else [data])
            df      = pd.json_normalize(records)
            if "userIdentity.userName" in df.columns:
                df["userIdentity"] = df["userIdentity.userName"].fillna(df.get("userIdentity.type","unknown"))
        else:
            import io
            df = pd.read_csv(io.StringIO(content.decode("utf-8","replace")))
    except Exception as e:
        raise HTTPException(422, f"Parse error: {e}")

    if df.empty: raise HTTPException(422, "Empty file")

    iforest,rf,scaler,encoders,baselines = MODELS
    result = predict_df(df, iforest, rf, scaler, encoders, baselines)

    events = []
    for i,(_,row) in enumerate(result.iterrows()):
        ip  = str(row.get("sourceIPAddress",row.get("sourceIP","0.0.0.0")))
        exp = json.loads(row.get("explanation","{}")) if isinstance(row.get("explanation"),str) else {}
        ev  = str(row.get("eventName","Unknown"))
        events.append({
            "id":i+1,"trailId":str(row.get("requestID",f"ct-{i:06x}")),
            "timestamp":str(row.get("eventTime",row.get("timestamp",datetime.utcnow().isoformat()))),
            "eventName":ev,"eventSource":str(row.get("eventSource","unknown")),
            "sourceIP":ip,"region":str(row.get("awsRegion",row.get("region","unknown"))),
            "user":str(row.get("userIdentity",row.get("user","unknown"))),
            "userAgent":str(row.get("userAgent","unknown"))[:60],
            "errorCode":str(row.get("errorCode","")) or None,
            "requestId":str(row.get("requestID",f"req-{i}")),
            "status":str(row.get("status","NORMAL")),
            "risk":float(row.get("riskScore",0)),
            "anomScore":float(row.get("anomScore",0)),
            "confidence":float(row.get("confidence",0)),
            "explanation":exp,
            "mitre":get_mitre(ev),
            "blocked":ip in blocked_ips,
        })

    # Correlate
    corr = correlate_events(events)

    threats    = sum(1 for e in events if e["status"]=="THREAT")
    suspicious = sum(1 for e in events if e["status"]=="SUSPICIOUS")
    region_map = defaultdict(lambda:{"blocked":0,"suspicious":0})
    for e in events:
        if e["status"]=="THREAT":      region_map[e["region"]]["blocked"]   += 1
        elif e["status"]=="SUSPICIOUS":region_map[e["region"]]["suspicious"] += 1
    evt_map = defaultdict(int)
    for e in events:
        if e["status"]!="NORMAL": evt_map[e["eventName"]] += 1

    return {"success":True,"filename":filename,"total":len(events),
            "threats":threats,"suspicious":suspicious,"normal":len(events)-threats-suspicious,
            "events":events,"correlation":corr,
            "regionData":[{"region":r,"blocked":v["blocked"],"suspicious":v["suspicious"]} for r,v in region_map.items()],
            "topEvents":sorted([{"event":k,"count":v} for k,v in evt_map.items()],key=lambda x:-x["count"])[:8],
            "analyzedAt":datetime.utcnow().isoformat()+"Z"}

@app.get("/api/events")
async def get_events(limit:int=50, status:Optional[str]=None):
    evts = event_store[-limit:]
    if status: evts = [e for e in evts if e["status"]==status]
    return {"events":list(reversed(evts)),"total":len(evts)}

@app.get("/api/correlate")
async def correlate_live():
    return correlate_events(event_store[-200:])

@app.get("/api/mitre")
async def mitre_coverage():
    coverage = {}
    for ev,meta in MITRE_MAP.items():
        t = meta["tactic"]
        if t not in coverage: coverage[t] = []
        coverage[t].append({"technique":meta["id"],"name":meta["name"],"event":ev,"severity":meta["sev"]})
    return {"coverage":coverage,"totalTechniques":len(MITRE_MAP),"tacticsCount":len(coverage)}

@app.get("/api/cspm")
async def cspm(): return {"findings":get_misconfigurations(),"scannedAt":datetime.utcnow().isoformat()+"Z"}

@app.get("/api/honeypot")
async def honeypot(): return {"events":get_honeypot_events(),"traps":3,"triggered":3}

@app.get("/api/stats")
async def stats():
    total = len(event_store)
    th    = sum(1 for e in event_store if e["status"]=="THREAT")
    su    = sum(1 for e in event_store if e["status"]=="SUSPICIOUS")
    return {"total":total,"threats":th,"suspicious":su,"normal":total-th-su,
            "blockedIPs":len(blocked_ips),"modelStatus":"active" if MODEL_LOADED else "offline",
            "timestamp":datetime.utcnow().isoformat()+"Z"}

@app.get("/api/timeline")
async def timeline():
    buckets = defaultdict(lambda:{"normal":0,"suspicious":0,"threat":0})
    for e in event_store:
        try: h = f"{datetime.fromisoformat(e['timestamp'].rstrip('Z')).hour:02d}:00"
        except: h = "00:00"
        buckets[h][e["status"].lower() if e["status"]!="THREAT" else "threat"] += 1
    return [{"t":k,"normal":v["normal"],"suspicious":v["suspicious"],"threat":v["threat"]}
            for k,v in sorted(buckets.items())]

@app.post("/api/block")
async def block(data: dict):
    ip = data.get("ip","").strip()
    if not ip: raise HTTPException(400,"Provide ip")
    blocked_ips.add(ip)
    return {"success":True,"blocked":ip,"total":len(blocked_ips)}

@app.post("/api/unblock")
async def unblock(data: dict):
    blocked_ips.discard(data.get("ip","").strip())
    return {"success":True,"total":len(blocked_ips)}

@app.get("/api/blocklist")
async def blocklist(): return {"ips":list(blocked_ips),"count":len(blocked_ips)}

@app.post("/api/cases")
async def create_case(data: dict):
    cid = f"CASE-{len(active_cases)+1:04d}"
    active_cases[cid] = {**data,"id":cid,"status":"OPEN","created":datetime.utcnow().isoformat()+"Z","assignee":data.get("assignee","Analyst-1")}
    return active_cases[cid]

@app.get("/api/cases")
async def list_cases(): return {"cases":list(active_cases.values())}

@app.get("/api/hunt")
async def threat_hunt(query:str="", field:str="eventName", limit:int=100):
    results = event_store[-500:]
    if query:
        q = query.lower()
        results = [e for e in results if q in str(e.get(field,"")).lower() or q in str(e.get("sourceIP","")).lower() or q in str(e.get("user","")).lower()]
    return {"results":results[:limit],"total":len(results),"query":query,"field":field}

@app.get("/api/model/info")
async def model_info():
    if not MODEL_LOADED: raise HTTPException(503,"Model not loaded")
    iforest = MODELS[0]
    return {"algorithm":"Isolation Forest + Random Forest","n_estimators":iforest.n_estimators,
            "contamination":float(iforest.contamination),"features":13,"classes":["NORMAL","SUSPICIOUS","ATTACK"],
            "explainability":"SHAP-style feature attribution","status":"active"}

# ── WebSocket ────────────────────────────────────────────────────────────────
@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.discard(ws)

if __name__ == "__main__":
    print("\n"+"="*60+"\n  CLOUD AI DEFENDER — API Server v2.0\n  http://localhost:8000\n"+"="*60)
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)

"""
Cloud AI Defender — ML Engine v2
Isolation Forest + RandomForest + Behavioral Baselines + Explainability
"""
import pandas as pd
import numpy as np
import joblib, json, os, warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.metrics import classification_report

MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)
IF_PATH   = os.path.join(MODEL_DIR, "isolation_forest.pkl")
RF_PATH   = os.path.join(MODEL_DIR, "random_forest.pkl")
SC_PATH   = os.path.join(MODEL_DIR, "scaler.pkl")
ENC_PATH  = os.path.join(MODEL_DIR, "encoders.pkl")
BASE_PATH = os.path.join(MODEL_DIR, "baselines.json")

HIGH_RISK_IPS  = {"185.220.101.47","103.21.244.0","45.155.205.12","91.108.4.1","198.51.100.77","203.0.113.99"}
HIGH_RISK_RGNS = {"cn-north-1","sa-east-1","ru-central-1","me-south-1"}
SENSITIVE_APIS = {"DeleteTrail","StopLogging","CreateUser","PutUserPolicy","CreateLoginProfile",
                  "GetSecretValue","AttachUserPolicy","CreateAccessKey","PutBucketPolicy",
                  "AuthorizeSecurityGroupIngress","DisableMFADevice","UpdateAccountPasswordPolicy"}
EVASION_APIS   = {"DeleteTrail","StopLogging","DeleteFlowLogs","DeleteLogGroup","PutEventSelectors"}
EXFIL_APIS     = {"GetObject","ListObjects","GetSecretValue","GetParameter","GetParameters","ListSecrets"}
SUSP_AGENTS    = {"python-requests","curl","Go-http","libwww","masscan","zgrab","python-urllib"}

CAT_COLS = ["eventName","eventSource","awsRegion","userIdentity","userAgent"]
NUM_COLS = ["failedLoginAttempts","apiCallFrequency","geoAnomaly","rootUsage",
            "offHours","mfaDisabled","errorFlag","sensitiveAPI","evasionAPI",
            "exfilAPI","suspiciousAgent","hour","riskScore"]

FEAT_LABELS = {
    "failedLoginAttempts":"Failed Login Attempts","apiCallFrequency":"API Call Frequency",
    "geoAnomaly":"Geographic Anomaly","rootUsage":"Root Account Usage",
    "offHours":"Off-Hours Access","mfaDisabled":"MFA Disabled",
    "errorFlag":"Auth Error Detected","sensitiveAPI":"Sensitive API Call",
    "evasionAPI":"Defense Evasion API","exfilAPI":"Data Exfiltration API",
    "suspiciousAgent":"Suspicious User-Agent","riskScore":"Composite Risk Score",
}
FEAT_WEIGHTS = {
    "failedLoginAttempts":1.5,"apiCallFrequency":0.4,"geoAnomaly":22,"rootUsage":20,
    "offHours":12,"mfaDisabled":18,"errorFlag":14,"sensitiveAPI":18,
    "evasionAPI":30,"exfilAPI":16,"suspiciousAgent":10,"riskScore":0,
}

def engineer(df):
    df = df.copy()
    ip  = next((c for c in ["sourceIPAddress","sourceIP","ip"]   if c in df.columns), None)
    evt = next((c for c in ["eventName"]                          if c in df.columns), None)
    rgn = next((c for c in ["awsRegion","region"]                if c in df.columns), None)
    ua  = next((c for c in ["userAgent"]                         if c in df.columns), None)
    err = next((c for c in ["errorCode"]                         if c in df.columns), None)
    usr = next((c for c in ["userIdentity","user"]               if c in df.columns), None)
    ts  = next((c for c in ["eventTime","timestamp","time"]      if c in df.columns), None)

    for col in NUM_COLS:
        if col not in df.columns: df[col] = 0
    df["apiCallFrequency"] = df["apiCallFrequency"].replace(0,1)

    if ip:  df["geoAnomaly"]      = df[ip].apply(lambda x: 1 if str(x) in HIGH_RISK_IPS else 0)
    if evt: df["sensitiveAPI"]    = df[evt].apply(lambda x: 1 if str(x) in SENSITIVE_APIS else 0)
    if evt: df["evasionAPI"]      = df[evt].apply(lambda x: 1 if str(x) in EVASION_APIS else 0)
    if evt: df["exfilAPI"]        = df[evt].apply(lambda x: 1 if str(x) in EXFIL_APIS else 0)
    if rgn: df["geoAnomaly"]      = df.apply(lambda r: 1 if str(r.get(rgn,"")) in HIGH_RISK_RGNS else r["geoAnomaly"], axis=1)
    if ua:  df["suspiciousAgent"] = df[ua].apply(lambda x: 1 if any(s in str(x).lower() for s in SUSP_AGENTS) else 0)
    if err: df["errorFlag"]       = df[err].apply(lambda x: 0 if (pd.isna(x) or str(x).strip()=="") else 1)
    if usr: df["rootUsage"]       = df[usr].apply(lambda x: 1 if str(x).lower() in ["root","admin"] else 0)
    if ts:
        def gh(t):
            try: return pd.to_datetime(t, utc=True).hour
            except:
                try: return pd.to_datetime(t).hour
                except: return 12
        df["hour"]     = df[ts].apply(gh)
        df["offHours"] = df["hour"].apply(lambda h: 1 if h in [0,1,2,3,22,23] else 0)

    # canonical col names for encoding
    if "userIdentity" not in df.columns and usr: df["userIdentity"] = df[usr]
    if "awsRegion"    not in df.columns and rgn: df["awsRegion"]    = df[rgn]

    df["riskScore"] = (
        df["failedLoginAttempts"]*1.5 + df["apiCallFrequency"]*0.4
        + df["geoAnomaly"]*22  + df["rootUsage"]*20    + df["offHours"]*12
        + df["mfaDisabled"]*18 + df["errorFlag"]*14    + df["sensitiveAPI"]*18
        + df["evasionAPI"]*30  + df["exfilAPI"]*16     + df["suspiciousAgent"]*10
    ).clip(0,100)
    return df

def feature_matrix(df, encoders=None, fit=False):
    df = engineer(df)
    parts = [df[NUM_COLS].fillna(0).astype(float)]
    if encoders is None: encoders = {}
    for col in CAT_COLS:
        if col not in df.columns:
            parts.append(pd.DataFrame({col:np.zeros(len(df))}, index=df.index)); continue
        vals = df[col].fillna("UNKNOWN").astype(str)
        if fit:
            le = LabelEncoder(); le.fit(list(vals)+["UNKNOWN","__unk__"]); encoders[col]=le
        else:
            le = encoders.get(col)
            if le is None:
                parts.append(pd.DataFrame({col:np.zeros(len(df))}, index=df.index)); continue
            vals = vals.apply(lambda x: x if x in le.classes_ else "UNKNOWN")
        parts.append(pd.DataFrame({col:le.transform(vals)}, index=df.index))
    return pd.concat(parts, axis=1).fillna(0).astype(float), encoders

def explain_event(row_dict):
    contributions = {}
    for feat, label in FEAT_LABELS.items():
        val = float(row_dict.get(feat,0))
        w   = FEAT_WEIGHTS.get(feat,1)
        c   = val*w
        if c > 0: contributions[label] = round(c,2)
    total  = sum(contributions.values()) or 1
    factors = sorted([{"feature":k,"value":v,"pct":round(v/total*100,1)} for k,v in contributions.items()],
                     key=lambda x:-x["value"])[:6]
    sents = []
    ev,ip,rgn,ua,usr,err = (str(row_dict.get(k,"")) for k in
        ["eventName","sourceIPAddress","awsRegion","userAgent","userIdentity","errorCode"])
    if ip  in HIGH_RISK_IPS:    sents.append(f"Source IP {ip} is on the known malicious IP watchlist.")
    if rgn in HIGH_RISK_RGNS:   sents.append(f"AWS region {rgn} is flagged as high-risk.")
    if ev  in EVASION_APIS:     sents.append(f"'{ev}' is a known defense-evasion technique (MITRE T1562).")
    if ev  in SENSITIVE_APIS:   sents.append(f"'{ev}' accesses sensitive cloud resources.")
    if float(row_dict.get("offHours",0)):   sents.append(f"Activity at {int(row_dict.get('hour',0)):02d}:00 — outside business hours.")
    if float(row_dict.get("failedLoginAttempts",0))>5: sents.append(f"{int(row_dict.get('failedLoginAttempts',0))} failed logins — brute force indicator.")
    if float(row_dict.get("suspiciousAgent",0)):  sents.append(f"User-agent matches known attack tooling signatures.")
    if err: sents.append(f"Error '{err}' indicates unauthorized access attempt.")
    if not sents: sents.append(f"Behavioral deviation from baseline for user '{usr}'.")
    return {"factors":factors,"narrative":" ".join(sents),"risk":round(float(row_dict.get("riskScore",0)),1),"topFactor":factors[0]["feature"] if factors else "Risk Score"}

def build_baselines(df):
    df = engineer(df)
    b  = {"users":{},"ips":{},"regions":{},"events":{}}
    ip_c  = next((c for c in ["sourceIPAddress","sourceIP"] if c in df.columns), None)
    usr_c = next((c for c in ["userIdentity","user"]        if c in df.columns), None)
    rgn_c = next((c for c in ["awsRegion","region"]         if c in df.columns), None)
    evt_c = "eventName" if "eventName" in df.columns else None
    if usr_c:
        for u,g in df.groupby(usr_c):
            b["users"][str(u)] = {"avg_risk":round(g["riskScore"].mean(),2),"max_risk":round(g["riskScore"].max(),2),
                "events":g[evt_c].value_counts().to_dict() if evt_c else {},"count":int(len(g)),"off_hours":int(g["offHours"].sum())}
    if ip_c:
        for ip,g in df.groupby(ip_c):
            b["ips"][str(ip)] = {"count":int(len(g)),"avg_risk":round(g["riskScore"].mean(),2),"malicious":str(ip) in HIGH_RISK_IPS}
    if rgn_c:
        for r,g in df.groupby(rgn_c):
            b["regions"][str(r)] = {"count":int(len(g)),"avg_risk":round(g["riskScore"].mean(),2)}
    if evt_c: b["events"] = {str(k):int(v) for k,v in df[evt_c].value_counts().items()}
    return b

def train(data_path="cloudtrail_dataset.csv"):
    print(f"\n{'='*58}\n  CLOUD AI DEFENDER — Training Pipeline\n{'='*58}")
    df   = pd.read_csv(data_path)
    print(f"[+] {len(df)} rows | {df['label'].value_counts().to_dict()}")
    X,encoders = feature_matrix(df, fit=True)
    scaler     = StandardScaler()
    X_sc       = scaler.fit_transform(X)
    cont       = round((df["label"]!="NORMAL").mean(),3)
    iforest    = IsolationForest(n_estimators=250,contamination=cont,random_state=42,n_jobs=-1)
    iforest.fit(X_sc)
    lmap       = {"NORMAL":0,"SUSPICIOUS":1,"ATTACK":2}
    y          = df["label"].map(lmap).fillna(0).astype(int)
    rf         = RandomForestClassifier(n_estimators=150,random_state=42,n_jobs=-1,class_weight="balanced")
    rf.fit(X_sc,y)
    print(classification_report(y,rf.predict(X_sc),target_names=["NORMAL","SUSPICIOUS","ATTACK"]))
    baselines  = build_baselines(df)
    joblib.dump(iforest,IF_PATH); joblib.dump(rf,RF_PATH)
    joblib.dump(scaler,SC_PATH);  joblib.dump(encoders,ENC_PATH)
    with open(BASE_PATH,"w") as f: json.dump(baselines,f)
    print(f"[✓] Saved to {MODEL_DIR}/")
    return iforest,rf,scaler,encoders,baselines

def load_models():
    for p in [IF_PATH,RF_PATH,SC_PATH,ENC_PATH]:
        if not os.path.exists(p): raise FileNotFoundError(f"Run --train first: {p}")
    bsl = json.load(open(BASE_PATH)) if os.path.exists(BASE_PATH) else {}
    return joblib.load(IF_PATH),joblib.load(RF_PATH),joblib.load(SC_PATH),joblib.load(ENC_PATH),bsl

def predict_df(df, iforest, rf, scaler, encoders, baselines=None):
    df_eng = engineer(df.copy())
    X,_    = feature_matrix(df_eng, encoders=encoders, fit=False)
    X_sc   = scaler.transform(X)
    if_sc  = iforest.decision_function(X_sc)
    if_p   = iforest.predict(X_sc)
    rf_pb  = rf.predict_proba(X_sc)
    rf_p   = rf.predict(X_sc)
    anom   = MinMaxScaler().fit_transform(-if_sc.reshape(-1,1)).flatten()*100
    lmap   = {0:"NORMAL",1:"SUSPICIOUS",2:"ATTACK"}
    labels,confs,exps = [],[],[]
    for i,(ip,rp,rpb,an,risk) in enumerate(zip(if_p,rf_p,rf_pb,anom,df_eng["riskScore"].values)):
        conf  = float(max(rpb))
        label = lmap[int(rp)] if conf>0.70 else ("ATTACK" if (ip==-1 and risk>=60) else ("SUSPICIOUS" if (ip==-1 or risk>=40) else "NORMAL"))
        labels.append(label); confs.append(round(conf*100,1))
        exps.append(json.dumps(explain_event(df_eng.iloc[i].to_dict())))
    r = df.copy()
    r["status"] = labels; r["riskScore"] = df_eng["riskScore"].values.round(1)
    r["anomScore"] = anom.round(1); r["confidence"] = confs; r["explanation"] = exps
    return r

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--train",action="store_true")
    p.add_argument("--predict",type=str)
    args = p.parse_args()
    if args.train: train()
    elif args.predict:
        m = load_models()
        df = pd.read_csv(args.predict)
        print(predict_df(df,*m)[["eventName","sourceIPAddress","awsRegion","status","riskScore"]].to_string())

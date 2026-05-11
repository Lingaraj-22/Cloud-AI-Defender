import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, PieChart, Pie, Cell
} from "recharts";

const API = "http://localhost:8000/api";
const WS  = "ws://localhost:8000/ws/events";
const M   = "'JetBrains Mono','Courier New',monospace";
const D   = "'Orbitron',monospace";
const SC  = { THREAT:"#ff2d55", SUSPICIOUS:"#ffcc00", NORMAL:"#34c759", ATTACK:"#ff2d55" };
const c   = (s) => SC[s] ?? "#607080";

// ── Risk mini-bar ─────────────────────────────────────────────────────────────
const RiskBar = ({v=0}) => (
  <div style={{display:"flex",alignItems:"center",gap:6}}>
    <div style={{width:50,height:3,background:"#0a1828",borderRadius:2}}>
      <div style={{width:`${v}%`,height:"100%",background:v>74?"#ff2d55":v>44?"#ffcc00":"#34c759",borderRadius:2}}/>
    </div>
    <span style={{fontSize:9,color:v>74?"#ff2d55":v>44?"#ffcc00":"#34c759",fontWeight:700}}>{Math.round(v)}%</span>
  </div>
);

// ── Severity badge ─────────────────────────────────────────────────────────────
const Badge = ({s,small=false}) => {
  const bg = {critical:"rgba(255,45,85,.18)",high:"rgba(255,149,0,.15)",medium:"rgba(255,204,0,.13)",low:"rgba(52,199,89,.12)",THREAT:"rgba(255,45,85,.18)",SUSPICIOUS:"rgba(255,204,0,.13)",NORMAL:"rgba(52,199,89,.12)",ATTACK:"rgba(255,45,85,.18)"}[s]||"rgba(96,112,128,.15)";
  const fc = {critical:"#ff2d55",high:"#ff9500",medium:"#ffcc00",low:"#34c759",THREAT:"#ff2d55",SUSPICIOUS:"#ffcc00",NORMAL:"#34c759",ATTACK:"#ff2d55"}[s]||"#607080";
  return <span style={{background:bg,color:fc,border:`1px solid ${fc}35`,borderRadius:3,padding:small?"1px 5px":"2px 7px",fontSize:small?7:8,fontWeight:600,letterSpacing:1,textTransform:"uppercase"}}>{s}</span>;
};

// ── Tactic color ──────────────────────────────────────────────────────────────
const TAC_COLORS = {
  "Initial Access":"#ff2d55","Persistence":"#ff6b35","Privilege Escalation":"#ff9500",
  "Credential Access":"#ffcc00","Discovery":"#30d158","Defense Evasion":"#0a84ff",
  "Lateral Movement":"#5e5ce6","Collection":"#bf5af2","Exfiltration":"#ff375f","Impact":"#ff2d55"
};

// ── Simulated events (offline fallback) ──────────────────────────────────────
const CT_EVTS=["ConsoleLogin","AssumeRole","GetSecretValue","DescribeInstances","CreateUser","PutBucketPolicy","DeleteTrail","StopLogging","AuthorizeSecurityGroupIngress","RunInstances","CreateAccessKey","AttachUserPolicy","GetCallerIdentity","ListBuckets","GetObject","DisableMFADevice"];
const RGNS=["ap-south-1","us-east-1","eu-west-2","ap-northeast-1","us-west-2","cn-north-1","sa-east-1"];
const IPS=["185.220.101.47","103.21.244.0","45.155.205.12","91.108.4.1","198.51.100.77","10.0.0.1","172.16.0.5","54.239.28.85"];
const USERS=["admin","root","john.doe","svc-billing","devops","api-user","iam-readonly"];
const AGENTS=["aws-cli/2.13.0","Boto3/1.28.0","Terraform/1.5.0","console.aws.amazon.com","python-requests/2.31","Mozilla/5.0 (unknown)"];
const RISK_MAP={"DeleteTrail":95,"StopLogging":95,"CreateUser":70,"AttachUserPolicy":75,"CreateAccessKey":72,"PutBucketPolicy":68,"GetSecretValue":60,"DisableMFADevice":98,"ConsoleLogin":30,"AssumeRole":40};
const BAD_IPS=new Set(["185.220.101.47","103.21.244.0","45.155.205.12"]);
const MITRE_LOCAL={"ConsoleLogin":{"id":"T1078","tactic":"Initial Access","sev":"medium"},"AssumeRole":{"id":"T1078.004","tactic":"Initial Access","sev":"medium"},"CreateUser":{"id":"T1136.003","tactic":"Persistence","sev":"high"},"CreateAccessKey":{"id":"T1098.001","tactic":"Persistence","sev":"high"},"AttachUserPolicy":{"id":"T1098","tactic":"Privilege Escalation","sev":"high"},"GetSecretValue":{"id":"T1552.001","tactic":"Credential Access","sev":"critical"},"DeleteTrail":{"id":"T1562.008","tactic":"Defense Evasion","sev":"critical"},"StopLogging":{"id":"T1562.008","tactic":"Defense Evasion","sev":"critical"},"PutBucketPolicy":{"id":"T1530","tactic":"Collection","sev":"high"},"GetObject":{"id":"T1530","tactic":"Exfiltration","sev":"high"},"DisableMFADevice":{"id":"T1556","tactic":"Credential Access","sev":"critical"}};
let _eid=1;
const simEv=()=>{
  const ev=CT_EVTS[Math.floor(Math.random()*CT_EVTS.length)];
  const ip=IPS[Math.floor(Math.random()*IPS.length)];
  const rgn=RGNS[Math.floor(Math.random()*RGNS.length)];
  const ua=AGENTS[Math.floor(Math.random()*AGENTS.length)];
  const er=[null,null,null,"AccessDenied","UnauthorizedOperation"][Math.floor(Math.random()*5)];
  let risk=RISK_MAP[ev]??20;
  if(BAD_IPS.has(ip))risk=Math.min(100,risk+30);
  if(rgn==="cn-north-1"||rgn==="sa-east-1")risk=Math.min(100,risk+15);
  if(er)risk=Math.min(100,risk+15);
  const status=risk>=75?"THREAT":risk>=45?"SUSPICIOUS":"NORMAL";
  const mitre=MITRE_LOCAL[ev]||{id:"T1078",tactic:"Unknown",sev:"low"};
  return {id:_eid++,trailId:`ct-${Math.random().toString(36).slice(2,10)}`,
    timestamp:new Date().toISOString(),eventName:ev,eventSource:"aws.amazon.com",
    sourceIP:ip,region:rgn,user:USERS[Math.floor(Math.random()*USERS.length)],
    userAgent:ua,errorCode:er,requestId:`req-${Math.random().toString(36).slice(2,14)}`,
    status,risk,anomScore:risk+Math.random()*8-4,confidence:70+Math.random()*28,
    mitre,blocked:BAD_IPS.has(ip),
    explanation:{narrative:ev in MITRE_LOCAL?`'${ev}' maps to MITRE ${mitre.id} (${mitre.tactic}).`:`Behavioral deviation detected for this event pattern.`,
      factors:[{feature:"Risk Score",value:risk,pct:60},{feature:"Geographic Anomaly",value:BAD_IPS.has(ip)?22:0,pct:25}],topFactor:"Risk Score",risk}};
};
const INIT_EVTS=Array.from({length:30},()=>simEv());

const TIMELINE_SEED=[
  {t:"00:00",normal:12,suspicious:3,threat:1},{t:"02:00",normal:8,suspicious:2,threat:0},
  {t:"04:00",normal:5,suspicious:7,threat:4},{t:"06:00",normal:14,suspicious:5,threat:2},
  {t:"08:00",normal:32,suspicious:8,threat:3},{t:"10:00",normal:45,suspicious:12,threat:6},
  {t:"12:00",normal:38,suspicious:15,threat:9},{t:"14:00",normal:41,suspicious:10,threat:5},
  {t:"16:00",normal:36,suspicious:18,threat:11},{t:"18:00",normal:28,suspicious:22,threat:14},
  {t:"20:00",normal:20,suspicious:19,threat:12},{t:"22:00",normal:15,suspicious:11,threat:7},
];

const TACTIC_ORDER=["Initial Access","Persistence","Privilege Escalation","Credential Access","Discovery","Defense Evasion","Lateral Movement","Collection","Exfiltration","Impact"];

const CSPM_MOCK=[
  {id:"CSPM-001",title:"S3 Bucket Publicly Accessible",resource:"s3://prod-data-bucket",severity:"critical",service:"S3",remediation:"Set BlockPublicAccess = true",status:"OPEN"},
  {id:"CSPM-002",title:"Root Account MFA Disabled",resource:"arn:aws:iam::root",severity:"critical",service:"IAM",remediation:"Enable MFA on root account",status:"OPEN"},
  {id:"CSPM-003",title:"IAM User with Wildcard Policy",resource:"john.doe",severity:"high",service:"IAM",remediation:"Apply least privilege",status:"OPEN"},
  {id:"CSPM-004",title:"Security Group Allows 0.0.0.0/0 SSH",resource:"sg-0abc123",severity:"high",service:"EC2",remediation:"Restrict port 22 to known CIDRs",status:"OPEN"},
  {id:"CSPM-005",title:"CloudTrail Disabled in Region",resource:"ap-northeast-1",severity:"high",service:"CloudTrail",remediation:"Enable in all active regions",status:"OPEN"},
  {id:"CSPM-006",title:"Unused Access Key > 90 Days",resource:"AKIA...XYZ",severity:"medium",service:"IAM",remediation:"Rotate or deactivate keys",status:"OPEN"},
  {id:"CSPM-007",title:"VPC Flow Logs Disabled",resource:"vpc-0prod123",severity:"medium",service:"VPC",remediation:"Enable VPC Flow Logs",status:"OPEN"},
  {id:"CSPM-008",title:"EBS Volume Not Encrypted",resource:"vol-0abc456",severity:"medium",service:"EC2",remediation:"Enable EBS encryption",status:"RESOLVED"},
];

const HONEYPOT_MOCK=[
  {id:"HP-001",asset:"s3://honeypot-credentials-prod",type:"S3 Honeybucket",sourceIP:"185.220.101.47",user:"unknown",timestamp:"2024-01-15T02:34:11Z",action:"GetObject",severity:"critical",attackerInfo:"TOR Exit Node · RU ASN"},
  {id:"HP-002",asset:"arn:aws:iam::honeypot-admin-role",type:"IAM Honey Role",sourceIP:"103.21.244.0",user:"root",timestamp:"2024-01-15T03:10:05Z",action:"AssumeRole",severity:"critical",attackerInfo:"Malicious ASN · CN"},
  {id:"HP-003",asset:"arn:aws:secretsmanager::fake-api-key",type:"Fake Secret",sourceIP:"45.155.205.12",user:"john.doe",timestamp:"2024-01-15T04:22:33Z",action:"GetSecretValue",severity:"high",attackerInfo:"Known Scanner"},
];

const CHAINS_MOCK=[
  {name:"Credential Harvesting + Trail Deletion",description:"Attacker obtained credentials, accessed secrets, then disabled logging to cover tracks.",severity:"critical",confidence:95,sequence:["ConsoleLogin","GetSecretValue","DeleteTrail"],mitre_tactics:["Initial Access","Credential Access","Defense Evasion"],affectedUsers:["root"],affectedIPs:["185.220.101.47"]},
  {name:"IAM Privilege Escalation",description:"New IAM user created with admin-level policies — classic privilege escalation.",severity:"critical",confidence:92,sequence:["CreateUser","AttachUserPolicy","CreateAccessKey"],mitre_tactics:["Persistence","Privilege Escalation"],affectedUsers:["admin"],affectedIPs:["103.21.244.0"]},
  {name:"Reconnaissance → Exfiltration",description:"Cloud resource discovery followed by bulk data exfiltration.",severity:"high",confidence:85,sequence:["DescribeInstances","ListBuckets","GetObject"],mitre_tactics:["Discovery","Exfiltration"],affectedUsers:["john.doe"],affectedIPs:["45.155.205.12"]},
];

// ── AI Copilot via Anthropic API ──────────────────────────────────────────────
const callCopilot = async (question, context) => {
  const res = await fetch("https://api.anthropic.com/v1/messages",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      model:"claude-sonnet-4-20250514",
      max_tokens:1000,
      system:`You are an expert AWS cloud security analyst for the Cloud AI Defender SOC platform.
You analyze CloudTrail events, detect attacks, explain MITRE ATT&CK techniques, and guide incident response.
Be concise, technical, and action-oriented. Format responses clearly.
Context: ${JSON.stringify(context).slice(0,1500)}`,
      messages:[{role:"user",content:question}]
    })
  });
  const d = await res.json();
  return d.content?.[0]?.text || "Unable to get AI response.";
};

// ══════════════════════════════════════════════════════════════════════════════
export default function CloudDefender() {
  const [view,       setView]       = useState("live");      // live|chains|mitre|cspm|hunt|honeypot|upload|copilot
  const [events,     setEvents]     = useState(INIT_EVTS);
  const [blockedIPs, setBlockedIPs] = useState(new Set(["185.220.101.47","103.21.244.0"]));
  const [selected,   setSelected]   = useState(null);
  const [liveMode,   setLiveMode]   = useState(true);
  const [filter,     setFilter]     = useState("ALL");
  const [alerts,     setAlerts]     = useState([]);
  const [pulse,      setPulse]      = useState(false);
  const [apiOnline,  setApiOnline]  = useState(false);
  const [modelInfo,  setModelInfo]  = useState(null);
  const [timeline,   setTimeline]   = useState(TIMELINE_SEED);
  const [clock,      setClock]      = useState(new Date().toLocaleTimeString());
  // upload
  const [upState,    setUpState]    = useState("idle");
  const [upPct,      setUpPct]      = useState(0);
  const [upData,     setUpData]     = useState(null);
  const [upFilter,   setUpFilter]   = useState("ALL");
  // hunt
  const [huntQuery,  setHuntQuery]  = useState("");
  const [huntField,  setHuntField]  = useState("eventName");
  const [huntResults,setHuntResults]=useState([]);
  // copilot
  const [copilotQ,   setCopilotQ]   = useState("");
  const [copilotH,   setCopilotH]   = useState([]);
  const [copilotBusy,setCopilotBusy]=useState(false);
  // cases
  const [cases,      setCases]      = useState([]);

  const wsRef  = useRef(null);
  const nextId = useRef(INIT_EVTS.length+1);
  const dropRef= useRef();
  const fileRef= useRef();

  // clock
  useEffect(()=>{const t=setInterval(()=>setClock(new Date().toLocaleTimeString()),1000);return()=>clearInterval(t);},[]);

  // API health
  useEffect(()=>{
    const check=async()=>{
      try{const r=await fetch(`${API}/health`,{signal:AbortSignal.timeout(2000)});
        if(r.ok){setApiOnline(true);fetch(`${API}/model/info`).then(r=>r.json()).then(setModelInfo).catch(()=>{});}
        else setApiOnline(false);
      }catch{setApiOnline(false);}
    };
    check();const t=setInterval(check,15000);return()=>clearInterval(t);
  },[]);

  // WebSocket
  useEffect(()=>{
    if(!apiOnline)return;
    try{
      const ws=new WebSocket(WS);
      ws.onmessage=(e)=>{
        const msg=JSON.parse(e.data);
        if(msg.type==="event"){
          const ev=msg.data;
          setEvents(p=>[ev,...p.slice(0,49)]);
          if(ev.status==="THREAT"){
            setBlockedIPs(p=>new Set([...p,ev.sourceIP]));
            setPulse(true);setTimeout(()=>setPulse(false),800);
            setAlerts(p=>[{id:Date.now(),ev},...p.slice(0,3)]);
          }
        }
      };
      wsRef.current=ws;
      return()=>ws.close();
    }catch{}
  },[apiOnline]);

  // Offline simulation
  useEffect(()=>{
    if(apiOnline||!liveMode)return;
    const iv=setInterval(()=>{
      const ev=simEv();
      setEvents(p=>[ev,...p.slice(0,49)]);
      if(ev.status==="THREAT"){
        setBlockedIPs(p=>new Set([...p,ev.sourceIP]));
        setPulse(true);setTimeout(()=>setPulse(false),800);
        setAlerts(p=>[{id:Date.now(),ev},...p.slice(0,3)]);
      }
    },2600);
    return()=>clearInterval(iv);
  },[apiOnline,liveMode]);

  // Alert dismiss
  useEffect(()=>{
    if(!alerts.length)return;
    const t=setTimeout(()=>setAlerts(p=>p.slice(0,-1)),5500);
    return()=>clearTimeout(t);
  },[alerts]);

  // Upload
  const analyzeFile=useCallback(async(file)=>{
    setUpState("analyzing");setUpPct(0);
    let p=0;
    const iv=setInterval(()=>{p+=Math.random()*10+4;setUpPct(Math.min(p,88));if(p>=88)clearInterval(iv);},140);
    if(apiOnline){
      try{
        const fd=new FormData();fd.append("file",file);
        const res=await fetch(`${API}/predict/upload`,{method:"POST",body:fd});
        clearInterval(iv);setUpPct(100);
        const data=await res.json();
        setTimeout(()=>{setUpData(data);setUpState("done");setView("upload");},300);
      }catch{clearInterval(iv);setUpState("error");}
    } else {
      const reader=new FileReader();
      reader.onload=(e)=>{
        clearInterval(iv);setUpPct(100);
        try{
          const text=e.target.result;
          let recs=[];
          if(file.name.endsWith(".json")){const j=JSON.parse(text);recs=(j.Records||[j]).flat();}
          else{
            const lines=text.trim().split("\n");
            const hdr=lines[0].split(",").map(h=>h.trim().toLowerCase().replace(/[^a-z]/g,""));
            const get=(vals,...keys)=>{for(const k of keys){const i=hdr.findIndex(h=>h.includes(k));if(i>=0)return vals[i]?.trim()||"";}return "";};
            recs=lines.slice(1).map(l=>{const v=l.split(",");return{eventName:get(v,"eventname","event"),sourceIPAddress:get(v,"sourceip","ip"),awsRegion:get(v,"region","awsregion"),userAgent:get(v,"useragent","agent"),errorCode:get(v,"errorcode","error"),userIdentity:get(v,"user","identity"),eventTime:get(v,"eventtime","time","timestamp")};}).filter(r=>r.eventName);
          }
          const evts=recs.map((r,i)=>{
            const ip=r.sourceIPAddress||r.sourceIP||"0.0.0.0";
            const ev=r.eventName||"Unknown";
            let risk=RISK_MAP[ev]??20;
            if(BAD_IPS.has(ip))risk=Math.min(100,risk+30);
            if(r.errorCode)risk=Math.min(100,risk+15);
            const status=risk>=75?"THREAT":risk>=45?"SUSPICIOUS":"NORMAL";
            const mitre=MITRE_LOCAL[ev]||{id:"T1078",tactic:"Unknown",sev:"low"};
            return{id:i+1,trailId:`ct-${i}`,timestamp:r.eventTime||new Date().toISOString(),eventName:ev,eventSource:"aws.amazon.com",sourceIP:ip,region:r.awsRegion||"unknown",user:r.userIdentity||"unknown",userAgent:r.userAgent||"unknown",errorCode:r.errorCode||null,requestId:`req-${i}`,status,risk,anomScore:risk,confidence:75,mitre,blocked:BAD_IPS.has(ip),explanation:{narrative:`'${ev}' matched threat pattern.`,factors:[{feature:"Risk Score",value:risk,pct:100}],topFactor:"Risk Score",risk}};
          });
          const threats=evts.filter(e=>e.status==="THREAT").length;
          const susp=evts.filter(e=>e.status==="SUSPICIOUS").length;
          const rmMap={};evts.forEach(e=>{if(!rmMap[e.region])rmMap[e.region]={region:e.region,blocked:0,suspicious:0};if(e.status==="THREAT")rmMap[e.region].blocked++;else if(e.status==="SUSPICIOUS")rmMap[e.region].suspicious++;});
          const emMap={};evts.filter(e=>e.status!=="NORMAL").forEach(e=>{emMap[e.eventName]=(emMap[e.eventName]||0)+1;});
          const chains=CHAINS_MOCK.filter(ch=>ch.sequence.some(s=>evts.some(e=>e.eventName===s)));
          setTimeout(()=>{
            setUpData({events:evts,total:evts.length,threats,suspicious:susp,normal:evts.length-threats-susp,
              filename:file.name,analyzedAt:new Date().toLocaleTimeString(),
              regionData:Object.values(rmMap),
              topEvents:Object.entries(emMap).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([event,count])=>({event,count})),
              correlation:{attackChains:chains,tacticsHit:[...new Set(evts.map(e=>e.mitre?.tactic||"").filter(Boolean))],totalThreats:threats}});
            setUpState("done");setView("upload");
          },300);
        }catch{setUpState("error");}
      };
      reader.readAsText(file);
    }
  },[apiOnline]);

  const handleDrop=useCallback((e)=>{e.preventDefault();dropRef.current?.classList.remove("drop-active");const f=e.dataTransfer.files[0];if(f)analyzeFile(f);},[analyzeFile]);
  const handleFile=(e)=>{const f=e.target.files[0];if(f)analyzeFile(f);e.target.value="";};

  const block=(ip)=>{setBlockedIPs(p=>new Set([...p,ip]));if(apiOnline)fetch(`${API}/block`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip})});};
  const unblock=(ip)=>{setBlockedIPs(p=>{const s=new Set(p);s.delete(ip);return s;});if(apiOnline)fetch(`${API}/unblock`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip})});};

  const hunt=async()=>{
    if(apiOnline){const r=await fetch(`${API}/hunt?query=${encodeURIComponent(huntQuery)}&field=${huntField}`);const d=await r.json();setHuntResults(d.results||[]);}
    else{const q=huntQuery.toLowerCase();setHuntResults(events.filter(e=>q?Object.values(e).some(v=>String(v).toLowerCase().includes(q)):true).slice(0,100));}
  };

  const askCopilot=async()=>{
    if(!copilotQ.trim()||copilotBusy)return;
    const q=copilotQ;setCopilotQ("");setCopilotBusy(true);
    setCopilotH(p=>[...p,{role:"user",content:q}]);
    const ctx={recentThreats:events.filter(e=>e.status==="THREAT").slice(0,5),blockedCount:blockedIPs.size,totalEvents:events.length,topEvent:events[0]?.eventName};
    try{
      const ans=await callCopilot(q,ctx);
      setCopilotH(p=>[...p,{role:"assistant",content:ans}]);
    }catch{setCopilotH(p=>[...p,{role:"assistant",content:"AI service unavailable. Check API key."}]);}
    setCopilotBusy(false);
  };

  // derived
  const disp   = view==="upload"&&upData ? upData.events : events;
  const filt   = view==="upload" ? upFilter : filter;
  const setFilt= view==="upload" ? setUpFilter : setFilter;
  const filtd  = filt==="ALL" ? disp : disp.filter(e=>e.status===filt);
  const threats= events.filter(e=>e.status==="THREAT").length;
  const susp   = events.filter(e=>e.status==="SUSPICIOUS").length;
  const norm   = events.filter(e=>e.status==="NORMAL").length;
  const chains = (view==="upload"&&upData?.correlation?.attackChains) || CHAINS_MOCK;
  const cspm   = CSPM_MOCK;
  const honeyp = HONEYPOT_MOCK;
  const tacMap = {};
  events.forEach(e=>{const t=e.mitre?.tactic||e.mitre?.["tactic"]||"";if(t){if(!tacMap[t])tacMap[t]=0;tacMap[t]++;}});

  const NAV=[
    {id:"live",    icon:"⚡",label:"LIVE STREAM"},
    {id:"chains",  icon:"🔗",label:"ATTACK CHAINS"},
    {id:"mitre",   icon:"🎯",label:"MITRE ATT&CK"},
    {id:"cspm",    icon:"🔍",label:"MISCONFIGS"},
    {id:"hunt",    icon:"🕵️",label:"THREAT HUNT"},
    {id:"honeypot",icon:"🍯",label:"HONEYPOT"},
    {id:"upload",  icon:"📂",label:"LOG ANALYSIS"},
    {id:"copilot", icon:"🤖",label:"AI COPILOT"},
  ];

  return (
    <div style={{display:"flex",height:"100vh",background:"#030710",fontFamily:M,color:"#8ba5be",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Orbitron:wght@600;800;900&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-track{background:#050c18}
        ::-webkit-scrollbar-thumb{background:#1a3050;border-radius:2px}
        .rh:hover{background:rgba(0,120,255,.06)!important;cursor:pointer}
        .btn{transition:all .15s;cursor:pointer}
        .btn:hover{opacity:.82;transform:translateY(-1px)}
        .nav-item{transition:all .2s;cursor:pointer}
        .nav-item:hover{background:rgba(0,100,200,.08)!important}
        .drop-zone{transition:all .2s;cursor:pointer}
        .drop-zone:hover,.drop-active{border-color:rgba(0,180,255,.5)!important;background:rgba(0,60,120,.05)!important}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:.1}}
        @keyframes fadeUp{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes slideR{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:translateX(0)}}
        @keyframes pulseR{0%,100%{box-shadow:0 0 0 0 rgba(255,45,85,0)}50%{box-shadow:0 0 0 8px rgba(255,45,85,.12)}}
        @keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
        @keyframes scanline{0%{top:0}100%{top:100%}}
        .live-blink{animation:blink 1.4s infinite}
        .fade-up{animation:fadeUp .3s ease}
        .slide-r{animation:slideR .35s ease}
        .card-pulse{animation:pulseR .8s ease}
        .spin{animation:spin .9s linear infinite}
        textarea{resize:none;outline:none}
        textarea:focus{border-color:rgba(10,132,255,.5)!important}
        input:focus{outline:none;border-color:rgba(10,132,255,.5)!important}
        select:focus{outline:none}
      `}</style>

      {/* ── TOAST ALERTS ── */}
      <div style={{position:"fixed",top:12,right:12,zIndex:9999,display:"flex",flexDirection:"column",gap:6,width:310}}>
        {alerts.map(a=>(
          <div key={a.id} className="slide-r" style={{background:"#0b0814",border:"1px solid rgba(255,45,85,.45)",borderLeft:"3px solid #ff2d55",borderRadius:8,padding:"10px 14px",boxShadow:"0 4px 20px rgba(255,45,85,.2)"}}>
            <div style={{fontSize:8,color:"#ff2d55",letterSpacing:2,fontWeight:700}}>⚡ AUTO-BLOCKED · {a.ev.mitre?.id||"T1078"}</div>
            <div style={{fontSize:9,color:"#c0d0e0",marginTop:3,fontWeight:500}}>{a.ev.eventName} <span style={{color:"#607080"}}>from</span> {a.ev.sourceIP}</div>
            <div style={{fontSize:7,color:"#2a4060",marginTop:2}}>{a.ev.region} · {a.ev.mitre?.tactic} · {new Date().toLocaleTimeString()}</div>
          </div>
        ))}
      </div>

      {/* ── SIDEBAR ── */}
      <div style={{width:180,background:"#040a14",borderRight:"1px solid rgba(0,60,120,.35)",display:"flex",flexDirection:"column",flexShrink:0}}>
        {/* logo */}
        <div style={{padding:"16px 14px",borderBottom:"1px solid rgba(0,60,120,.25)"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <div style={{width:28,height:28,borderRadius:5,background:"linear-gradient(135deg,#FF9900,#FF5500)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,boxShadow:"0 0 12px rgba(255,153,0,.3)"}}>☁️</div>
            <div style={{fontFamily:D,fontSize:9,fontWeight:900,color:"#dff0ff",letterSpacing:2,lineHeight:1.3}}>CLOUD AI<br/>DEFENDER</div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:5}}>
            <div className="live-blink" style={{width:5,height:5,borderRadius:"50%",background:apiOnline?"#34c759":"#ffcc00"}}/>
            <span style={{fontSize:7,color:apiOnline?"#34c759":"#ffcc00",letterSpacing:1}}>{apiOnline?"API ONLINE":"SIMULATION"}</span>
          </div>
        </div>
        {/* nav */}
        <div style={{flex:1,padding:"8px 0",overflowY:"auto"}}>
          {NAV.map(n=>(
            <div key={n.id} className="nav-item" onClick={()=>setView(n.id)} style={{display:"flex",alignItems:"center",gap:8,padding:"8px 14px",background:view===n.id?"rgba(10,132,255,.12)":"transparent",borderLeft:view===n.id?"2px solid #0a84ff":"2px solid transparent",marginBottom:1}}>
              <span style={{fontSize:13}}>{n.icon}</span>
              <span style={{fontSize:8,color:view===n.id?"#0a84ff":"#2a4060",letterSpacing:1.5,fontWeight:view===n.id?700:400}}>{n.label}</span>
              {n.id==="chains"&&CHAINS_MOCK.length>0&&<span style={{marginLeft:"auto",background:"rgba(255,45,85,.2)",color:"#ff2d55",fontSize:7,padding:"1px 5px",borderRadius:8}}>{CHAINS_MOCK.length}</span>}
              {n.id==="cspm"&&<span style={{marginLeft:"auto",background:"rgba(255,149,0,.2)",color:"#ff9500",fontSize:7,padding:"1px 5px",borderRadius:8}}>{cspm.filter(c=>c.status==="OPEN").length}</span>}
              {n.id==="honeypot"&&<span style={{marginLeft:"auto",background:"rgba(255,45,85,.2)",color:"#ff2d55",fontSize:7,padding:"1px 5px",borderRadius:8}}>{HONEYPOT_MOCK.length}</span>}
            </div>
          ))}
        </div>
        {/* upload shortcut */}
        <div style={{padding:"10px 10px",borderTop:"1px solid rgba(0,60,120,.25)"}}>
          <div className="drop-zone" ref={dropRef}
            onDragOver={e=>{e.preventDefault();dropRef.current?.classList.add("drop-active")}}
            onDragLeave={()=>dropRef.current?.classList.remove("drop-active")}
            onDrop={handleDrop} onClick={()=>fileRef.current?.click()}
            style={{border:"1px dashed rgba(0,140,255,.2)",borderRadius:6,padding:"8px",textAlign:"center"}}>
            <div style={{fontSize:16,marginBottom:3}}>🗂️</div>
            <div style={{fontSize:7,color:"#1a3050",letterSpacing:1}}>DROP LOG FILE<br/>JSON / CSV</div>
            <input ref={fileRef} type="file" accept=".json,.csv" style={{display:"none"}} onChange={handleFile}/>
          </div>
          {upState==="analyzing"&&<div style={{marginTop:6}}>
            <div style={{fontSize:7,color:"#0a84ff",marginBottom:3}}>ANALYZING {Math.floor(upPct)}%</div>
            <div style={{height:2,background:"#0a1020",borderRadius:1}}><div style={{height:"100%",width:`${upPct}%`,background:"#0a84ff",borderRadius:1,transition:"width .2s"}}/></div>
          </div>}
        </div>
        {/* stats */}
        <div style={{padding:"10px 14px",borderTop:"1px solid rgba(0,60,120,.25)",display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
          {[["THREATS",threats,"#ff2d55"],["SUSPICIOUS",susp,"#ffcc00"],["NORMAL",norm,"#34c759"],["BLOCKED",blockedIPs.size,"#0a84ff"]].map(([l,v,col])=>(
            <div key={l} style={{background:`${col}08`,border:`1px solid ${col}20`,borderRadius:5,padding:"5px 7px",textAlign:"center"}}>
              <div style={{fontSize:14,color:col,fontWeight:700,fontFamily:D}}>{v}</div>
              <div style={{fontSize:6,color:`${col}60`,letterSpacing:1}}>{l}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── MAIN CONTENT ── */}
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        {/* header bar */}
        <div style={{height:46,background:"#040a14",borderBottom:"1px solid rgba(0,60,120,.3)",display:"flex",alignItems:"center",padding:"0 20px",gap:14,flexShrink:0}}>
          <div style={{fontFamily:D,fontSize:11,fontWeight:700,color:"#dff0ff",letterSpacing:3}}>
            {NAV.find(n=>n.id===view)?.label}
          </div>
          <div style={{flex:1}}/>
          {/* service pills */}
          {[["CloudTrail","#34c759"],["IAM","#34c759"],["GuardDuty","#ffcc00"],["WAF","#34c759"],["S3","#34c759"],["VPC","#34c759"]].map(([s,c])=>(
            <div key={s} style={{display:"flex",alignItems:"center",gap:4,fontSize:7,color:"#1e3a5a"}}>
              <div style={{width:4,height:4,borderRadius:"50%",background:c}}/>
              <span>{s}</span>
            </div>
          ))}
          <div style={{width:1,height:20,background:"#0d1e30",margin:"0 4px"}}/>
          {modelInfo&&<div style={{fontSize:7,color:"#bf5af2",background:"rgba(191,90,242,.1)",border:"1px solid rgba(191,90,242,.25)",borderRadius:4,padding:"3px 8px"}}>🤖 {modelInfo.n_estimators}T ENSEMBLE</div>}
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <div className="live-blink" style={{width:5,height:5,borderRadius:"50%",background:liveMode?"#34c759":"#444"}}/>
            <span style={{fontSize:7,color:liveMode?"#34c759":"#444",letterSpacing:1}}>{liveMode?"LIVE":"PAUSED"}</span>
          </div>
          <button className="btn" onClick={()=>setLiveMode(v=>!v)} style={{background:liveMode?"rgba(255,45,85,.1)":"rgba(52,199,89,.1)",border:`1px solid ${liveMode?"#ff2d5540":"#34c75940"}`,color:liveMode?"#ff2d55":"#34c759",borderRadius:4,padding:"3px 10px",fontSize:7,letterSpacing:1}}>
            {liveMode?"⏸ PAUSE":"▶ RESUME"}
          </button>
          <div style={{fontSize:7,color:"#1a3050",borderLeft:"1px solid #0d1e30",paddingLeft:12}}>
            <div style={{color:"#FF990080"}}>ap-south-1</div>
            <div>{clock}</div>
          </div>
        </div>

        {/* ── VIEW CONTENT ── */}
        <div style={{flex:1,overflowY:"auto",padding:"16px 20px"}}>

          {/* ════ LIVE STREAM ════ */}
          {view==="live"&&<>
            {/* mini charts */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 200px 200px",gap:12,marginBottom:16}}>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:2}}>CLOUDTRAIL EVENT STREAM · 24H</div>
                <div style={{fontSize:7,color:"#1e3a5a",marginBottom:10}}>ConsoleLogin · AssumeRole · IAM · API Calls</div>
                <ResponsiveContainer width="100%" height={110}>
                  <AreaChart data={TIMELINE_SEED} margin={{top:2,right:4,left:-28,bottom:0}}>
                    <defs>{[["n","#34c759"],["s","#ffcc00"],["t","#ff2d55"]].map(([k,c])=>(
                      <linearGradient key={k} id={`tg${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={c} stopOpacity={.18}/><stop offset="95%" stopColor={c} stopOpacity={0}/>
                      </linearGradient>))}</defs>
                    <CartesianGrid strokeDasharray="2 5" stroke="#070f1c"/>
                    <XAxis dataKey="t" tick={{fill:"#1a3050",fontSize:7,fontFamily:M}}/>
                    <YAxis tick={{fill:"#1a3050",fontSize:7,fontFamily:M}}/>
                    <Tooltip contentStyle={{background:"#060c18",border:"1px solid #1a2d45",borderRadius:5,fontFamily:M,fontSize:8}}/>
                    <Area type="monotone" dataKey="normal"     stroke="#34c759" fill="url(#tgn)" strokeWidth={1.5}/>
                    <Area type="monotone" dataKey="suspicious" stroke="#ffcc00" fill="url(#tgs)" strokeWidth={1.5}/>
                    <Area type="monotone" dataKey="threat"     stroke="#ff2d55" fill="url(#tgt)" strokeWidth={1.5}/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:8}}>DISTRIBUTION</div>
                <ResponsiveContainer width="100%" height={80}>
                  <PieChart><Pie data={[{name:"T",value:threats,color:"#ff2d55"},{name:"S",value:susp,color:"#ffcc00"},{name:"N",value:norm,color:"#34c759"}]} cx="50%" cy="50%" innerRadius={25} outerRadius={40} paddingAngle={3} dataKey="value">
                    {[{color:"#ff2d55"},{color:"#ffcc00"},{color:"#34c759"}].map((e,i)=><Cell key={i} fill={e.color} stroke="none"/>)}
                  </Pie><Tooltip contentStyle={{background:"#060c18",border:"1px solid #1a2d45",borderRadius:5,fontFamily:M,fontSize:8}}/></PieChart>
                </ResponsiveContainer>
                <div style={{display:"flex",justifyContent:"space-around",marginTop:6}}>
                  {[["T",threats,"#ff2d55"],["S",susp,"#ffcc00"],["N",norm,"#34c759"]].map(([l,v,c])=>(
                    <div key={l} style={{textAlign:"center"}}><div style={{fontSize:13,color:c,fontWeight:700}}>{v}</div><div style={{fontSize:6,color:`${c}60`}}>{l}</div></div>
                  ))}
                </div>
              </div>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:8}}>TACTIC COVERAGE</div>
                <div style={{display:"flex",flexDirection:"column",gap:4,maxHeight:120,overflowY:"auto"}}>
                  {Object.entries(tacMap).slice(0,6).map(([t,cnt])=>(
                    <div key={t} style={{display:"flex",alignItems:"center",gap:6}}>
                      <div style={{width:4,height:4,borderRadius:"50%",background:TAC_COLORS[t]||"#607080",flexShrink:0}}/>
                      <span style={{fontSize:7,color:"#3a5a7a",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t}</span>
                      <span style={{fontSize:7,color:TAC_COLORS[t]||"#607080",fontWeight:700}}>{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* events table + blacklist */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 240px",gap:12}}>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                  <div>
                    <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600}}>LIVE CLOUDTRAIL EVENTS</div>
                    <div style={{fontSize:7,color:"#1e3a5a",marginTop:2}}>Real-time · Isolation Forest + RF · {filtd.length} events</div>
                  </div>
                  <div style={{display:"flex",gap:5}}>
                    {["ALL","THREAT","SUSPICIOUS","NORMAL"].map(f=>(
                      <button key={f} className="btn" onClick={()=>setFilt(f)} style={{background:filter===f?(f==="THREAT"?"rgba(255,45,85,.18)":f==="SUSPICIOUS"?"rgba(255,204,0,.15)":f==="NORMAL"?"rgba(52,199,89,.12)":"rgba(0,130,255,.12)"):"transparent",border:`1px solid ${filter===f?(f==="THREAT"?"#ff2d5550":f==="SUSPICIOUS"?"#ffcc0050":f==="NORMAL"?"#34c75950":"#0a84ff50"):"#0d2035"}`,color:filter===f?(f==="THREAT"?"#ff2d55":f==="SUSPICIOUS"?"#ffcc00":f==="NORMAL"?"#34c759":"#0a84ff"):"#1e3a5a",borderRadius:4,padding:"3px 8px",fontSize:7,letterSpacing:1}}>
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"75px 100px 75px 90px 80px 80px 60px 80px",gap:5,padding:"5px 8px",borderBottom:"1px solid #0a1828",fontSize:6,color:"#1a3050",letterSpacing:2}}>
                  {["TIME","EVENT","SERVICE","SOURCE IP","REGION","MITRE","RISK","ACTION"].map(h=><div key={h}>{h}</div>)}
                </div>
                <div style={{maxHeight:300,overflowY:"auto"}}>
                  {filtd.slice(0,60).map(ev=>{
                    const ip=ev.sourceIP||ev.ip||"";
                    const tsStr=(()=>{try{return new Date(ev.timestamp||ev.time).toLocaleTimeString();}catch{return ev.time||"";}})();
                    return (
                      <div key={ev.id} className="rh fade-up" onClick={()=>setSelected(selected?.id===ev.id?null:ev)}
                        style={{display:"grid",gridTemplateColumns:"75px 100px 75px 90px 80px 80px 60px 80px",gap:5,padding:"6px 8px",borderBottom:"1px solid #060d1a",background:selected?.id===ev.id?"rgba(0,100,200,.08)":ev.status==="THREAT"?"rgba(255,45,85,.03)":"transparent",fontSize:9,alignItems:"center",borderLeft:ev.status==="THREAT"?"2px solid #ff2d5540":ev.status==="SUSPICIOUS"?"2px solid #ffcc0030":"2px solid transparent"}}>
                        <div style={{color:"#1e3a5a",fontSize:7}}>{tsStr}</div>
                        <div style={{color:c(ev.status),fontWeight:ev.status!=="NORMAL"?600:400,fontSize:8,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ev.eventName}</div>
                        <div style={{fontSize:6,color:"#FF990060"}}>{String(ev.eventSource||"").replace(".amazonaws.com","").slice(0,8)}</div>
                        <div style={{color:"#2a5070",fontFamily:M,fontSize:8}}>{ip}</div>
                        <div><span style={{background:"rgba(255,153,0,.08)",border:"1px solid rgba(255,153,0,.18)",color:"#FF9900",borderRadius:2,padding:"1px 4px",fontSize:6}}>{ev.region}</span></div>
                        <div style={{fontSize:6,color:TAC_COLORS[ev.mitre?.tactic]||"#607080"}}>{ev.mitre?.id||"—"}<br/><span style={{fontSize:5,color:"#1e3a5a"}}>{String(ev.mitre?.tactic||"").slice(0,12)}</span></div>
                        <RiskBar v={ev.risk}/>
                        <div>
                          {ev.status==="NORMAL"?<span style={{color:"#0d1e2a",fontSize:7}}>—</span>
                            :blockedIPs.has(ip)?
                              <button className="btn" onClick={e=>{e.stopPropagation();unblock(ip);}} style={{background:"rgba(52,199,89,.1)",border:"1px solid #34c75935",color:"#34c759",fontSize:6,padding:"2px 6px",borderRadius:3}}>RELEASE</button>
                              :<button className="btn" onClick={e=>{e.stopPropagation();block(ip);}} style={{background:"rgba(255,45,85,.1)",border:"1px solid #ff2d5535",color:"#ff2d55",fontSize:6,padding:"2px 6px",borderRadius:3}}>⊘ BLOCK</button>}
                        </div>
                      </div>
                    );
                  })}
                </div>
                {/* event detail drawer */}
                {selected&&(
                  <div className="fade-up" style={{marginTop:10,background:"#050a14",border:"1px solid #0a84ff25",borderRadius:8,padding:"12px 14px"}}>
                    <div style={{fontSize:7,color:"#0a84ff",letterSpacing:3,marginBottom:8}}>▸ EVENT DETAIL · {selected.trailId}</div>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8,marginBottom:8}}>
                      {[["Event",selected.eventName],["Source IP",selected.sourceIP||selected.ip],["Region",selected.region],["User",selected.user],["MITRE",selected.mitre?.id||"—"],
                        ["Tactic",selected.mitre?.tactic||"—"],["Risk",`${Math.round(selected.risk||0)}%`],["Anomaly",`${Math.round(selected.anomScore||0)}`],["Confidence",`${Math.round(selected.confidence||0)}%`],["Error",selected.errorCode||"None"]
                      ].map(([k,v])=>(
                        <div key={k}><div style={{fontSize:6,color:"#1a3050",letterSpacing:2,marginBottom:2}}>{k}</div>
                          <div style={{fontSize:9,color:k==="Risk"?c(selected.status):"#8ab4d0",wordBreak:"break-all"}}>{v}</div></div>
                      ))}
                    </div>
                    {selected.explanation?.narrative&&(
                      <div style={{background:"rgba(10,132,255,.06)",border:"1px solid #0a84ff20",borderRadius:6,padding:"8px 10px"}}>
                        <div style={{fontSize:7,color:"#0a84ff",letterSpacing:2,marginBottom:4}}>🤖 AI EXPLANATION</div>
                        <div style={{fontSize:8,color:"#7090a0",lineHeight:1.6}}>{selected.explanation.narrative}</div>
                        {selected.explanation.factors?.length>0&&(
                          <div style={{display:"flex",gap:8,marginTop:8,flexWrap:"wrap"}}>
                            {selected.explanation.factors.map((f,i)=>(
                              <div key={i} style={{background:"rgba(255,45,85,.08)",border:"1px solid rgba(255,45,85,.2)",borderRadius:4,padding:"3px 7px",fontSize:7,color:"#ff8090"}}>
                                {f.feature} <span style={{color:"#ff2d55",fontWeight:700}}>{f.pct}%</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* WAF blacklist */}
              <div style={{display:"flex",flexDirection:"column",gap:10}}>
                <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"12px 14px",flex:1}}>
                  <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:2}}>🔒 WAF BLACKLIST</div>
                  <div style={{fontSize:7,color:"#1e3a5a",marginBottom:8}}>{blockedIPs.size} active rules</div>
                  <div style={{maxHeight:160,overflowY:"auto",display:"flex",flexDirection:"column",gap:4}}>
                    {[...blockedIPs].map(ip=>(
                      <div key={ip} style={{display:"flex",justifyContent:"space-between",alignItems:"center",background:"rgba(255,45,85,.05)",border:"1px solid rgba(255,45,85,.12)",borderRadius:4,padding:"4px 8px"}}>
                        <div><div style={{fontSize:8,color:"#ff6070"}}>{ip}</div><div style={{fontSize:6,color:"#1a3050"}}>WAF Rule Active</div></div>
                        <button className="btn" onClick={()=>unblock(ip)} style={{background:"transparent",border:"1px solid #34c75830",color:"#34c759",fontSize:6,padding:"2px 6px",borderRadius:3}}>RELEASE</button>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"12px 14px"}}>
                  <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:8}}>🌏 REGION MAP</div>
                  <ResponsiveContainer width="100%" height={110}>
                    <BarChart data={[{r:"ap-south-1",v:34},{r:"cn-north-1",v:41},{r:"us-east-1",v:22},{r:"eu-west-2",v:15},{r:"us-west-2",v:8}]} layout="vertical" margin={{left:-20,right:4}}>
                      <XAxis type="number" tick={{fill:"#1a3050",fontSize:7,fontFamily:M}}/>
                      <YAxis type="category" dataKey="r" tick={{fill:"#2a4060",fontSize:7,fontFamily:M}} width={72}/>
                      <Tooltip contentStyle={{background:"#060c18",border:"1px solid #1a2d45",borderRadius:5,fontFamily:M,fontSize:8}}/>
                      <Bar dataKey="v" fill="#ff2d55" radius={[0,3,3,0]}/>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </>}

          {/* ════ ATTACK CHAINS ════ */}
          {view==="chains"&&<>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
              {[["CRITICAL CHAINS",chains.filter(c=>c.severity==="critical").length,"#ff2d55"],["HIGH CHAINS",chains.filter(c=>c.severity==="high").length,"#ff9500"],["TACTICS HIT",Object.keys(tacMap).length,"#0a84ff"]].map(([l,v,col])=>(
                <div key={l} style={{background:"#06101e",border:`1px solid ${col}25`,borderTop:`2px solid ${col}50`,borderRadius:10,padding:"16px 18px"}}>
                  <div style={{fontSize:8,color:"#1e3a5a",letterSpacing:3,marginBottom:6}}>{l}</div>
                  <div style={{fontSize:32,color:col,fontWeight:700,fontFamily:D}}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:12}}>
              {chains.map((ch,i)=>(
                <div key={i} className="fade-up" style={{background:"#06101e",border:`1px solid ${ch.severity==="critical"?"rgba(255,45,85,.25)":"rgba(255,149,0,.2)"}`,borderRadius:10,padding:"16px 20px",borderLeft:`3px solid ${ch.severity==="critical"?"#ff2d55":"#ff9500"}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
                    <div>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                        <Badge s={ch.severity}/>
                        <span style={{fontSize:11,color:"#dff0ff",fontWeight:600}}>{ch.name}</span>
                        <span style={{fontSize:8,color:"#607080"}}>·</span>
                        <span style={{fontSize:8,color:"#34c759",fontWeight:600}}>{ch.confidence}% confidence</span>
                      </div>
                      <div style={{fontSize:9,color:"#4a7090",lineHeight:1.5}}>{ch.description}</div>
                    </div>
                    <button className="btn" onClick={()=>setCases(p=>[{id:`CASE-${p.length+1001}`,title:ch.name,severity:ch.severity,status:"OPEN",created:new Date().toISOString(),assignee:"Analyst-1"},...p])} style={{background:"rgba(10,132,255,.12)",border:"1px solid #0a84ff40",color:"#0a84ff",borderRadius:5,padding:"5px 10px",fontSize:7,letterSpacing:1,whiteSpace:"nowrap"}}>+ CREATE CASE</button>
                  </div>
                  {/* attack chain viz */}
                  <div style={{display:"flex",alignItems:"center",gap:0,marginBottom:12,flexWrap:"wrap"}}>
                    {ch.sequence.map((s,j)=>(
                      <div key={j} style={{display:"flex",alignItems:"center"}}>
                        <div style={{background:`${MITRE_LOCAL[s]?TAC_COLORS[MITRE_LOCAL[s].tactic]||"#607080":"#607080"}18`,border:`1px solid ${MITRE_LOCAL[s]?TAC_COLORS[MITRE_LOCAL[s].tactic]||"#607080":"#607080"}40`,borderRadius:5,padding:"4px 10px",fontSize:8,color:MITRE_LOCAL[s]?TAC_COLORS[MITRE_LOCAL[s].tactic]||"#c0d0e0":"#c0d0e0",fontWeight:500}}>{s}</div>
                        {j<ch.sequence.length-1&&<div style={{fontSize:10,color:"#1a3050",margin:"0 4px"}}>→</div>}
                      </div>
                    ))}
                  </div>
                  <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                    {ch.mitre_tactics.map(t=>(
                      <span key={t} style={{background:`${TAC_COLORS[t]||"#607080"}15`,border:`1px solid ${TAC_COLORS[t]||"#607080"}35`,color:TAC_COLORS[t]||"#607080",borderRadius:3,padding:"2px 7px",fontSize:7}}>{t}</span>
                    ))}
                    {ch.affectedUsers?.map(u=><span key={u} style={{background:"rgba(191,90,242,.1)",border:"1px solid rgba(191,90,242,.25)",color:"#bf5af2",borderRadius:3,padding:"2px 7px",fontSize:7}}>👤 {u}</span>)}
                    {ch.affectedIPs?.map(ip=><span key={ip} style={{background:"rgba(255,45,85,.08)",border:"1px solid rgba(255,45,85,.2)",color:"#ff6070",borderRadius:3,padding:"2px 7px",fontSize:7}}>🌐 {ip}</span>)}
                  </div>
                </div>
              ))}
            </div>
            {cases.length>0&&(
              <div style={{marginTop:16,background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:10}}>📋 ACTIVE CASES</div>
                <div style={{display:"flex",flexDirection:"column",gap:6}}>
                  {cases.map(ca=>(
                    <div key={ca.id} style={{display:"flex",alignItems:"center",gap:12,background:"rgba(10,132,255,.06)",border:"1px solid #0a84ff20",borderRadius:6,padding:"8px 12px"}}>
                      <span style={{fontSize:8,color:"#0a84ff",fontWeight:700}}>{ca.id}</span>
                      <span style={{fontSize:8,color:"#8ab4d0",flex:1}}>{ca.title}</span>
                      <Badge s={ca.severity} small/><Badge s={ca.status} small/>
                      <span style={{fontSize:7,color:"#2a4060"}}>→ {ca.assignee}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>}

          {/* ════ MITRE ATT&CK ════ */}
          {view==="mitre"&&(
            <div>
              <div style={{marginBottom:14}}>
                <div style={{fontSize:10,color:"#c0d8f0",fontWeight:600,marginBottom:4}}>MITRE ATT&CK® CLOUD MATRIX</div>
                <div style={{fontSize:8,color:"#2a4060"}}>Techniques detected in current session · IaaS / SaaS cloud scope</div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10,marginBottom:16}}>
                {TACTIC_ORDER.slice(0,5).concat(TACTIC_ORDER.slice(5)).map(tactic=>{
                  const techniques=Object.entries(MITRE_LOCAL).filter(([_,m])=>m.tactic===tactic);
                  const detected=techniques.filter(([ev])=>events.some(e=>e.eventName===ev));
                  return (
                    <div key={tactic} style={{background:"#06101e",border:`1px solid ${TAC_COLORS[tactic]||"#607080"}25`,borderTop:`2px solid ${TAC_COLORS[tactic]||"#607080"}60`,borderRadius:8,padding:"10px 12px"}}>
                      <div style={{fontSize:7,color:TAC_COLORS[tactic]||"#607080",letterSpacing:2,fontWeight:700,marginBottom:6}}>{tactic.toUpperCase()}</div>
                      <div style={{display:"flex",flexDirection:"column",gap:4}}>
                        {techniques.map(([ev,m])=>{
                          const hit=events.some(e=>e.eventName===ev);
                          return (
                            <div key={ev} style={{background:hit?`${TAC_COLORS[tactic]||"#607080"}18`:"rgba(255,255,255,.02)",border:`1px solid ${hit?`${TAC_COLORS[tactic]||"#607080"}40`:"#0d2035"}`,borderRadius:4,padding:"4px 7px"}}>
                              <div style={{fontSize:7,color:hit?TAC_COLORS[tactic]||"#c0d0e0":"#2a4060",fontWeight:hit?600:400}}>{m.id}</div>
                              <div style={{fontSize:6,color:hit?"#8090a0":"#1a3050",marginTop:1}}>{ev}</div>
                            </div>
                          );
                        })}
                        {techniques.length===0&&<div style={{fontSize:7,color:"#1a3050",fontStyle:"italic"}}>No techniques mapped</div>}
                      </div>
                      <div style={{marginTop:6,fontSize:7,color:`${TAC_COLORS[tactic]||"#607080"}80`}}>{detected.length}/{techniques.length} detected</div>
                    </div>
                  );
                })}
              </div>
              {/* recent MITRE events */}
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:10}}>RECENT TECHNIQUE DETECTIONS</div>
                <div style={{display:"grid",gridTemplateColumns:"70px 100px 120px 90px 90px 1fr",gap:8,padding:"5px 8px",borderBottom:"1px solid #0a1828",fontSize:6,color:"#1a3050",letterSpacing:2}}>
                  {["TIME","TECHNIQUE","TACTIC","EVENT","SOURCE IP","SEVERITY"].map(h=><div key={h}>{h}</div>)}
                </div>
                <div style={{maxHeight:200,overflowY:"auto"}}>
                  {events.filter(e=>e.mitre?.id&&e.status!=="NORMAL").slice(0,30).map(ev=>(
                    <div key={ev.id} style={{display:"grid",gridTemplateColumns:"70px 100px 120px 90px 90px 1fr",gap:8,padding:"5px 8px",borderBottom:"1px solid #060d1a",fontSize:8,alignItems:"center"}}>
                      <div style={{color:"#1e3a5a",fontSize:7}}>{(()=>{try{return new Date(ev.timestamp).toLocaleTimeString();}catch{return "";}})()}</div>
                      <div style={{color:TAC_COLORS[ev.mitre?.tactic]||"#607080",fontWeight:600}}>{ev.mitre?.id}</div>
                      <div style={{fontSize:7,color:TAC_COLORS[ev.mitre?.tactic]||"#607080"}}>{ev.mitre?.tactic||"—"}</div>
                      <div style={{color:c(ev.status),fontSize:8}}>{ev.eventName}</div>
                      <div style={{color:"#2a5070",fontSize:8}}>{ev.sourceIP||ev.ip}</div>
                      <div><Badge s={ev.mitre?.sev||"low"} small/></div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ════ CSPM ════ */}
          {view==="cspm"&&(
            <div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:16}}>
                {[["CRITICAL",cspm.filter(f=>f.severity==="critical"&&f.status==="OPEN").length,"#ff2d55"],["HIGH",cspm.filter(f=>f.severity==="high"&&f.status==="OPEN").length,"#ff9500"],["MEDIUM",cspm.filter(f=>f.severity==="medium"&&f.status==="OPEN").length,"#ffcc00"],["RESOLVED",cspm.filter(f=>f.status==="RESOLVED").length,"#34c759"]].map(([l,v,col])=>(
                  <div key={l} style={{background:"#06101e",border:`1px solid ${col}25`,borderTop:`2px solid ${col}50`,borderRadius:10,padding:"14px 16px"}}>
                    <div style={{fontSize:8,color:"#1e3a5a",letterSpacing:3,marginBottom:6}}>{l}</div>
                    <div style={{fontSize:30,color:col,fontWeight:700,fontFamily:D}}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:12}}>🔍 CLOUD SECURITY POSTURE FINDINGS</div>
                <div style={{display:"flex",flexDirection:"column",gap:8}}>
                  {cspm.map(f=>(
                    <div key={f.id} className="rh" style={{display:"grid",gridTemplateColumns:"60px 1fr 80px 60px 1fr 80px",gap:12,padding:"10px 12px",background:f.status==="RESOLVED"?"rgba(52,199,89,.03)":"rgba(255,45,85,.03)",border:`1px solid ${f.status==="RESOLVED"?"rgba(52,199,89,.12)":f.severity==="critical"?"rgba(255,45,85,.2)":f.severity==="high"?"rgba(255,149,0,.15)":"rgba(255,204,0,.12)"}`,borderRadius:7,alignItems:"center"}}>
                      <span style={{fontSize:8,color:"#2a4060",fontFamily:M}}>{f.id}</span>
                      <div><div style={{fontSize:9,color:"#c0d8f0",fontWeight:500,marginBottom:2}}>{f.title}</div><div style={{fontSize:7,color:"#2a5070"}}>{f.resource}</div></div>
                      <Badge s={f.severity}/>
                      <span style={{fontSize:7,color:"#FF990080",background:"rgba(255,153,0,.08)",border:"1px solid rgba(255,153,0,.15)",borderRadius:3,padding:"2px 6px"}}>{f.service}</span>
                      <div style={{fontSize:7,color:"#3a6080",lineHeight:1.5}}>💡 {f.remediation}</div>
                      <Badge s={f.status}/>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ════ THREAT HUNT ════ */}
          {view==="hunt"&&(
            <div>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"16px 18px",marginBottom:14}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:12}}>🕵️ THREAT HUNTING CONSOLE</div>
                <div style={{display:"flex",gap:10,alignItems:"flex-end"}}>
                  <div style={{flex:1}}>
                    <div style={{fontSize:7,color:"#1e3a5a",letterSpacing:2,marginBottom:4}}>SEARCH QUERY</div>
                    <input value={huntQuery} onChange={e=>setHuntQuery(e.target.value)} onKeyDown={e=>e.key==="Enter"&&hunt()} placeholder='Search events — e.g. "DeleteTrail" or "185.220.101.47" or "root"' style={{width:"100%",background:"#030710",border:"1px solid #0d2035",borderRadius:5,padding:"8px 12px",color:"#8ab4d0",fontSize:9,fontFamily:M}}/>
                  </div>
                  <div>
                    <div style={{fontSize:7,color:"#1e3a5a",letterSpacing:2,marginBottom:4}}>FIELD</div>
                    <select value={huntField} onChange={e=>setHuntField(e.target.value)} style={{background:"#040a14",border:"1px solid #0d2035",color:"#607080",borderRadius:5,padding:"8px 10px",fontSize:8,fontFamily:M}}>
                      {["eventName","sourceIP","user","region","errorCode"].map(f=><option key={f} value={f}>{f}</option>)}
                    </select>
                  </div>
                  <button className="btn" onClick={hunt} style={{background:"rgba(10,132,255,.15)",border:"1px solid #0a84ff50",color:"#0a84ff",borderRadius:5,padding:"8px 16px",fontSize:8,letterSpacing:1}}>🔍 HUNT</button>
                </div>
                <div style={{display:"flex",gap:8,marginTop:8,flexWrap:"wrap"}}>
                  {["DeleteTrail","GetSecretValue","DisableMFADevice","185.220.101.47","root","cn-north-1","AccessDenied"].map(q=>(
                    <button key={q} className="btn" onClick={()=>{setHuntQuery(q);setTimeout(hunt,50);}} style={{background:"rgba(0,100,200,.08)",border:"1px solid #1a3050",color:"#2a5070",borderRadius:3,padding:"3px 8px",fontSize:7}}>
                      {q}
                    </button>
                  ))}
                </div>
              </div>
              {huntResults.length>0&&(
                <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                  <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:10}}>RESULTS · {huntResults.length} events</div>
                  <div style={{display:"grid",gridTemplateColumns:"70px 110px 90px 90px 80px 80px",gap:8,padding:"5px 8px",borderBottom:"1px solid #0a1828",fontSize:6,color:"#1a3050",letterSpacing:2}}>
                    {["TIME","EVENT","SOURCE IP","REGION","USER","STATUS"].map(h=><div key={h}>{h}</div>)}
                  </div>
                  <div style={{maxHeight:360,overflowY:"auto"}}>
                    {huntResults.map(ev=>(
                      <div key={ev.id} className="rh" onClick={()=>setSelected(selected?.id===ev.id?null:ev)} style={{display:"grid",gridTemplateColumns:"70px 110px 90px 90px 80px 80px",gap:8,padding:"6px 8px",borderBottom:"1px solid #060d1a",fontSize:9,background:selected?.id===ev.id?"rgba(0,100,200,.08)":"transparent",alignItems:"center"}}>
                        <div style={{fontSize:7,color:"#1e3a5a"}}>{(()=>{try{return new Date(ev.timestamp||ev.time).toLocaleTimeString();}catch{return ev.time||"";}})()}</div>
                        <div style={{color:c(ev.status),fontWeight:600,fontSize:8}}>{ev.eventName}</div>
                        <div style={{color:"#2a5070",fontSize:8}}>{ev.sourceIP||ev.ip}</div>
                        <div><span style={{background:"rgba(255,153,0,.08)",border:"1px solid rgba(255,153,0,.15)",color:"#FF9900",borderRadius:2,padding:"1px 4px",fontSize:6}}>{ev.region}</span></div>
                        <div style={{color:"#4a7090",fontSize:8}}>{ev.user}</div>
                        <Badge s={ev.status} small/>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ════ HONEYPOT ════ */}
          {view==="honeypot"&&(
            <div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
                {[["ACTIVE TRAPS","3","#0a84ff"],["TRIGGERED","3","#ff2d55"],["ATTACKER IPs","3","#ffcc00"]].map(([l,v,col])=>(
                  <div key={l} style={{background:"#06101e",border:`1px solid ${col}25`,borderTop:`2px solid ${col}50`,borderRadius:10,padding:"14px 16px"}}>
                    <div style={{fontSize:8,color:"#1e3a5a",letterSpacing:3,marginBottom:6}}>{l}</div>
                    <div style={{fontSize:32,color:col,fontWeight:700,fontFamily:D}}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:14}}>
                {[{id:"HP-T1",type:"S3 Honeybucket",asset:"s3://honeypot-credentials-prod",status:"ARMED",trips:1},{id:"HP-T2",type:"IAM Honey Role",asset:"arn:aws:iam::honeypot-admin-role",status:"ARMED",trips:1},{id:"HP-T3",type:"Fake Secret",asset:"arn:aws:secretsmanager::fake-api-key",status:"ARMED",trips:1},{id:"HP-T4",type:"EC2 Honey Instance",asset:"i-0honeypot456",status:"ARMED",trips:0}].map(trap=>(
                  <div key={trap.id} style={{background:"#06101e",border:`1px solid ${trap.trips>0?"rgba(255,45,85,.25)":"rgba(52,199,89,.15)"}`,borderRadius:8,padding:"12px 14px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <div>
                      <div style={{fontSize:7,color:trap.trips>0?"#ff2d55":"#34c759",letterSpacing:2,marginBottom:3}}>{trap.type} · {trap.id}</div>
                      <div style={{fontSize:8,color:"#8ab4d0"}}>{trap.asset}</div>
                    </div>
                    <div style={{textAlign:"center"}}>
                      <div style={{fontSize:18,color:trap.trips>0?"#ff2d55":"#34c759",fontWeight:700,fontFamily:D}}>{trap.trips}</div>
                      <div style={{fontSize:6,color:"#1e3a5a"}}>TRIGGERS</div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600,marginBottom:10}}>🍯 HONEYPOT TRIGGER EVENTS</div>
                <div style={{display:"flex",flexDirection:"column",gap:8}}>
                  {honeyp.map(h=>(
                    <div key={h.id} style={{background:"rgba(255,45,85,.04)",border:"1px solid rgba(255,45,85,.2)",borderRadius:8,padding:"12px 14px",borderLeft:"3px solid #ff2d55"}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                        <div style={{display:"flex",gap:8,alignItems:"center"}}>
                          <Badge s={h.severity}/>
                          <span style={{fontSize:9,color:"#dff0ff",fontWeight:600}}>{h.type} TRIGGERED</span>
                        </div>
                        <span style={{fontSize:8,color:"#ff2d55"}}>{h.timestamp}</span>
                      </div>
                      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
                        {[["Asset",h.asset],["Source IP",h.sourceIP],["Action",h.action],["Intel",h.attackerInfo]].map(([k,v])=>(
                          <div key={k}><div style={{fontSize:6,color:"#1a3050",letterSpacing:2,marginBottom:2}}>{k}</div><div style={{fontSize:8,color:"#8090a0"}}>{v}</div></div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ════ LOG UPLOAD ════ */}
          {view==="upload"&&(
            <div>
              {!upData?(
                <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",minHeight:300}}>
                  <div ref={dropRef} className="drop-zone" onDragOver={e=>{e.preventDefault();dropRef.current?.classList.add("drop-active")}} onDragLeave={()=>dropRef.current?.classList.remove("drop-active")} onDrop={handleDrop} onClick={()=>fileRef.current?.click()} style={{border:"2px dashed rgba(0,140,255,.2)",borderRadius:12,padding:"40px 60px",textAlign:"center",maxWidth:400}}>
                    <div style={{fontSize:40,marginBottom:12}}>🗂️</div>
                    <div style={{fontSize:10,color:"#2a4060",marginBottom:6,letterSpacing:1}}>DROP CLOUDTRAIL LOG</div>
                    <div style={{fontSize:8,color:"#1a3050"}}>JSON · CSV supported<br/>Real AWS CloudTrail format or synthetic</div>
                    {upState==="error"&&<div style={{fontSize:8,color:"#ff2d55",marginTop:8}}>⚠ Parse error — check file format</div>}
                  </div>
                  {upState==="analyzing"&&(
                    <div style={{marginTop:20,textAlign:"center"}}>
                      <div className="spin" style={{width:28,height:28,border:"2px solid #0a84ff",borderTopColor:"transparent",borderRadius:"50%",margin:"0 auto 10px"}}/>
                      <div style={{fontSize:9,color:"#0a84ff",letterSpacing:2}}>ML ANALYSIS IN PROGRESS · {Math.floor(upPct)}%</div>
                      <div style={{width:200,height:3,background:"#0a1020",borderRadius:2,margin:"8px auto 0"}}>
                        <div style={{height:"100%",width:`${upPct}%`,background:"linear-gradient(90deg,#0a84ff,#34c759)",borderRadius:2,transition:"width .2s"}}/>
                      </div>
                    </div>
                  )}
                </div>
              ):(
                <div>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
                    <div>
                      <div style={{fontSize:10,color:"#c0d8f0",fontWeight:600,marginBottom:2}}>📂 {upData.filename} · {upData.analyzedAt}</div>
                      <div style={{fontSize:8,color:"#2a4060"}}>{upData.total} events analyzed · {apiOnline?"Isolation Forest + RF":"Rule-based classifier"}</div>
                    </div>
                    <button className="btn" onClick={()=>{setUpData(null);setUpState("idle");}} style={{background:"rgba(255,45,85,.1)",border:"1px solid #ff2d5535",color:"#ff2d55",borderRadius:5,padding:"5px 12px",fontSize:8}}>✕ CLEAR</button>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:14}}>
                    {[["THREATS",upData.threats,"#ff2d55"],["SUSPICIOUS",upData.suspicious,"#ffcc00"],["NORMAL",upData.normal,"#34c759"],["TOTAL",upData.total,"#0a84ff"]].map(([l,v,col])=>(
                      <div key={l} style={{background:"#06101e",border:`1px solid ${col}25`,borderTop:`2px solid ${col}50`,borderRadius:8,padding:"12px 14px"}}>
                        <div style={{fontSize:8,color:"#1e3a5a",letterSpacing:3,marginBottom:4}}>{l}</div>
                        <div style={{fontSize:28,color:col,fontWeight:700,fontFamily:D}}>{v}</div>
                      </div>
                    ))}
                  </div>
                  {upData.correlation?.attackChains?.length>0&&(
                    <div style={{background:"rgba(255,45,85,.04)",border:"1px solid rgba(255,45,85,.2)",borderRadius:10,padding:"12px 16px",marginBottom:14}}>
                      <div style={{fontSize:8,color:"#ff2d55",letterSpacing:3,fontWeight:600,marginBottom:8}}>⚡ ATTACK CHAINS DETECTED IN LOG</div>
                      {upData.correlation.attackChains.map((ch,i)=>(
                        <div key={i} style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
                          <Badge s={ch.severity}/><span style={{fontSize:9,color:"#dff0ff"}}>{ch.name}</span><span style={{fontSize:8,color:"#34c759"}}>{ch.confidence}%</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 16px"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                      <div style={{fontSize:8,color:"#c0d8f0",letterSpacing:3,fontWeight:600}}>ANALYZED EVENTS · {upData.events.filter(e=>upFilter==="ALL"||e.status===upFilter).length}</div>
                      <div style={{display:"flex",gap:5}}>
                        {["ALL","THREAT","SUSPICIOUS","NORMAL"].map(f=>(
                          <button key={f} className="btn" onClick={()=>setUpFilter(f)} style={{background:upFilter===f?(f==="THREAT"?"rgba(255,45,85,.18)":f==="SUSPICIOUS"?"rgba(255,204,0,.15)":f==="NORMAL"?"rgba(52,199,89,.12)":"rgba(0,130,255,.12)"):"transparent",border:`1px solid ${upFilter===f?"#0a84ff50":"#0d2035"}`,color:upFilter===f?"#0a84ff":"#1e3a5a",borderRadius:4,padding:"3px 8px",fontSize:7,letterSpacing:1}}>{f}</button>
                        ))}
                      </div>
                    </div>
                    <div style={{display:"grid",gridTemplateColumns:"70px 110px 90px 90px 80px 60px 80px",gap:6,padding:"5px 8px",borderBottom:"1px solid #0a1828",fontSize:6,color:"#1a3050",letterSpacing:2}}>
                      {["TIME","EVENT","SOURCE IP","REGION","USER","RISK","STATUS"].map(h=><div key={h}>{h}</div>)}
                    </div>
                    <div style={{maxHeight:300,overflowY:"auto"}}>
                      {upData.events.filter(e=>upFilter==="ALL"||e.status===upFilter).map(ev=>(
                        <div key={ev.id} className="rh" onClick={()=>setSelected(selected?.id===ev.id?null:ev)} style={{display:"grid",gridTemplateColumns:"70px 110px 90px 90px 80px 60px 80px",gap:6,padding:"6px 8px",borderBottom:"1px solid #060d1a",fontSize:9,background:selected?.id===ev.id?"rgba(0,100,200,.08)":"transparent",alignItems:"center",borderLeft:ev.status==="THREAT"?"2px solid #ff2d5540":ev.status==="SUSPICIOUS"?"2px solid #ffcc0030":"2px solid transparent"}}>
                          <div style={{fontSize:7,color:"#1e3a5a"}}>{(()=>{try{return new Date(ev.timestamp).toLocaleTimeString();}catch{return "";}})()}</div>
                          <div style={{color:c(ev.status),fontWeight:600,fontSize:8}}>{ev.eventName}</div>
                          <div style={{color:"#2a5070",fontSize:8}}>{ev.sourceIP}</div>
                          <div><span style={{background:"rgba(255,153,0,.08)",border:"1px solid rgba(255,153,0,.15)",color:"#FF9900",borderRadius:2,padding:"1px 4px",fontSize:6}}>{ev.region}</span></div>
                          <div style={{color:"#4a7090",fontSize:8}}>{ev.user}</div>
                          <RiskBar v={ev.risk}/>
                          <Badge s={ev.status} small/>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ════ AI COPILOT ════ */}
          {view==="copilot"&&(
            <div style={{display:"flex",flexDirection:"column",height:"calc(100vh - 130px)"}}>
              <div style={{background:"#06101e",border:"1px solid #0d2035",borderRadius:10,padding:"14px 18px",marginBottom:12}}>
                <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
                  <div style={{width:28,height:28,borderRadius:6,background:"linear-gradient(135deg,#0a84ff,#bf5af2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14}}>🤖</div>
                  <div><div style={{fontSize:10,color:"#dff0ff",fontWeight:600}}>AI SOC COPILOT</div><div style={{fontSize:7,color:"#1e3a5a"}}>Claude-powered cloud security analyst · AWS CloudTrail · MITRE ATT&CK expert</div></div>
                </div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  {["Why was this event flagged?","Summarize the attack chain","What MITRE techniques were used?","Which resources are affected?","Recommend remediation steps","Explain the IAM privilege escalation"].map(q=>(
                    <button key={q} className="btn" onClick={()=>{setCopilotQ(q);}} style={{background:"rgba(10,132,255,.08)",border:"1px solid #0a84ff25",color:"#2a5070",borderRadius:4,padding:"4px 10px",fontSize:7}}>
                      {q}
                    </button>
                  ))}
                </div>
              </div>
              <div style={{flex:1,background:"#06101e",border:"1px solid #0d2035",borderRadius:10,display:"flex",flexDirection:"column",overflow:"hidden"}}>
                <div style={{flex:1,overflowY:"auto",padding:"14px 16px",display:"flex",flexDirection:"column",gap:10}}>
                  {copilotH.length===0&&(
                    <div style={{textAlign:"center",padding:"40px 20px",color:"#1e3a5a"}}>
                      <div style={{fontSize:30,marginBottom:10}}>🤖</div>
                      <div style={{fontSize:9,letterSpacing:1}}>ASK ME ANYTHING ABOUT YOUR CLOUD SECURITY</div>
                      <div style={{fontSize:7,marginTop:4,color:"#122030"}}>Attack analysis · MITRE mapping · Remediation · Threat intelligence</div>
                    </div>
                  )}
                  {copilotH.map((msg,i)=>(
                    <div key={i} className="fade-up" style={{display:"flex",gap:10,justifyContent:msg.role==="user"?"flex-end":"flex-start"}}>
                      {msg.role==="assistant"&&<div style={{width:22,height:22,borderRadius:5,background:"linear-gradient(135deg,#0a84ff,#bf5af2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,flexShrink:0}}>🤖</div>}
                      <div style={{maxWidth:"78%",background:msg.role==="user"?"rgba(10,132,255,.15)":"rgba(96,112,128,.1)",border:`1px solid ${msg.role==="user"?"#0a84ff30":"#1a3050"}`,borderRadius:8,padding:"10px 14px"}}>
                        <div style={{fontSize:9,color:msg.role==="user"?"#8ab4d0":"#7090a0",lineHeight:1.7,whiteSpace:"pre-wrap"}}>{msg.content}</div>
                      </div>
                      {msg.role==="user"&&<div style={{width:22,height:22,borderRadius:5,background:"rgba(10,132,255,.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,flexShrink:0}}>👤</div>}
                    </div>
                  ))}
                  {copilotBusy&&<div style={{display:"flex",gap:10}}><div style={{width:22,height:22,borderRadius:5,background:"linear-gradient(135deg,#0a84ff,#bf5af2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11}}>🤖</div><div style={{background:"rgba(96,112,128,.1)",border:"1px solid #1a3050",borderRadius:8,padding:"10px 14px"}}><div className="spin" style={{width:14,height:14,border:"2px solid #0a84ff",borderTopColor:"transparent",borderRadius:"50%"}}/></div></div>}
                </div>
                <div style={{padding:"12px 14px",borderTop:"1px solid #0d2035",display:"flex",gap:10}}>
                  <textarea value={copilotQ} onChange={e=>setCopilotQ(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();askCopilot();}}} placeholder="Ask about threats, attack chains, MITRE techniques, remediation…  (Enter to send)" style={{flex:1,background:"#030710",border:"1px solid #0d2035",borderRadius:6,padding:"8px 12px",color:"#8ab4d0",fontSize:9,fontFamily:M,minHeight:44,maxHeight:90}}/>
                  <button className="btn" onClick={askCopilot} disabled={copilotBusy||!copilotQ.trim()} style={{background:copilotBusy?"rgba(96,112,128,.1)":"rgba(10,132,255,.18)",border:`1px solid ${copilotBusy?"#1a3050":"#0a84ff50"}`,color:copilotBusy?"#2a4060":"#0a84ff",borderRadius:6,padding:"8px 16px",fontSize:9,letterSpacing:1,alignSelf:"stretch"}}>
                    {copilotBusy?"…":"SEND"}
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

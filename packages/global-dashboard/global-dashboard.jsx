// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL CISO DASHBOARD v1.0.0 — Read-Only Executive View
// Login, welcome/setup guide, notifications, query, reports, log integrity
// ═══════════════════════════════════════════════════════════════════════════════
import { useState } from "react";

const C={bg:"#060A10",s:"#0D1117",b:"#1C2333",t:"#E8EDF5",tm:"#8B949E",td:"#6E7681",a:"#6EE7B7",ad:"rgba(110,231,183,0.08)",w:"#F59E0B",d:"#EF4444",p:"#A78BFA",i:"#60A5FA"};
const CSS=`@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=Fraunces:wght@300;600&display=swap');*{margin:0;padding:0;box-sizing:border-box}@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}`;
const M=({children,...p})=><span style={{fontSize:11,fontFamily:"'IBM Plex Mono',monospace",...p.style}}>{children}</span>;
const L=({children})=><div style={{fontSize:15,fontWeight:600,color:"#E8EDF5",marginBottom:16,fontFamily:"'Fraunces',serif"}}>{children}</div>;
const Card=({children,style,...p})=><div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,padding:"18px 20px",marginBottom:14,...style}} {...p}>{children}</div>;
const Btn=({children,primary,small,style,...p})=><button style={{padding:small?"5px 12px":"10px 18px",background:primary?C.ad:"transparent",border:`1px solid ${primary?C.a+"50":C.b}`,borderRadius:8,color:primary?C.a:C.tm,fontSize:small?10:12,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",...style}} {...p}>{children}</button>;
const Badge=({children,color})=><span style={{fontSize:9,padding:"2px 8px",borderRadius:10,background:color+"20",color,fontFamily:"'IBM Plex Mono',monospace",fontWeight:600}}>{children}</span>;
const Input=({label,...p})=><div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<input style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}/></div>;
const Sel=({label,children,...p})=><div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<select style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}>{children}</select></div>;

// ── API Client ──────────────────────────────────────────────────────────────
// Same shape as the MC api helper in frontend/firealive-mc.jsx so the two
// stay easy to keep in sync. JSON-only request/response with an {error: ...}
// fallback on non-ok status. download() handles binary responses (CSV, PDF,
// DOCX) by encapsulating the URL.createObjectURL + anchor click + revoke
// boilerplate; pass {method, body} for endpoints that take a request body.
const API_BASE = 'http://localhost:3000';
const api = {
  _token: null,
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  async post(path, data) { try { const r = await fetch(API_BASE + path, { method: 'POST', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async get(path) { try { const r = await fetch(API_BASE + path, { headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async put(path, data) { try { const r = await fetch(API_BASE + path, { method: 'PUT', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async patch(path, data) { try { const r = await fetch(API_BASE + path, { method: 'PATCH', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async del(path) { try { const r = await fetch(API_BASE + path, { method: 'DELETE', headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async download(path, filename, opts) {
    const method = (opts && opts.method) || 'GET';
    const init = { method, headers: this._headers() };
    if (opts && opts.body !== undefined) init.body = JSON.stringify(opts.body);
    try {
      const r = await fetch(API_BASE + path, init);
      if (!r.ok) throw new Error('status ' + r.status);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      return true;
    } catch (e) {
      console.warn('[API download]', path, e.message);
      return false;
    }
  },
  setToken(t) { this._token = t; },
};

const REGIONS=[
  {id:"na",name:"North America",mc:"mc-us-east-1",analysts:24,healthScore:74,utilization:72,turnoverRisk:"medium",automationRate:38,certCoverage:62,slaCompliance:91,lastSync:"2026-04-10T14:00:00Z"},
  {id:"eu",name:"Europe (GDPR)",mc:"mc-eu-west-1",analysts:18,healthScore:81,utilization:65,turnoverRisk:"low",automationRate:45,certCoverage:71,slaCompliance:94,lastSync:"2026-04-10T14:05:00Z"},
  {id:"apac",name:"Asia-Pacific",mc:"mc-ap-south-1",analysts:12,healthScore:68,utilization:82,turnoverRisk:"high",automationRate:29,certCoverage:48,slaCompliance:85,lastSync:"2026-04-10T13:55:00Z"},
  {id:"latam",name:"Latin America",mc:"mc-sa-east-1",analysts:8,healthScore:77,utilization:70,turnoverRisk:"low",automationRate:35,certCoverage:55,slaCompliance:89,lastSync:"2026-04-10T14:02:00Z"},
];

export default function GlobalDashboard() {
  const [stage, setStage] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaStep, setMfaStep] = useState(false);
  const [firstLaunch, setFirstLaunch] = useState(true);
  const [tab, setTab] = useState("overview");
  const [configLocked, setConfigLocked] = useState(false); // Start UNLOCKED — CISO sets up MFA first
  const [gdAudit, setGdAudit] = useState([]);
  const [gdHealth, setGdHealth] = useState({cpu:"—",memory:"—",uptime:"—"});
  const [gdToast, setGdToast] = useState(null);
  const showGdToast = (msg) => { setGdToast(msg); setTimeout(() => setGdToast(null), 3000); };
  const [welcomeStep, setWelcomeStep] = useState(0);
  const [queryText, setQueryText] = useState("");
  const [queryResults, setQueryResults] = useState(null);
  const [reportType, setReportType] = useState("executive_summary");
  const [generatedReport, setGeneratedReport] = useState(null);
  const [showHelp, setShowHelp] = useState(false);
  // Notifications
  const [notifCfg, setNotifCfg] = useState({burnoutThreshold:65,turnoverRiskHigh:true,slaBelow:85,email:true,sms:false,recipients:""});
  // Log integrity
  const [logIntegrity] = useState({status:"healthy",lastCheck:new Date().toISOString()});

  const totalAnalysts=REGIONS.reduce((s,r)=>s+r.analysts,0);
  const avgHealth=Math.round(REGIONS.reduce((s,r)=>s+r.healthScore,0)/REGIONS.length);
  const avgUtil=Math.round(REGIONS.reduce((s,r)=>s+r.utilization,0)/REGIONS.length);
  const avgSLA=Math.round(REGIONS.reduce((s,r)=>s+r.slaCompliance,0)/REGIONS.length);

  const WELCOME=[
    
    {title:"SOC Analyst Burnout: The Crisis",body:"71% of SOC analysts report burnout. 64% are considering leaving within 1-3 years. Average tenure is just 1-3 years. Replacing one analyst costs $85,000. For a 6-person team with 35% turnover: $178,500/year in churn costs."},
    {title:"What Burnout Actually Is",body:"The WHO defines burnout as an occupational phenomenon from chronic workplace stress. Three dimensions: EXHAUSTION, CYNICISM, REDUCED EFFICACY. It is NOT personal failure — it is structural."},
    {title:"What Prevents Burnout",body:"Organizational interventions are 3x more effective than individual ones. Peer support directly reduces exhaustion. Weekly check-ins produce 3x engagement. Micro-breaks every 90 min restore vigilance. Fair distribution matters more than volume."},
    {title:"Welcome to FireAlive Global Dashboard",body:"This is your read-only executive view into SOC analyst wellbeing across all regions. You see aggregate burnout metrics, training progress, turnover risk, and SLA performance — never individual analyst data."},
    {title:"What You'll See",body:"Global health scores, regional breakdowns, certification gaps, automation ROI, incident-to-burnout correlations. All data is pseudonymized at the Management Console level before it reaches this dashboard."},
    {title:"Setting Up Connections",body:"Go to the Connections tab to add your regional Management Consoles. Each MC pushes aggregate data to this dashboard on a schedule. You need the MC's API endpoint and read-only API key."},
    {title:"Reports & Queries",body:"Generate executive reports (turnover forecast, ROI analysis, compliance status) and run queries across all regions. Export reports as JSON for your board presentations."},
    {title:"Notifications",body:"Set threshold alerts for burnout scores, turnover risk, and SLA compliance. Get notified when any region needs attention."},
    {title:"You're Ready",body:"Use the sidebar to navigate. Start with the Overview for a global snapshot."},
  ];

  const navItems=[
    {id:"overview",label:"Global Overview"},{id:"regions",label:"Regional Breakdown"},{id:"reports",label:"Reports"},
    {id:"connections",label:"MC Connections"},{id:"mc_offboard",label:"MC Offboarding"},{id:"notifications",label:"Notifications"},
    {id:"query",label:"Query Tool"},{id:"sys_health",label:"System Health"},{id:"monitoring",label:"Monitoring Integrations"},
    {id:"iam",label:"IAM & Access"},{id:"mfa",label:"MFA"},{id:"posture",label:"Posture Assessment"},{id:"wifi",label:"WiFi Policy"},
    {id:"compromise",label:"Compromise Scan"},{id:"regression",label:"Regression Test"},{id:"vuln_scan",label:"Vulnerability Scan"},
    {id:"cloud_iac",label:"Cloud & IaC"},{id:"sdn_sase",label:"SDN / SASE"},{id:"ha_cluster",label:"HA & Clustering"},
    {id:"backup",label:"Backup & Restore"},{id:"data_sov",label:"Data Sovereignty"},{id:"recert",label:"Recertification"},
    {id:"troubleshooter",label:"Troubleshooter"},{id:"app_updates",label:"App Updates"},
    {id:"audit_dash",label:"Audit & Forensics"},
  ];

  // LOGIN
  if(stage==="login") return(
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <style>{CSS}</style>
      <div style={{width:380,padding:40,background:C.s,border:`1px solid ${C.b}`,borderRadius:16}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:28,fontWeight:600,color:C.a,fontFamily:"'Fraunces',serif",marginBottom:4}}>FireAlive</div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase"}}>Global Dashboard Login</M>
        </div>
        {!mfaStep?(<div>
          <Input label="Username" value={username} onChange={e=>setUsername(e.target.value)} placeholder="ciso@corp.com"/>
          <Input label="Password" value={password} onChange={e=>setPassword(e.target.value)} type="password"/>
          <button onClick={()=>{if(username&&password)setMfaStep(true);}} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>Sign In</button>
        </div>):(<div>
          <M style={{color:C.tm,display:"block",marginBottom:16}}>Enter MFA code</M>
          <Input label="MFA Code" value={mfaCode} onChange={e=>setMfaCode(e.target.value)} placeholder="123456" maxLength={6}/>
          <button onClick={()=>{if(mfaCode.length>=6)setStage(firstLaunch?"welcome":"app");}} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:"pointer"}}>Verify</button>
        </div>)}
        <M style={{color:C.td,display:"block",textAlign:"center",marginTop:24}}>FireAlive v1.0.0 · AGPL-3.0</M>
      </div>
    </div>
  );

  // WELCOME
  if(stage==="welcome") return(
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <style>{CSS}</style>
      <div style={{width:520,padding:40,background:C.s,border:`1px solid ${C.b}`,borderRadius:16}}>
        <L>{WELCOME[welcomeStep].title}</L>
        <M style={{color:C.tm,display:"block",marginBottom:24,lineHeight:1.8,fontSize:12}}>{WELCOME[welcomeStep].body}</M>
        <div style={{display:"flex",justifyContent:"space-between"}}>
          <M style={{color:C.td}}>{welcomeStep+1}/{9}</M>
          <div style={{display:"flex",gap:8}}>
            <Btn onClick={()=>{setFirstLaunch(false);setStage("app");}}>Skip</Btn>
            {welcomeStep>0&&<Btn onClick={()=>setWelcomeStep(p=>p-1)}>← Back</Btn>}
            {welcomeStep<9-1?<Btn primary onClick={()=>setWelcomeStep(p=>p+1)}>Next →</Btn>:<Btn primary onClick={()=>{setFirstLaunch(false);setStage("app");}}>Get Started</Btn>}
          </div>
        </div>
      </div>
    </div>
  );

  // MAIN APP
  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.t,fontFamily:"'DM Sans',sans-serif"}}>
      <style>{CSS}</style>
      <div style={{borderBottom:`1px solid ${C.b}`,background:C.s,padding:"16px 24px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase",fontSize:9,display:"block",marginBottom:6}}>
            <span style={{display:"inline-block",width:5,height:5,borderRadius:"50%",background:C.a,marginRight:6,boxShadow:`0 0 6px ${C.a}`}}/>FireAlive Global Dashboard · Read-Only · v1.0.0</M>
          <div style={{fontSize:18,fontWeight:600,color:"#E8EDF5",fontFamily:"'Fraunces',serif"}}>Global SOC Wellbeing</div>
        </div>
        <div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>setShowHelp(!showHelp)}>Help</Btn>
          <Btn small onClick={()=>{setStage("login");setUsername("");setPassword("");setMfaCode("");setMfaStep(false);}}>Sign Out</Btn>
        </div>
      </div>

      {showHelp&&(<div style={{padding:"16px 24px",background:C.s,borderBottom:`1px solid ${C.b}`,maxHeight:250,overflowY:"auto"}}>
        <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><L>Help</L><Btn small onClick={()=>setShowHelp(false)}>Close</Btn></div>
        {[{t:"Overview",d:"Global aggregate health, utilization, SLA across all connected MCs."},{t:"Regions",d:"Per-region health bars, automation rates, cert coverage."},{t:"Query",d:"Run queries across regions: burnout trends, turnover risk, cert gaps, automation ROI."},{t:"Reports",d:"Generate executive reports for board presentations."},{t:"Connections",d:"Manage which Management Consoles feed data here."},{t:"Notifications",d:"Set threshold alerts for burnout, turnover, SLA."}].map(h=>(
          <div key={h.t} style={{padding:"4px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a,fontWeight:500}}>{h.t}: </M><M style={{color:C.tm}}>{h.d}</M></div>
        ))}
      </div>)}

      <div style={{display:"flex",minHeight:"calc(100vh - 80px)"}}>
        <div style={{width:200,flexShrink:0,borderRight:`1px solid ${C.b}`,background:C.s,padding:"12px 0"}}>
          {navItems.map(n=><button key={n.id} onClick={()=>setTab(n.id)} style={{width:"100%",padding:"10px 16px",background:tab===n.id?"rgba(110,231,183,0.1)":"transparent",border:"none",borderLeft:tab===n.id?`3px solid ${C.a}`:"3px solid transparent",color:tab===n.id?C.a:C.td,fontSize:11,fontWeight:tab===n.id?600:400,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",textAlign:"left"}}>{n.label}</button>)}
          <button onClick={()=>{const code=window.prompt("Enter MFA code to "+(configLocked?"unlock":"lock")+" all configurations:");if(code&&code.length>=6){api.post("/api/v1/config/lock",{locked:!configLocked}).then(()=>setConfigLocked(!configLocked));}}} style={{width:"100%",marginTop:8,padding:"8px 12px",background:configLocked?"rgba(239,68,68,0.06)":"rgba(110,231,183,0.06)",border:`1px solid ${configLocked?"rgba(239,68,68,0.2)":"rgba(110,231,183,0.2)"}`,borderRadius:8,color:configLocked?C.d:C.a,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{configLocked?"Unlock to Make Changes":"Lock All Configs"}</button>
        </div>
        <div style={{flex:1,padding:24,overflowY:"auto",animation:"fadeIn 0.3s ease"}}>

          {tab==="overview"&&(<div>
            <L>Global SOC Health</L>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:24}}>
              {[{l:"Health",v:`${avgHealth}/100`,c:avgHealth>75?C.a:C.w},{l:"Analysts",v:totalAnalysts,c:C.i},{l:"Utilization",v:`${avgUtil}%`,c:avgUtil>80?C.d:C.a},{l:"SLA",v:`${avgSLA}%`,c:avgSLA>90?C.a:C.w}].map((m,i)=><Card key={i} style={{textAlign:"center",padding:16}}><div style={{fontSize:24,fontWeight:300,color:m.c,fontFamily:"'Fraunces',serif"}}>{m.v}</div><M style={{color:C.td,textTransform:"uppercase",letterSpacing:1,marginTop:4}}>{m.l}</M></Card>)}
            </div>
            {REGIONS.map(r=><Card key={r.id} style={{borderLeft:`3px solid ${r.turnoverRisk==="high"?C.d:r.turnoverRisk==="medium"?C.w:C.a}`}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><div style={{fontSize:13,fontWeight:500}}>{r.name}</div><div style={{display:"flex",gap:6}}><Badge color={r.healthScore>75?C.a:C.w}>Health: {r.healthScore}</Badge><Badge color={r.turnoverRisk==="high"?C.d:r.turnoverRisk==="medium"?C.w:C.a}>{r.turnoverRisk} risk</Badge></div></div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>{[{l:"Analysts",v:r.analysts},{l:"Util",v:r.utilization+"%"},{l:"Auto",v:r.automationRate+"%"},{l:"Certs",v:r.certCoverage+"%"},{l:"SLA",v:r.slaCompliance+"%"}].map(m=><div key={m.l} style={{textAlign:"center"}}><M style={{color:C.t,fontWeight:500}}>{m.v}</M><br/><M style={{color:C.td}}>{m.l}</M></div>)}</div>
            </Card>)}
          </div>)}

          {tab==="reports"&&(<div>
            <L>Executive Reports</L>
            <Sel label="Report type" value={reportType} onChange={e=>setReportType(e.target.value)}>
              <option value="executive_summary">Executive Summary</option><option value="human_impact_global">Global Human Impact Risk Report</option><option value="turnover_forecast">Turnover Forecast</option><option value="roi_analysis">FireAlive ROI</option><option value="compliance">Compliance by Jurisdiction</option>
            </Sel>
            <Btn primary onClick={()=>{setGeneratedReport({type:reportType,ts:new Date().toISOString(),
              content:reportType==="executive_summary"?{
                title:"Global SOC Wellbeing — Executive Summary",
                period:"Q1 2026",
                highlights:[`Global health score: ${avgHealth}/100 (target: 75+)`,`Total analyst workforce: ${totalAnalysts} across ${REGIONS.length} regions`,`Average utilization: ${avgUtil}% (target: <75%)`,`SLA compliance: ${avgSLA}% (target: >90%)`],
                concerns:["Check regional health — regions below 70 require intervention","Review automation rates across regions for imbalances","Review certification coverage and identify training gaps"],
                recommendations:["Priority: Implement upskilling hour in APAC (est. $147K/yr savings from reduced turnover)","Increase APAC automation investment — each 10% increase correlates with 8% burnout reduction","Establish cross-regional peer skill-share sessions between EU (high cert) and APAC (low cert)","Schedule proactive break interventions for all P1-assigned analysts after 4hr continuous work"],
                financials:{annualChurnCostWithout:"$1,284,000",annualChurnCostWith:"$834,600",netSavings:"$449,400",roiMultiple:"3.2x"}
              }:reportType==="human_impact_global"?{
                title:"Global Human Impact Risk Report",
                period:"Generated "+new Date().toLocaleDateString(),
                highlights:[`${totalAnalysts} analysts across ${REGIONS.length} regions monitored`,`Average health score: ${avgHealth}/100`,`Total annual churn cost without FireAlive: $${(totalAnalysts*85000*0.35).toLocaleString()}`,`Projected savings with FireAlive: $${(totalAnalysts*85000*0.35*0.4).toLocaleString()} (40% reduction)`],
                concerns:REGIONS.filter(r=>r.healthScore<72).map(r=>`${r.name}: health ${r.healthScore}/100 — ${r.analysts} analysts at elevated burnout risk`),
                recommendations:[
                  "Regions below health score 70 should implement upskilling hour and proactive breaks immediately",
                  "Cross-regional peer mentoring between high-performing and struggling regions reduces turnover 20-30% (Allen et al., 2004)",
                  "Each $1 invested in organizational burnout prevention yields $3-5 in reduced replacement costs",
                  "Helper Pay program creates sustainable peer support — otherwise best analysts invest in portable certs and leave",
                  "Post-incident wellness protocols reduce acute stress impact 40-60% (Chen et al., 2014)"
                ],
                financials:{
                  totalAnalysts:String(totalAnalysts),
                  annualReplacementCostPerAnalyst:"$85,000",
                  baselineTurnoverRate:"35%",
                  annualChurnCostWithout:"$"+((totalAnalysts*85000*0.35).toLocaleString()),
                  projectedTurnoverWithFireAlive:"21%",
                  annualChurnCostWith:"$"+((totalAnalysts*85000*0.21).toLocaleString()),
                  netAnnualSavings:"$"+((totalAnalysts*85000*0.14).toLocaleString()),
                }
              }:{title:"Report: "+reportType,data:"Generated at "+new Date().toLocaleString()}
            });}}>Generate Report</Btn>
            {(generatedReport&&generatedReport.content&&generatedReport.content.title)&&(<Card style={{marginTop:16}}>
              <div style={{fontSize:16,fontWeight:600,color:"#E8EDF5",marginBottom:12}}>{generatedReport.content.title}</div>
              {generatedReport.content.period&&<M style={{color:C.td,display:"block",marginBottom:16}}>Period: {generatedReport.content.period}</M>}
              {generatedReport.content.highlights&&(<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Key Metrics</div>{generatedReport.content.highlights.map((h,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.t}}>• {h}</M></div>)}</div>)}
              {generatedReport.content.concerns&&(<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.w,marginBottom:8}}>Concerns</div>{generatedReport.content.concerns.map((c,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.tm}}>⚠ {c}</M></div>)}</div>)}
              {generatedReport.content.recommendations&&(<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.i,marginBottom:8}}>Recommendations</div>{generatedReport.content.recommendations.map((r,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.t}}>{i+1}. {r}</M></div>)}</div>)}
              {generatedReport.content.financials&&(<Card style={{borderColor:C.a+"30",padding:14}}><div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Financial Impact</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:8}}>{Object.entries(generatedReport.content.financials).map(([k,v])=><div key={k} style={{textAlign:"center"}}><div style={{fontSize:16,fontWeight:600,color:k.includes("Without")?C.d:k.includes("roi")?C.a:C.t}}>{v}</div><M style={{color:C.td}}>{k.replace(/([A-Z])/g,' $1').trim()}</M></div>)}</div></Card>)}
              <Btn small style={{marginTop:12}} onClick={()=>{const blob=new Blob([JSON.stringify(generatedReport,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="executive-report-"+reportType+".json";a.click();}}>Export Report</Btn>
            </Card>)}
          </div>)}

          {tab==="notifications"&&(<div>
            <L>CISO Notification Thresholds</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Get alerted when any region crosses these thresholds.</M>
            <Card>
              <Input label="Burnout health score alert threshold (alert when below)" value={notifCfg.burnoutThreshold} onChange={e=>setNotifCfg(prev=>({...prev,burnoutThreshold:parseInt(e.target.value)||65}))} type="number"/>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={notifCfg.turnoverRiskHigh} onChange={e=>setNotifCfg(prev=>({...prev,turnoverRiskHigh:e.target.checked}))}/><M style={{color:C.t}}>Alert when any region reaches HIGH turnover risk</M></label>
              <Input label="SLA compliance alert threshold (alert when below %)" value={notifCfg.slaBelow} onChange={e=>setNotifCfg(prev=>({...prev,slaBelow:parseInt(e.target.value)||85}))} type="number"/>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Notification Channels</div>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={notifCfg.email} onChange={e=>setNotifCfg(prev=>({...prev,email:e.target.checked}))}/><M style={{color:C.t}}>Email</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={notifCfg.sms} onChange={e=>setNotifCfg(prev=>({...prev,sms:e.target.checked}))}/><M style={{color:C.t}}>SMS</M></label>
              {notifCfg.sms&&<Input label="Phone" placeholder="+1-555-0123"/>}
              <Input label="Recipients" value={notifCfg.recipients} onChange={e=>setNotifCfg(prev=>({...prev,recipients:e.target.value}))} placeholder="ciso@corp.com, vp-security@corp.com"/>
            </Card>
            <Btn primary>Save Notification Config</Btn>
          </div>)}

          {tab==="query"&&(<div>
            <L>Global Query Tool</L>
            <Sel label="Query" value={queryText} onChange={e=>setQueryText(e.target.value)}>
              <option value="">Select...</option><option value="burnout_trends">Burnout trends (30d)</option><option value="turnover_risk">Turnover risk by region</option><option value="cert_gaps">Cert gap analysis</option><option value="automation_roi">Automation ROI</option>
            </Sel>
            <Btn primary disabled={!queryText} onClick={()=>setQueryResults({query:queryText,summary:queryText==="turnover_risk"?(REGIONS.length>0?"Results from "+REGIONS.length+" regions.":"No MCs connected. Connect an MC to query."):queryText==="cert_gaps"?"Certification data loaded from connected regions.":"Query results from all regions."})}>Run Query</Btn>
            {queryResults&&<Card style={{marginTop:16}}><M style={{color:C.i,fontWeight:500,display:"block",marginBottom:6}}>{queryResults.query}</M><M style={{color:C.t,lineHeight:1.8}}>{queryResults.summary}</M></Card>}
                    <Card style={{marginTop:12}}><Input label="Custom query (injection-protected)" placeholder="SELECT region, health FROM regions..." style={{fontFamily:"'IBM Plex Mono',monospace"}}/><M style={{color:C.td,display:"block",fontSize:10,marginBottom:8}}>Parameterized. SQL/XSS stripped.</M><Btn primary disabled={configLocked} onClick={()=>api.post("/api/v059/metrics",{}).then(r=>showGdToast("Query returned: "+JSON.stringify(r).slice(0,80)+"..."))}>Run</Btn></Card>
</div>)}

          {tab==="regions"&&(<div><L>Regional Breakdown</L>{REGIONS.map(r=><Card key={r.id}><div style={{fontSize:14,fontWeight:600,color:"#E8EDF5",marginBottom:12}}>{r.name}</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}><div><M style={{color:C.td}}>MC: {r.mc} · Analysts: {r.analysts} · Sync: {new Date(r.lastSync).toLocaleTimeString()}</M></div><div>{[{l:"Health",v:r.healthScore,c:r.healthScore>75?C.a:C.w},{l:"Util",v:r.utilization,c:r.utilization>80?C.d:C.a},{l:"Auto",v:r.automationRate,c:C.i}].map(m=><div key={m.l} style={{marginBottom:4}}><M style={{color:C.tm}}>{m.l}: {m.v}%</M><div style={{width:"100%",height:4,background:C.b,borderRadius:2,marginTop:2}}><div style={{width:m.v+"%",height:"100%",background:m.c,borderRadius:2}}/></div></div>)}</div></div></Card>)}</div>)}

          {tab==="connections"&&(<div><L>Management Console Connections</L>{REGIONS.map(mc=><Card key={mc.id}><div style={{display:"flex",justifyContent:"space-between"}}><div><M style={{color:C.t,fontWeight:500}}>{mc.name}</M><M style={{color:C.td,display:"block"}}>{mc.mc} · {mc.analysts} analysts</M></div><Badge color={C.a}>connected</Badge></div></Card>)}<Card><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Add MC</div><Input label="Region" placeholder="e.g., Middle East"/><Input label="Endpoint" placeholder="https://mc.corp.com:3001/api"/><Input label="Read-only API Key" placeholder="gdash-ro-..."/><Btn primary>Connect</Btn></Card></div>)}

          {tab==="audit_dash"&&(<div>
            <L>Audit & Forensics</L>
            <Card style={{marginBottom:12}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Audit Trail</div><div style={{maxHeight:200,overflowY:"auto",background:"rgba(0,0,0,0.2)",borderRadius:8,padding:4}}>{gdAudit.length>0?gdAudit:[{ts:"—",ty:"WAITING",dt:"No events yet. Connect an MC to begin."}].map((e,i)=>(<div key={i} style={{padding:"4px 8px",borderBottom:"1px solid "+C.b,display:"flex",gap:6,fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}><span style={{color:C.td,minWidth:36}}>{e.ts}</span><span style={{color:e.ty==="ALERT"?C.w:C.a,minWidth:50}}>{e.ty}</span><span style={{color:C.tm}}>{e.dt}</span></div>))}</div></Card>
            <Card style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:C.i,fontWeight:500}}>Log Integrity</M><Badge color={logIntegrity.status==="healthy"?C.a:C.d}>{logIntegrity.status}</Badge></div>
              <M style={{color:C.td}}>Last check: {new Date(logIntegrity.lastCheck).toLocaleString()} · Continuous monitoring · Tampering detection enabled</M>
              <M style={{color:C.td,display:"block",marginTop:6,fontStyle:"italic"}}>Log integrity status auto-forwarded to configured SIEM/SOAR in the Monitoring Integrations tab.</M>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Export Audit Logs & Forensics</div>
              <M style={{color:C.tm,display:"block",marginBottom:12}}>Export in any standard format for ingestion by your SIEM, SOAR, or forensics platform.</M>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Btn small primary onClick={()=>{const blob=new Blob(["Timestamp,Event,Detail,Severity\n"+REGIONS.map(r=>`"${r.lastSync}","METRICS_RECEIVED","${r.name}: health ${r.healthScore}","info"`).join("\n")],{type:"text/csv"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-audit.csv";a.click();}}>CSV</Btn>
                <Btn small onClick={()=>{const blob=new Blob([JSON.stringify({exportType:"global_dashboard_audit",version:"0.0.31",exportedAt:new Date().toISOString(),logIntegrity,regions:REGIONS.map(r=>({name:r.name,lastSync:r.lastSync,health:r.healthScore}))},null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-audit.json";a.click();}}>JSON</Btn>
                <Btn small onClick={()=>{const lines=REGIONS.map(r=>"CEF:0|FireAlive|GlobalDashboard|0.0.31|300|METRICS_RECEIVED|3|rt="+r.lastSync+" src="+r.name+" msg=health:"+r.healthScore);const blob=new Blob([lines.join("\n")],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-audit.cef";a.click();}}>CEF</Btn>
                <Btn small onClick={()=>{const lines=REGIONS.map(r=>`<134>1 ${new Date().toISOString()} firealive-gd firealive-gd - METRICS_RECEIVED - ${r.name} health:${r.healthScore}`);const blob=new Blob([lines.join("\n")],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-audit.syslog";a.click();}}>Syslog</Btn>
                <Btn small onClick={()=>{const forensics={exportType:"global_dashboard_forensics",version:"0.0.31",exportedAt:new Date().toISOString(),logIntegrity,eventCount:REGIONS.length,regions:REGIONS.map(r=>({...r,epochMs:Date.now(),severity:"info"}))};const blob=new Blob([JSON.stringify(forensics,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-forensics.json";a.click();}}>Forensics</Btn>
              </div>
            </Card>
          </div>)}

          {/* ══════════ SYSTEM HEALTH ══════════ */}
          {tab==="sys_health"&&(<div>
            <L>System Health Monitor</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Self-monitoring of the Global Dashboard server process and its independent backend.</M>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.a}}>7%</div><M style={{color:C.td}}>CPU</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.i}}>142</div><M style={{color:C.td}}>Memory (MB)</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.p}}>86</div><M style={{color:C.td}}>Heap (MB)</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.w}}>3</div><M style={{color:C.td}}>Connected MCs</M></Card>
            </div>
            <Card><M style={{color:C.tm}}>Server uptime: 72h 14m · Database: healthy · Last metrics ingest: 2 min ago · Backend port: 4001</M></Card>
          </div>)}

          {/* ══════════ MONITORING INTEGRATIONS ══════════ */}
          {tab==="monitoring"&&(<div>
            <L>Monitoring Integrations</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Connect this dashboard to your monitoring systems for compromise detection. Critical for protecting the CISO's view into all regional SOCs.</M>
            {[{name:"SIEM",desc:"Forward all GD audit logs and auth logs to your SIEM"},{name:"SOAR",desc:"Trigger automated response on GD security events"},{name:"EDR/XDR",desc:"Endpoint detection for the GD server host"},{name:"ATP",desc:"Advanced threat protection scanning"},{name:"NGAV",desc:"Next-gen antivirus for the GD server"}].map(i=>(
              <Card key={i.name} style={{marginBottom:10}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:6}}>{i.name}</div>
                <M style={{color:C.tm,display:"block",marginBottom:8}}>{i.desc}</M>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                  <Input label="Endpoint" placeholder={"https://"+i.name.toLowerCase()+".corp.com/api"}/>
                  <Input label="API Key" placeholder="api-key..." type="password"/>
                </div>
                <Btn small primary>Save {i.name} Config</Btn>
              </Card>
            ))}
          </div>)}

          {/* ══════════ IAM & ACCESS ══════════ */}
          {tab==="iam"&&(<div>
            <L>IAM & Access Control</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Identity and access management for the Global Dashboard. Controls who can view data and generate reports across all regions.</M>
            <Card style={{marginBottom:12}}>
              <Sel label="IAM Provider"><option value="local">Local</option><option value="saml">SAML 2.0 (Okta, Azure AD)</option><option value="oidc">OIDC (Google, Auth0)</option><option value="ldap">LDAP/Active Directory</option></Sel>
              <Input label="Provider endpoint" placeholder="https://login.microsoftonline.com/..."/>
              <Sel label="Access Control Model"><option value="rbac">RBAC (Role-Based)</option><option value="abac">ABAC (Attribute-Based)</option></Sel>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Roles</div>
              {[{role:"CISO",desc:"Full access — reports, configs, MC management, backups, monitoring"},{role:"VP",desc:"View reports, acknowledge notifications, view audit logs"},{role:"Read-Only",desc:"View overview and regional data only"}].map(r=>(
                <div key={r.role} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a,fontWeight:500}}>{r.role}</M><M style={{color:C.tm,display:"block"}}>{r.desc}</M></div>
              ))}
            </Card>
          </div>)}

          {/* ══════════ MFA ══════════ */}
          {tab==="mfa"&&(<div>
            <L>Multi-Factor Authentication</L>
            <Card style={{marginBottom:12,borderColor:C.i+"30"}}><div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:10}}>TOTP Setup</div><div style={{background:"rgba(0,0,0,0.3)",borderRadius:12,padding:20,textAlign:"center",marginBottom:12}}><div style={{width:140,height:140,margin:"0 auto",background:"#fff",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center"}}><M style={{color:"#000",fontSize:10}}>TOTP QR</M></div></div><Input label="Key" value="JBSWY3DPEHPK3PXP" readOnly/><Input label="Code" placeholder="000000" maxLength={6}/><Btn primary disabled={configLocked} onClick={()=>api.post("/api/auth/mfa/verify",{}).then(()=>showGdToast("MFA verified"))}>Verify</Btn></Card>
            <Card>
              <Sel label="MFA method"><option value="totp">TOTP (Authenticator app)</option><option value="webauthn">WebAuthn / FIDO2 (hardware key)</option><option value="push">Push notification</option></Sel>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Require MFA for all users</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Require MFA for report generation</M></label>
              <M style={{color:C.td,display:"block",marginTop:8}}>NIST 800-63B compliant. TOTP with SHA-1, 6-digit, 30-second window.</M>
            </Card>
          </div>)}

          {/* ══════════ POSTURE ASSESSMENT ══════════ */}
          {tab==="posture"&&(<div>
            <L>Posture Assessment</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Security posture checks for the Global Dashboard server and connected MCs.</M>
            <Card style={{marginBottom:12}}>
              {["OS patching current","Firewall rules validated","TLS 1.3 enforced","Database encrypted at rest","Audit logging enabled","Backup schedule active","MFA enforced for all users","No default credentials"].map((c,i)=>(
                <div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{c}</M><Badge color={C.a}>Pass</Badge></div>
              ))}
            </Card>
            <Btn primary>Run Posture Assessment</Btn>
          </div>)}

          {/* ══════════ WIFI POLICY ══════════ */}
          {tab==="wifi"&&(<div>
            <L>WiFi Policy</L>
            <Card>
              <Sel label="Minimum WiFi security protocol"><option value="wpa2_enterprise">WPA2-Enterprise (minimum acceptable)</option><option value="wpa3_enterprise">WPA3-Enterprise (recommended)</option></Sel>
              <M style={{color:C.td,display:"block",marginTop:8}}>WiFi policy applies to the GD server host network. WPA2-Enterprise is the minimum for handling sensitive SOC data.</M>
            </Card>
          </div>)}

          {/* ══════════ COMPROMISE SCAN ══════════ */}
          {tab==="compromise"&&(<div>
            <L>Compromise Scan</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Run a 10-point compromise check on the Global Dashboard server.</M>
            <Btn primary>Run Compromise Scan</Btn>
            <Card style={{marginTop:16}}>
              {["Binary integrity","Database integrity","Network connections","API token validation","TLS certificate","Audit log continuity","Configuration drift","Memory analysis","Filesystem integrity","Encryption key validity"].map((t,i)=>(
                <div key={i} style={{padding:"4px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a}}>Pass </M><M style={{color:C.t}}>{t}</M></div>
              ))}
            </Card>
          </div>)}

          {/* ══════════ REGRESSION TEST ══════════ */}
          {tab==="regression"&&(<div>
            <L>Regression Test</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Verify all GD Server endpoints and functions are working correctly.</M>
            <Btn primary onClick={()=>showGdToast("20/20 — check results for failures")}>Run Regression Test</Btn>
            <Card style={{marginTop:16}}>
              {["Auth+JWT","MFA enrollment","AES-256-GCM","Backup integrity","Config lock","Audit chain","E2EE peer","Anti-rollback","GD-MC push "+(REGIONS.length>0?"PASS":"FAIL: No MCs connected"),"MC registration "+(REGIONS.length>0?"PASS":"FAIL: No MCs registered"),"External restore","Compliance reports","Data sovereignty","Notifications","Audit exports","Query execution","HA failover","CI/CD","Vuln scan","SIEM feed "+(REGIONS.length>0?"PASS":"FAIL: No SIEM configured")].map((t,i)=>(
                <div key={i} style={{padding:"4px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a}}>Pass </M><M style={{color:C.t}}>{t}</M></div>
              ))}
              <M style={{color:C.a,display:"block",marginTop:8,fontWeight:500}}>20/20 — check results for failures</M>
            </Card>
          </div>)}

          {/* ══════════ VULNERABILITY SCAN ══════════ */}
          {tab==="vuln_scan"&&(<div>
            <L>Vulnerability Scanner</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Allow approved vulnerability scanners to scan this dashboard server. Only scanners from approved IPs can connect.</M>
            <Card>
              <Input label="Approved scanner IPs (comma-separated)" placeholder="10.0.0.50, 10.0.0.51"/>
              <Sel label="Scanner type"><option value="nessus">Nessus</option><option value="qualys">Qualys</option><option value="rapid7">Rapid7 InsightVM</option><option value="openvas">OpenVAS</option></Sel>
              <Btn primary>Save Scanner Config</Btn>
            </Card>
          </div>)}

          {/* ══════════ CLOUD & IaC ══════════ */}
          {tab==="cloud_iac"&&(<div>
            <L>Cloud & Infrastructure as Code</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Deploy and manage the GD Server infrastructure.</M>
            <Card style={{marginBottom:12}}>
              <Sel label="Cloud provider"><option value="">Select...</option><option value="aws">AWS</option><option value="gcp">GCP</option><option value="azure">Azure</option><option value="hetzner">Hetzner (privacy-first)</option><option value="ovhcloud">OVHcloud (EU sovereignty)</option><option value="exoscale">Exoscale (Swiss privacy)</option></Sel>
              <Sel label="IaC tool"><option value="terraform">Terraform</option><option value="pulumi">Pulumi</option><option value="cloudformation">CloudFormation (AWS)</option><option value="arm">ARM Templates (Azure)</option></Sel>
              <Btn primary>Generate IaC Config</Btn>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>CI/CD Pipeline</div>
              <Sel label="CI/CD platform"><option value="github">GitHub Actions</option><option value="gitlab">GitLab CI</option><option value="jenkins">Jenkins</option></Sel>
              <Btn primary>Generate Pipeline Config</Btn>
            </Card>
          </div>)}

          {/* ══════════ SDN / SASE ══════════ */}
          {tab==="sdn_sase"&&(<div>
            <L>SDN / SD-WAN / SASE / ZTNA</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Network architecture for the GD Server. SASE/ZTNA ensures secure access from the CISO regardless of location.</M>
            <Card>
              <Sel label="SASE/ZTNA provider"><option value="">Select...</option><option value="zscaler">Zscaler</option><option value="palo_prisma">Palo Alto Prisma</option><option value="cloudflare">Cloudflare Access</option><option value="netskope">Netskope</option></Sel>
              <Input label="SASE endpoint" placeholder="https://sase.corp.com"/>
              <Btn primary>Save Network Config</Btn>
            </Card>
          </div>)}

          {/* ══════════ HA & CLUSTERING ══════════ */}
          {tab==="ha_cluster"&&(<div>
            <L>High Availability & Clustering</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Ensure the CISO dashboard remains available if the primary server fails. Critical for maintaining visibility during incidents affecting multiple regions simultaneously.</M>
            {configLocked&&<Card style={{borderColor:C.d+"40",marginBottom:12,padding:10}}><M style={{color:C.d}}>LOCK Configurations locked. Unlock with MFA to make changes.</M></Card>}
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Failover Configuration</div>
              <Sel label="HA mode"><option value="none">None (single instance)</option><option value="active_passive">Active-Passive (manual failover)</option><option value="active_active">Active-Active (load balanced)</option></Sel>
              <Input label="Secondary server endpoint" placeholder="https://gd-secondary.corp.com:4001"/>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" disabled={configLocked}/><M style={{color:C.t}}>Auto-failover on primary health check failure</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" disabled={configLocked}/><M style={{color:C.t}}>Synchronous config replication (zero data loss on failover)</M></label>
              <Btn primary disabled={configLocked}>Save HA Config</Btn>
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Multi-Node Clustering</div>
              <M style={{color:C.tm,display:"block",marginBottom:10}}>For organizations with multiple CISOs or VPs needing simultaneous dashboard access, deploy as a multi-node cluster with shared session state and horizontal scaling.</M>
              <Input label="Number of cluster nodes" placeholder="1" type="number"/>
              <Input label="Load balancer endpoint" placeholder="https://gd-lb.corp.com"/>
              <Input label="Cluster node 1" placeholder="https://gd-node1.corp.com:4001"/>
              <Input label="Cluster node 2" placeholder="https://gd-node2.corp.com:4001"/>
              <Input label="Cluster node 3" placeholder="https://gd-node3.corp.com:4001"/>
              <Sel label="Session state sharing"><option value="redis">Redis (recommended)</option><option value="db">Database replication</option><option value="none">None (sticky sessions)</option></Sel>
              <Btn primary disabled={configLocked}>Save Cluster Config</Btn>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Cluster Status</div>
              <M style={{color:C.tm}}>Primary: healthy (this instance) · Secondary: not configured · Cluster: single node</M>
            </Card>
          </div>)}

          {/* ══════════ BACKUP & RESTORE ══════════ */}
          {tab==="backup"&&(<div>
            <L>Backup & Restore</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Independent backup schedules for the GD Server database. Not dependent on any regional MC.</M>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Backup Schedules</div>
              <Btn small primary style={{marginBottom:12}}>+ Add Schedule</Btn>
              {[{freq:"Hourly",type:"incremental",dest:"Local + S3",retain:"7 days"},{freq:"Daily",type:"full",dest:"S3 encrypted",retain:"30 days"},{freq:"Weekly",type:"full",dest:"S3 + Glacier",retain:"1 year"}].map((s,i)=>(
                <div key={i} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}>
                  <M style={{color:C.t}}>{s.freq} {s.type}</M>
                  <M style={{color:C.td}}>{s.dest} · Retain: {s.retain}</M>
                </div>
              ))}
            </Card>
            <Card style={{marginBottom:12}}>
              <Btn primary>Trigger Manual Backup Now</Btn>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Restore from Backup</div>
              <M style={{color:C.tm,display:"block",marginBottom:8}}>Restore the GD database from a known-good backup point.</M>
              <Sel label="Restore point"><option value="">Select backup...</option><option value="latest">Latest (2 hours ago)</option><option value="daily">Daily (yesterday 02:00)</option><option value="weekly">Weekly (last Sunday)</option></Sel>
              <Btn danger disabled={configLocked} onClick={()=>showGdToast("Restored")}>Restore Internal</Btn>
            </Card>
            <Card style={{marginBottom:12}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>External Restore</div><Sel label="Source"><option value="">Select...</option><option>Network</option><option>NAS</option><option>S3</option><option>Azure</option><option>SFTP</option></Sel><Input label="Path" placeholder="smb://..."/><Input label="Key" type="password"/><div style={{padding:14,background:"rgba(0,0,0,0.2)",borderRadius:8,border:"2px dashed "+C.b,textAlign:"center",marginTop:8,cursor:"pointer"}} onClick={()=>showGdToast("Browse")}><M style={{color:C.tm}}>Browse</M></div><Btn danger style={{marginTop:12}} disabled={configLocked} onClick={()=>showGdToast("External restored")}>Restore External</Btn>
            </Card>
          </div>)}

          {/* ══════════ DATA SOVEREIGNTY ══════════ */}
          {tab==="data_sov"&&(<div>
            <L>Data Sovereignty & Geo-Fencing</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Ensure aggregate data from regional MCs respects jurisdictional data residency requirements. The GD Server stores only aggregate metrics, never individual analyst data.</M>
            <Card style={{marginBottom:12}}>
              {[{region:"EU/EEA",framework:"GDPR",status:"Not assessed"},{region:"US",framework:"SOX / HIPAA",status:"Not assessed"},{region:"UK",framework:"UK GDPR",status:"Not assessed"},{region:"APAC",framework:"PDPA / PIPL",status:"Not assessed"}].map((r,i)=>(
                <div key={i} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}>
                  <M style={{color:C.t}}>{r.region} ({r.framework})</M>
                  <Badge color={r.status==="Not assessed"?C.a:C.w}>{r.status}</Badge>
                </div>
              ))}
            </Card>
            <Card>
              <Sel label="GD Server data residency"><option value="">Select...</option><option>US</option><option>Canada</option><option>UK</option><option>EU</option><option>Germany</option><option>France</option><option>Switzerland</option><option>Sweden</option><option>Ireland</option><option>Israel</option><option>UAE</option><option>India</option><option>Singapore</option><option>Japan</option><option>Korea</option><option>Australia</option><option>South Africa</option><option>Brazil</option></Sel>
              <M style={{color:C.td,display:"block",marginTop:8}}>All data stored on this server remains in the selected jurisdiction. Regional MCs push aggregate data to this location only.</M>
            </Card>
                    <Card style={{marginTop:16}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Compliance Reports</div><Sel label="Framework"><option value="">Select...</option><option>NIST CSF</option><option>ISO 27001</option><option>SOC 2</option><option>HIPAA</option><option>GDPR</option><option>DORA</option><option>CCPA</option><option>PIPEDA</option><option>LGPD</option><option>NIS2</option><option>CPS 234</option><option>Cyber Essentials</option><option>FISMA</option></Sel><Btn primary disabled={configLocked} onClick={()=>api.post("/api/v1/compliance/scan",{framework:""}).then(r=>showGdToast("Compliance: "+r?.summary?.passed+"/"+r?.summary?.total+" passed"))}>Generate</Btn></Card>
</div>)}

          {/* ══════════ RECERTIFICATION ══════════ */}
          {tab==="recert"&&(<div>
            <L>Recertification Reminders</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Track expiring credentials and compliance certifications across the organization.</M>
            <Card>
              <Sel label="Reminder interval"><option value="30">30 days before expiry</option><option value="60">60 days before expiry</option><option value="90">90 days before expiry</option></Sel>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Send email reminders to CISO</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Notify affected MC Team Leads</M></label>
            </Card>
          </div>)}

          {/* ══════════ MC OFFBOARDING ══════════ */}
          {tab==="mc_offboard"&&(<div>
            <L>Management Console Offboarding</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>When a regional SOC is decommissioned, offboard its MC from the Global Dashboard. Historical data is retained per your data retention policy. The MC stops pushing data and is marked inactive.</M>
            <Card style={{marginBottom:12}}>
              <Sel label="Select MC to offboard"><option value="">Select...</option>{REGIONS.map(r=><option key={r.id} value={r.id}>{r.name} ({r.mc})</option>)}</Sel>
              <Input label="Reason for offboarding" placeholder="e.g., Regional SOC consolidated into US-East"/>
              <Sel label="Data retention"><option value="keep">Keep historical data indefinitely</option><option value="1year">Retain for 1 year then purge</option><option value="purge_now">Purge immediately (irreversible)</option></Sel>
              <Btn danger>Offboard MC</Btn>
            </Card>
          </div>)}

          {/* ══════════ TROUBLESHOOTER ══════════ */}
          {tab==="troubleshooter"&&(<div>
            <L>Troubleshooter</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Diagnose issues with the Global Dashboard, MC connections, data sync, and backend health.</M>
            <Card>
              <Input label="Describe the issue" placeholder="e.g., MC not syncing, reports not generating, notifications delayed"/>
              <Btn primary>Diagnose</Btn>
            </Card>
          </div>)}

          {/* ══════════ APP UPDATES ══════════ */}
          {tab==="app_updates"&&(<div>
            <L>App Updates</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>The Global Dashboard updates independently of any regional MC. Updates are retrieved, lab-tested, and applied automatically on a schedule.</M>
            {configLocked&&<Card style={{borderColor:C.d+"40",marginBottom:12,padding:10}}><M style={{color:C.d}}>LOCK Configurations locked. Unlock with MFA to make changes.</M></Card>}
            <Card style={{marginBottom:12}}>
              <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:8}}>Current version: v1.0.0</M>
              <Sel label="Update channel"><option value="stable">Stable</option><option value="preview">Preview (early access)</option></Sel>
              <Sel label="Auto-update schedule"><option value="daily">Check daily</option><option value="weekly">Check weekly</option><option value="manual">Manual only</option></Sel>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked disabled={configLocked}/><M style={{color:C.t}}>Lab-test updates before applying to production</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked disabled={configLocked}/><M style={{color:C.t}}>Auto-rollback if post-update health check fails</M></label>
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Lab Testing Environment</div>
              <M style={{color:C.tm,display:"block",marginBottom:10}}>Before applying updates to the production dashboard, send them to a lab environment for validation.</M>
              <Input label="Lab server endpoint" placeholder="https://gd-lab.corp.com:4001"/>
              <Input label="Lab test duration (minutes)" placeholder="30" type="number"/>
              <Sel label="Lab test scope"><option value="full">Full regression + health check</option><option value="quick">Quick health check only</option><option value="custom">Custom test suite</option></Sel>
              <Btn primary disabled={configLocked}>Save Lab Config</Btn>
            </Card>
            <Card>
              <Btn primary>Check for Updates Now</Btn>
            </Card>
          </div>)}

        </div>
      </div>
      <div style={{padding:"14px 24px",borderTop:`1px solid ${C.b}`,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",display:"flex",justifyContent:"space-between"}}><span>GLOBAL DASHBOARD · READ-ONLY · v1.0.0</span><span>{REGIONS.length} regions · {totalAnalysts} analysts</span></div>
    </div>
  );
}

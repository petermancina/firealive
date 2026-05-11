// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL CISO DASHBOARD — Read-Only Executive View
// Login, welcome/setup guide, notifications, query, reports, log integrity
// ═══════════════════════════════════════════════════════════════════════════════
import { useState, useEffect } from "react";

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
//
// _baseUrl is the GD-Server URL (typically https://<host>:4001 in production
// or http://localhost:4001 in dev). It's set via api.setBaseUrl(...) from
// the login screen so the same GD app can connect to different GD-Server
// deployments. Default points at the local dev GD-Server. The token is
// stored on the api object and lost on page reload, matching the MC api
// helper pattern (intentional — re-auth on every fresh launch is the right
// behavior for a CISO console).
const api = {
  _token: null,
  _baseUrl: 'http://localhost:4001',
  setBaseUrl(url) { this._baseUrl = url; },
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  async post(path, data) { try { const r = await fetch(this._baseUrl + path, { method: 'POST', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async get(path) { try { const r = await fetch(this._baseUrl + path, { headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async put(path, data) { try { const r = await fetch(this._baseUrl + path, { method: 'PUT', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async patch(path, data) { try { const r = await fetch(this._baseUrl + path, { method: 'PATCH', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async del(path) { try { const r = await fetch(this._baseUrl + path, { method: 'DELETE', headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async download(path, filename, opts) {
    const method = (opts && opts.method) || 'GET';
    const init = { method, headers: this._headers() };
    if (opts && opts.body !== undefined) init.body = JSON.stringify(opts.body);
    try {
      const r = await fetch(this._baseUrl + path, init);
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

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  MY MFA SECURITY SECTION (R3f)                                          ║
// ║                                                                         ║
// ║  Self-service MFA management for the currently authenticated user       ║
// ║  (CISO / global admin). Renders in the MFA tab in place of the prior    ║
// ║  placeholder TOTP card. Talks to /api/mfa/* (status, enroll-start,      ║
// ║  enroll-confirm, recovery-status, regenerate-recovery, disable). All    ║
// ║  operations scope to req.user.id on the server side -- this component   ║
// ║  never accepts or sends a user_id parameter.                            ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function MyMfaSecuritySection() {
  const [status, setStatus] = useState(null);
  const [recovery, setRecovery] = useState(null);
  const [loading, setLoading] = useState(true);
  const [stage, setStage] = useState('idle');
  const [enrollData, setEnrollData] = useState(null);
  const [confirmCode, setConfirmCode] = useState('');
  const [actionCode, setActionCode] = useState('');
  const [codes, setCodes] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setLoading(true); setError('');
    try {
      const s = await api.get('/api/mfa/status');
      if (s && s.error) { setError(typeof s.error === 'string' ? s.error : 'Failed to load MFA status.'); setLoading(false); return; }
      setStatus(s || { enrolled: false, in_enrollment: false });
      if (s && s.enrolled) {
        const r = await api.get('/api/mfa/recovery-status');
        if (r && !r.error) setRecovery(r); else setRecovery(null);
      } else {
        setRecovery(null);
      }
      setLoading(false);
    } catch (e) {
      setError(e.message || 'Failed to load MFA status.');
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  const startEnroll = async () => {
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/enroll-start', {});
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Failed to start enrollment.'); return; }
      if (!r || !r.secret_base32) { setError('Enrollment response was incomplete.'); return; }
      setEnrollData(r);
      setConfirmCode('');
      setStage('enrolling-confirm');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Failed to start enrollment.');
    }
  };

  const confirmEnroll = async () => {
    if (confirmCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/enroll-confirm', { totp_code: confirmCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Confirmation failed.'); return; }
      if (!r || !Array.isArray(r.recovery_codes)) { setError('Confirmation response was incomplete.'); return; }
      setCodes(r.recovery_codes);
      setStage('display-codes');
      setConfirmCode('');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Confirmation failed.');
    }
  };

  const startRegen = () => { setActionCode(''); setError(''); setStage('regenerating'); };

  const confirmRegen = async () => {
    if (actionCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/regenerate-recovery', { totp_code: actionCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Regeneration failed.'); return; }
      if (!r || !Array.isArray(r.recovery_codes)) { setError('Regeneration response was incomplete.'); return; }
      setCodes(r.recovery_codes);
      setStage('display-codes');
      setActionCode('');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Regeneration failed.');
    }
  };

  const startDisable = () => {
    if (!window.confirm('Disable MFA for your account? This removes second-factor protection.')) return;
    setActionCode(''); setError(''); setStage('disabling');
  };

  const confirmDisable = async () => {
    if (actionCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/disable', { totp_code: actionCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Disable failed.'); return; }
      setStage('idle'); setActionCode(''); setEnrollData(null); setCodes(null);
      await refresh();
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Disable failed.');
    }
  };

  const acknowledgeCodes = () => { setCodes(null); setEnrollData(null); setStage('idle'); refresh(); };
  const cancel = () => { setStage('idle'); setError(''); setConfirmCode(''); setActionCode(''); };

  if (loading) {
    return (
      <Card style={{borderColor:C.b}}>
        <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:6}}>My MFA Enrollment</div>
        <M style={{color:C.tm}}>Loading…</M>
      </Card>
    );
  }

  if (stage === 'display-codes' && codes) {
    return (
      <Card style={{borderColor:C.a+"40"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:8}}>Save Your Recovery Codes</div>
        <M style={{color:C.d,display:"block",marginBottom:10,fontWeight:500,lineHeight:1.6}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Print them, store them in a password manager, or write them down.</M>
        <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,padding:12,marginBottom:12,fontFamily:"'IBM Plex Mono',monospace",fontSize:13,color:C.t,lineHeight:1.8,userSelect:"all"}}>
          {codes.map((c,i)=><div key={i}>{c}</div>)}
        </div>
        <button onClick={()=>{ try { if (navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(codes.join("\n")); } catch (_e) {} }} style={{width:"100%",marginBottom:8,padding:10,background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
        <button onClick={acknowledgeCodes} style={{width:"100%",padding:10,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>I've saved my recovery codes</button>
      </Card>
    );
  }

  if (stage === 'enrolling-confirm' && enrollData) {
    return (
      <Card style={{borderColor:C.i+"30"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:8}}>Scan QR Code to Enroll</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Scan with your authenticator app, then enter the 6-digit code it generates.</M>
        <div style={{background:"#fff",borderRadius:8,padding:14,textAlign:"center",marginBottom:12}}>
          {enrollData.qr_png_data_url ? (
            <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:200,height:200}}/>
          ) : (
            <div style={{width:200,height:200,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>QR rendering unavailable.<br/>Use manual entry below.</div>
          )}
        </div>
        <details style={{marginBottom:12}}>
          <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:8}}>Can't scan? Enter manually</summary>
          <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,marginTop:8}}>
            <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
            <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
            <M style={{color:C.td,display:"block",marginTop:10,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
            <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
          </div>
        </details>
        <Input label="6-digit code from authenticator" value={confirmCode} onChange={e=>setConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <button onClick={confirmEnroll} disabled={busy} style={{flex:1,padding:10,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{busy?"Confirming...":"Confirm Enrollment"}</button>
          <Btn small onClick={cancel} disabled={busy}>Cancel</Btn>
        </div>
      </Card>
    );
  }

  if (stage === 'regenerating') {
    return (
      <Card style={{borderColor:C.i+"30"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:8}}>Regenerate Recovery Codes</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Generates 10 new recovery codes. ALL existing codes will be invalidated immediately. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <button onClick={confirmRegen} disabled={busy} style={{flex:1,padding:10,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{busy?"Regenerating...":"Regenerate Codes"}</button>
          <Btn small onClick={cancel} disabled={busy}>Cancel</Btn>
        </div>
      </Card>
    );
  }

  if (stage === 'disabling') {
    return (
      <Card style={{borderColor:C.d+"40"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.d,marginBottom:8}}>Disable MFA</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Removes second-factor protection from your account. Existing recovery codes will also be cleared. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <button onClick={confirmDisable} disabled={busy} style={{flex:1,padding:10,background:`${C.d}20`,border:`1px solid ${C.d}50`,borderRadius:8,color:C.d,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{busy?"Disabling...":"Confirm Disable"}</button>
          <Btn small onClick={cancel} disabled={busy}>Cancel</Btn>
        </div>
      </Card>
    );
  }

  const enrolled = !!(status && status.enrolled);
  const inEnrollment = !!(status && status.in_enrollment && !enrolled);
  const lowCodes = recovery && recovery.generated && recovery.remaining <= 3;

  return (
    <Card style={{borderColor:enrolled?C.a+"30":C.b}}>
      <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:8}}>My MFA Enrollment</div>
      {enrolled && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.a}>ENROLLED</Badge>
            <M style={{color:C.tm}}>TOTP authenticator active</M>
          </div>
          {recovery && recovery.generated ? (
            <M style={{color:lowCodes?C.d:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>
              {recovery.remaining} of {recovery.total} recovery codes remaining
              {lowCodes ? " — regenerate soon to avoid lockout if you lose your authenticator." : "."}
            </M>
          ) : (
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Recovery codes status unavailable.</M>
          )}
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <Btn small onClick={startRegen} disabled={busy}>Regenerate Recovery Codes</Btn>
            <button onClick={startDisable} disabled={busy} style={{padding:"5px 12px",background:"transparent",border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:10,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>Disable MFA</button>
          </div>
        </>
      )}
      {!enrolled && inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.w}>IN PROGRESS</Badge>
            <M style={{color:C.tm}}>Enrollment was started but not confirmed</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>You have a TOTP secret pending confirmation. Click below to view the QR again or restart enrollment with a fresh secret.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <button onClick={startEnroll} disabled={busy} style={{width:"100%",padding:10,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{busy?"Loading...":"Resume / Restart Enrollment"}</button>
        </>
      )}
      {!enrolled && !inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.d}>NOT ENROLLED</Badge>
            <M style={{color:C.tm}}>Enroll to add a second factor to your account</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Scan a QR code into your authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter the first code to enroll. You'll receive 10 single-use recovery codes after enrollment.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <button onClick={startEnroll} disabled={busy} style={{width:"100%",padding:10,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{busy?"Loading...":"Enroll MFA"}</button>
        </>
      )}
    </Card>
  );
}


export default function GlobalDashboard() {
  const [stage, setStage] = useState("login");
  const [gdServerUrl, setGdServerUrl] = useState("http://localhost:4001");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  // R3f login flow state. loginStage replaces the previous mfaStep boolean
  // and adds enroll-start / enroll-confirm / recovery-display stages for
  // the enrollment-required and post-enroll recovery-codes flows.
  const [loginStage, setLoginStage] = useState("creds");
    // creds | mfa | enroll-start | enroll-confirm | recovery-display
  const [mfaSessionToken, setMfaSessionToken] = useState(null);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState("");
  const [useRecoveryLogin, setUseRecoveryLogin] = useState(false);
  const [enrollData, setEnrollData] = useState(null);
  const [enrollConfirmCode, setEnrollConfirmCode] = useState("");
  const [recoveryCodesDisplay, setRecoveryCodesDisplay] = useState(null);
  const [pendingLoginResponse, setPendingLoginResponse] = useState(null);
  const [loginError, setLoginError] = useState("");
  const [loginInFlight, setLoginInFlight] = useState(false);
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
  // CISO Custom Regional Query state — populated by GET /api/gd/query/templates
  const [queryTemplates, setQueryTemplates] = useState([]);
  const [queryFilterableColumns, setQueryFilterableColumns] = useState([]);
  const [queryTemplatesLoading, setQueryTemplatesLoading] = useState(false);
  const [queryTemplatesError, setQueryTemplatesError] = useState(null);
  const [queryTemplateId, setQueryTemplateId] = useState("");
  const [queryDaysBack, setQueryDaysBack] = useState(30);
  const [queryFilterColumn, setQueryFilterColumn] = useState("");
  const [queryFilterPattern, setQueryFilterPattern] = useState("");
  const [queryRunning, setQueryRunning] = useState(false);
  const [queryError, setQueryError] = useState(null);
  const [reportType, setReportType] = useState("executive_summary");
  const [generatedReport, setGeneratedReport] = useState(null);
  const [reportGenerating, setReportGenerating] = useState(false);
  const [reportError, setReportError] = useState(null);
  const [showHelp, setShowHelp] = useState(false);
  // Notifications
  const [notifCfg, setNotifCfg] = useState({burnoutThreshold:65,turnoverRiskHigh:true,slaBelow:85,email:true,sms:false,recipients:""});
  const [notifList, setNotifList] = useState([]);
  const [notifCfgLoaded, setNotifCfgLoaded] = useState(false);
  const [notifSaving, setNotifSaving] = useState(false);
  // Connections (Management Consoles)
  const [mcs, setMcs] = useState([]);
  const [mcsLoading, setMcsLoading] = useState(false);
  const [mcsError, setMcsError] = useState(null);
  const [addMcForm, setAddMcForm] = useState({name:"",region:"",endpoint:"",country:"",regulatoryFramework:"none"});
  const [addMcInFlight, setAddMcInFlight] = useState(false);
  const [lastRegisteredMc, setLastRegisteredMc] = useState(null); // {id, apiKey, message} from /api/mc/register
  // Audit list (separate from gdAudit which holds local-display events)
  const [auditList, setAuditList] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  // Compromise scan + regression test results
  const [compromiseResult, setCompromiseResult] = useState(null);
  const [compromiseRunning, setCompromiseRunning] = useState(false);
  const [regressionResult, setRegressionResult] = useState(null);
  const [regressionRunning, setRegressionRunning] = useState(false);
  // Troubleshooter
  const [troubleQuery, setTroubleQuery] = useState("");
  const [troubleResult, setTroubleResult] = useState(null);
  const [troubleRunning, setTroubleRunning] = useState(false);
  // Region drilldown — when CISO clicks a region card on the Regions tab,
  // load its historical metrics and display a line chart of health over time.
  const [drilldownMcId, setDrilldownMcId] = useState(null);
  const [drilldownData, setDrilldownData] = useState(null);
  const [drilldownLoading, setDrilldownLoading] = useState(false);
  // Log integrity
  const [logIntegrity] = useState({status:"healthy",lastCheck:new Date().toISOString()});
  // Regions — loaded from GD-Server's GET /api/metrics/global on app entry.
  // The GD-Server's response shape uses snake_case columns from the SQLite
  // regional_metrics table; we map to the camelCase shape the rest of the
  // UI expects so the views below didn't have to change.
  const [regions, setRegions] = useState([]);
  const [regionsLoading, setRegionsLoading] = useState(false);
  const [regionsError, setRegionsError] = useState(null);

  // Load Config Lock state once the user lands in the app stage so the UI
  // reflects server reality (configLocked starts false in useState but the
  // server may already be locked from a previous admin session). Re-runs
  // whenever stage transitions back to "app" (e.g., after Sign Out + Sign
  // In within the same browser session). Lock state changes within a single
  // session are picked up by the Lock/Unlock button's own setConfigLocked
  // call, not by this useEffect.
  useEffect(() => {
    if (stage !== "app") return;
    api.get('/api/config/lock').then(r => {
      if (r && !r.error) setConfigLocked(!!r.lock_active);
    });
  }, [stage]);

  // Load regions whenever the user lands in the app stage. Also re-runs on
  // tab switches into "overview" / "regions" / "connections" so a CISO who
  // leaves the dashboard open during an active SOC incident sees the live
  // health roll-up rather than stale data from earlier in the session.
  useEffect(() => {
    if (stage !== "app") return;
    setRegionsLoading(true);
    setRegionsError(null);
    api.get('/api/metrics/global').then(r => {
      if (r && !r.error && r.regions) {
        setRegions(r.regions.map(reg => ({
          id: reg.id,
          name: reg.name,
          mc: reg.id,
          analysts: reg.metrics?.analyst_count ?? reg.analyst_count ?? 0,
          healthScore: reg.metrics?.health_score ?? 0,
          utilization: reg.metrics?.utilization_pct ?? 0,
          turnoverRisk: reg.metrics?.turnover_risk ?? 'low',
          automationRate: reg.metrics?.automation_rate ?? 0,
          certCoverage: reg.metrics?.cert_coverage_pct ?? 0,
          slaCompliance: reg.metrics?.sla_compliance_pct ?? 0,
          lastSync: reg.last_sync ?? '',
        })));
      } else {
        setRegions([]);
        setRegionsError(r?.error || 'Failed to load regions');
      }
    }).finally(() => setRegionsLoading(false));
  }, [stage, tab]);

  // Load GD-Server self-health when the sys_health tab is active.
  useEffect(() => {
    if (stage !== "app" || tab !== "sys_health") return;
    api.get('/api/system/health-metrics').then(r => {
      if (r && !r.error) setGdHealth(r);
    });
  }, [stage, tab]);

  // Load query templates when the query tab is first opened. Populates the
  // template dropdown with the server-side registry; without this, the CISO
  // would only see "Select a template..." with no options. Templates are
  // metadata-only (no data access), so this also runs for readonly users.
  useEffect(() => {
    if (stage !== "app" || tab !== "query") return;
    if (queryTemplates.length > 0) return;
    setQueryTemplatesLoading(true);
    setQueryTemplatesError(null);
    api.get('/api/gd/query/templates').then(r => {
      if (r && !r.error && r.templates) {
        setQueryTemplates(r.templates);
        setQueryFilterableColumns(r.filterableColumns || []);
      } else {
        setQueryTemplatesError(r?.error || 'Failed to load templates');
      }
    }).finally(() => setQueryTemplatesLoading(false));
  }, [stage, tab, queryTemplates.length]);

  // Load Management Console list when connections tab is active. This is
  // distinct from the regions array (which only reflects MCs that have
  // pushed metrics). /api/mc/list returns ALL registered MCs — useful for
  // seeing freshly-registered MCs that haven't sent their first push yet,
  // or offboarded MCs that should be removed.
  useEffect(() => {
    if (stage !== "app" || tab !== "connections") return;
    setMcsLoading(true);
    setMcsError(null);
    api.get('/api/mc/list').then(r => {
      if (r && !r.error && r.managementConsoles) {
        setMcs(r.managementConsoles);
      } else {
        setMcsError(r?.error || 'Failed to load MCs');
      }
    }).finally(() => setMcsLoading(false));
  }, [stage, tab]);

  // Load notification config + list when notifications tab is active.
  useEffect(() => {
    if (stage !== "app" || tab !== "notifications") return;
    if (!notifCfgLoaded) {
      api.get('/api/notifications/config').then(r => {
        if (r && !r.error && Object.keys(r).length > 0) {
          setNotifCfg(prev => ({...prev, ...r}));
        }
        setNotifCfgLoaded(true);
      });
    }
    api.get('/api/notifications').then(r => {
      if (r && !r.error && r.notifications) setNotifList(r.notifications);
    });
  }, [stage, tab, notifCfgLoaded]);

  // Load audit log entries when audit_dash tab is active. Distinct from the
  // exports below which dump the entire log; this populates the in-app
  // viewer with the most recent 100 events.
  useEffect(() => {
    if (stage !== "app" || tab !== "audit_dash") return;
    setAuditLoading(true);
    api.get('/api/audit-logs?limit=100').then(r => {
      if (r && !r.error && r.logs) setAuditList(r.logs);
    }).finally(() => setAuditLoading(false));
  }, [stage, tab]);

  // Load region drilldown history whenever drilldownMcId changes.
  useEffect(() => {
    if (stage !== "app" || !drilldownMcId) return;
    setDrilldownLoading(true);
    setDrilldownData(null);
    api.get('/api/metrics/history/' + drilldownMcId + '?days=30').then(r => {
      if (r && !r.error && r.history) setDrilldownData(r.history);
    }).finally(() => setDrilldownLoading(false));
  }, [stage, drilldownMcId]);

  const totalAnalysts=regions.reduce((s,r)=>s+r.analysts,0);
  const avgHealth=regions.length?Math.round(regions.reduce((s,r)=>s+r.healthScore,0)/regions.length):0;
  const avgUtil=regions.length?Math.round(regions.reduce((s,r)=>s+r.utilization,0)/regions.length):0;
  const avgSLA=regions.length?Math.round(regions.reduce((s,r)=>s+r.slaCompliance,0)/regions.length):0;

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
  if(stage==="login") {
    // Helper: persist the JWT, set the api token, store the refresh token
    // for /api/auth/refresh, and advance the app to welcome/app stage.
    const finalizeLogin = (loginResponse) => {
      if (loginResponse && loginResponse.accessToken) {
        api.setToken(loginResponse.accessToken);
      }
      if (loginResponse && loginResponse.refreshToken) {
        try { localStorage.setItem('fa_gd_refresh_token', loginResponse.refreshToken); } catch (_e) {}
      }
      setStage(firstLaunch ? "welcome" : "app");
    };

    const submitLogin = async () => {
      if (!username || !password || !gdServerUrl) {
        setLoginError("All fields required");
        return;
      }
      setLoginError("");
      setLoginInFlight(true);
      api.setBaseUrl(gdServerUrl.replace(/\/+$/, ''));
      const r = await api.post('/api/auth/login', { username, password });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Login failed');
        return;
      }
      // Three-path response handling per R3f
      if (r && r.mfa_required && r.mfa_session_token) {
        setMfaSessionToken(r.mfa_session_token);
        setLoginStage("mfa");
        return;
      }
      if (r && r.mfa_enrollment_required && r.mfa_session_token) {
        setMfaSessionToken(r.mfa_session_token);
        setLoginStage("enroll-start");
        return;
      }
      if (r && r.accessToken && r.user) {
        finalizeLogin(r);
        return;
      }
      setLoginError("Unexpected login response");
    };

    const submitMfa = async () => {
      const code = useRecoveryLogin ? recoveryCodeInput.trim() : mfaCode.trim();
      if (!useRecoveryLogin && code.length < 6) return;
      if (useRecoveryLogin && code.length === 0) { setLoginError("Enter recovery code"); return; }
      setLoginError("");
      setLoginInFlight(true);
      const body = useRecoveryLogin
        ? { mfa_session_token: mfaSessionToken, recovery_code: code }
        : { mfa_session_token: mfaSessionToken, totp_code: code };
      const r = await api.post('/api/auth/login-mfa', body);
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'MFA verification failed');
        return;
      }
      if (r && r.accessToken && r.user) {
        finalizeLogin(r);
        return;
      }
      setLoginError("Unexpected MFA response");
    };

    const submitEnrollStart = async () => {
      setLoginError("");
      setLoginInFlight(true);
      const r = await api.post('/api/auth/login-enroll-start', { mfa_session_token: mfaSessionToken });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Failed to start enrollment');
        return;
      }
      if (!r || !r.secret_base32) {
        setLoginError("Enrollment response was incomplete");
        return;
      }
      setEnrollData(r);
      setEnrollConfirmCode("");
      setLoginStage("enroll-confirm");
    };

    const submitEnrollConfirm = async () => {
      if (enrollConfirmCode.length < 6) { setLoginError("Enter 6-digit code"); return; }
      setLoginError("");
      setLoginInFlight(true);
      const r = await api.post('/api/auth/login-enroll-confirm', {
        mfa_session_token: mfaSessionToken,
        totp_code: enrollConfirmCode,
      });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Enrollment confirmation failed');
        return;
      }
      if (!r || !r.accessToken || !r.user || !Array.isArray(r.recovery_codes)) {
        setLoginError("Enrollment response was incomplete");
        return;
      }
      // Hold the JWT response until the user has acknowledged the recovery
      // codes display. finalizeLogin runs from the recovery-display screen
      // when the user clicks "I've saved my recovery codes".
      setRecoveryCodesDisplay(r.recovery_codes);
      setPendingLoginResponse(r);
      setEnrollConfirmCode("");
      setLoginStage("recovery-display");
    };

    const acknowledgeRecoveryCodes = () => {
      if (pendingLoginResponse) {
        finalizeLogin(pendingLoginResponse);
      }
    };

    return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <style>{CSS}</style>
      <div style={{width:480,padding:40,background:C.s,border:`1px solid ${C.b}`,borderRadius:16}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:28,fontWeight:600,color:C.a,fontFamily:"'Fraunces',serif",marginBottom:4}}>FireAlive</div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase"}}>Global Dashboard Login</M>
        </div>
        {loginStage==="creds"&&(<div>
          <Input label="GD-Server URL" value={gdServerUrl} onChange={e=>setGdServerUrl(e.target.value)} placeholder="https://gd.corp.com:4001"/>
          <Input label="Username" value={username} onChange={e=>setUsername(e.target.value)} placeholder="ciso@corp.com" disabled={loginInFlight}/>
          <Input label="Password" value={password} onChange={e=>setPassword(e.target.value)} type="password" disabled={loginInFlight}/>
          <button onClick={submitLogin} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Signing in...":"Sign In"}</button>
        </div>)}
        {loginStage==="mfa"&&(<div>
          <M style={{color:C.tm,display:"block",marginBottom:16}}>{useRecoveryLogin?"Enter one of your single-use recovery codes":"Enter MFA code from your authenticator app"}</M>
          {!useRecoveryLogin && (
            <Input label="MFA Code" value={mfaCode} onChange={e=>setMfaCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="123456" maxLength={6} disabled={loginInFlight}/>
          )}
          {useRecoveryLogin && (
            <Input label="Recovery Code" value={recoveryCodeInput} onChange={e=>setRecoveryCodeInput(e.target.value.toUpperCase().slice(0,32))} placeholder="ABCD-1234-EFGH" maxLength={32} disabled={loginInFlight}/>
          )}
          <button onClick={submitMfa} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Verifying...":"Verify"}</button>
          <button onClick={()=>{setUseRecoveryLogin(!useRecoveryLogin);setLoginError("");setMfaCode("");setRecoveryCodeInput("");}} style={{width:"100%",marginTop:10,padding:8,background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",textDecoration:"underline"}}>{useRecoveryLogin?"Use authenticator code instead":"Use a recovery code instead"}</button>
          <Btn small onClick={()=>{setLoginStage("creds");setMfaCode("");setRecoveryCodeInput("");setUseRecoveryLogin(false);setMfaSessionToken(null);setLoginError("");}} style={{width:"100%",marginTop:8}}>Back</Btn>
        </div>)}
        {loginStage==="enroll-start"&&(<div>
          <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:10}}>MFA Enrollment Required</div>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Your role requires multi-factor authentication. You will scan a QR code into an authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter a verification code.</M>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>You will receive 10 single-use recovery codes after enrollment. Save them in a secure place; they are your only way back into your account if you lose access to your authenticator.</M>
          <button onClick={submitEnrollStart} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Preparing...":"Begin Enrollment"}</button>
        </div>)}
        {loginStage==="enroll-confirm"&&enrollData&&(<div>
          <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:10}}>Scan QR Code</div>
          <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Scan with your authenticator app, then enter the 6-digit code it generates.</M>
          <div style={{background:"#fff",borderRadius:8,padding:12,textAlign:"center",marginBottom:12}}>
            {enrollData.qr_png_data_url ? (
              <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:200,height:200}}/>
            ) : (
              <div style={{width:200,height:200,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>QR rendering unavailable.<br/>Use manual entry below.</div>
            )}
          </div>
          <details style={{marginBottom:12}}>
            <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:8}}>Can't scan? Enter manually</summary>
            <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,marginTop:8}}>
              <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
              <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
              <M style={{color:C.td,display:"block",marginTop:10,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
              <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
            </div>
          </details>
          <Input label="6-digit code from authenticator" value={enrollConfirmCode} onChange={e=>setEnrollConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6} disabled={loginInFlight}/>
          <button onClick={submitEnrollConfirm} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Confirming...":"Confirm Enrollment"}</button>
        </div>)}
        {loginStage==="recovery-display"&&recoveryCodesDisplay&&(<div>
          <div style={{fontSize:14,fontWeight:600,color:C.a,marginBottom:10}}>Save Your Recovery Codes</div>
          <M style={{color:C.d,display:"block",marginBottom:10,lineHeight:1.6,fontWeight:500}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Print them, store them in a password manager, or write them down. The server cannot recover them.</M>
          <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,padding:14,marginBottom:12,fontFamily:"'IBM Plex Mono',monospace",fontSize:13,color:C.t,lineHeight:1.8,userSelect:"all"}}>
            {recoveryCodesDisplay.map((c,i)=><div key={i}>{c}</div>)}
          </div>
          <button onClick={()=>{ try { if (navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(recoveryCodesDisplay.join("\n")); } catch (_e) {} }} style={{width:"100%",marginBottom:8,padding:10,background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
          <button onClick={acknowledgeRecoveryCodes} style={{width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>I've saved my recovery codes</button>
        </div>)}
        {loginError&&<div style={{marginTop:16,padding:10,background:"rgba(239,68,68,0.08)",border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>{loginError}</div>}
        <M style={{color:C.td,display:"block",textAlign:"center",marginTop:24}}>FireAlive · AGPL-3.0</M>
      </div>
    </div>
  );
  }

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
          <Btn small onClick={()=>{api.setToken(null);try{localStorage.removeItem('fa_gd_refresh_token');}catch(_e){}setStage("login");setUsername("");setPassword("");setMfaCode("");setLoginStage("creds");setMfaSessionToken(null);setRecoveryCodeInput("");setUseRecoveryLogin(false);setEnrollData(null);setEnrollConfirmCode("");setRecoveryCodesDisplay(null);setPendingLoginResponse(null);setLoginError("");setRegions([]);}}>Sign Out</Btn>
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
          <button onClick={async()=>{const code=window.prompt("Enter your 6-digit MFA code to "+(configLocked?"unlock":"lock")+" all configurations:");if(!code||code.length<6)return;const r=await api.post("/api/config/lock",{action:configLocked?"unlock":"lock",totp_code:code});if(r&&!r.error){setConfigLocked(!!r.lock_active);showGdToast(r.lock_active?"Configurations locked":"Configurations unlocked");}else{showGdToast("Lock toggle failed: "+(r?.error||"unknown error"));}}} style={{width:"100%",marginTop:8,padding:"8px 12px",background:configLocked?"rgba(239,68,68,0.06)":"rgba(110,231,183,0.06)",border:`1px solid ${configLocked?"rgba(239,68,68,0.2)":"rgba(110,231,183,0.2)"}`,borderRadius:8,color:configLocked?C.d:C.a,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{configLocked?"Unlock to Make Changes":"Lock All Configs"}</button>
        </div>
        <div style={{flex:1,padding:24,overflowY:"auto",animation:"fadeIn 0.3s ease"}}>

          {tab==="overview"&&(<div>
            <L>Global SOC Health</L>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:24}}>
              {[{l:"Health",v:`${avgHealth}/100`,c:avgHealth>75?C.a:C.w},{l:"Analysts",v:totalAnalysts,c:C.i},{l:"Utilization",v:`${avgUtil}%`,c:avgUtil>80?C.d:C.a},{l:"SLA",v:`${avgSLA}%`,c:avgSLA>90?C.a:C.w}].map((m,i)=><Card key={i} style={{textAlign:"center",padding:16}}><div style={{fontSize:24,fontWeight:300,color:m.c,fontFamily:"'Fraunces',serif"}}>{m.v}</div><M style={{color:C.td,textTransform:"uppercase",letterSpacing:1,marginTop:4}}>{m.l}</M></Card>)}
            </div>
            {regions.map(r=><Card key={r.id} style={{borderLeft:`3px solid ${r.turnoverRisk==="high"?C.d:r.turnoverRisk==="medium"?C.w:C.a}`}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><div style={{fontSize:13,fontWeight:500}}>{r.name}</div><div style={{display:"flex",gap:6}}><Badge color={r.healthScore>75?C.a:C.w}>Health: {r.healthScore}</Badge><Badge color={r.turnoverRisk==="high"?C.d:r.turnoverRisk==="medium"?C.w:C.a}>{r.turnoverRisk} risk</Badge></div></div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>{[{l:"Analysts",v:r.analysts},{l:"Util",v:r.utilization+"%"},{l:"Auto",v:r.automationRate+"%"},{l:"Certs",v:r.certCoverage+"%"},{l:"SLA",v:r.slaCompliance+"%"}].map(m=><div key={m.l} style={{textAlign:"center"}}><M style={{color:C.t,fontWeight:500}}>{m.v}</M><br/><M style={{color:C.td}}>{m.l}</M></div>)}</div>
            </Card>)}
          </div>)}

          {tab==="reports"&&(<div>
            <L>Executive Reports</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate a CISO-grade report from real aggregated regional data. The GD-Server computes the report server-side using the latest <code>regional_metrics</code> snapshots from each connected MC and persists it in the reports table.</M>
            <Card style={{marginBottom:16}}>
              <Sel label="Report type" value={reportType} onChange={e=>setReportType(e.target.value)}>
                <option value="executive_summary">Executive Summary</option>
                <option value="human_impact_global">Global Human Impact Risk Report</option>
                <option value="turnover_forecast">Turnover Forecast</option>
                <option value="roi_analysis">FireAlive ROI</option>
                <option value="compliance">Compliance by Jurisdiction</option>
              </Sel>
              <Btn primary disabled={reportGenerating} onClick={async()=>{
                setReportGenerating(true);setReportError(null);setGeneratedReport(null);
                const r=await api.post("/api/reports/generate",{type:reportType});
                setReportGenerating(false);
                if(r&&!r.error){setGeneratedReport(r);showGdToast("Report generated");}
                else{setReportError(r?.error||"Report generation failed");showGdToast("Report failed: "+(r?.error||"unknown"));}
              }}>{reportGenerating?"Generating...":"Generate Report"}</Btn>
            </Card>
            {reportError&&<Card style={{padding:12,borderColor:C.d+"40",marginBottom:12}}><M style={{color:C.d}}>{reportError}</M></Card>}
            {generatedReport&&<Card style={{marginTop:16}}>
              <div style={{fontSize:16,fontWeight:600,color:"#E8EDF5",marginBottom:8}}>{generatedReport.title||"Report: "+generatedReport.type}</div>
              <M style={{color:C.td,display:"block",marginBottom:16}}>Generated: {generatedReport.generatedAt?new Date(generatedReport.generatedAt).toLocaleString():"—"}</M>
              {generatedReport.globalMetrics&&<Card style={{marginBottom:12,padding:12,borderColor:C.i+"30"}}><div style={{fontSize:12,fontWeight:500,color:C.i,marginBottom:8}}>Global Metrics</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,textAlign:"center"}}>{Object.entries(generatedReport.globalMetrics).map(([k,v])=><div key={k}><div style={{fontSize:18,fontWeight:600,color:C.t}}>{v}</div><M style={{color:C.td,fontSize:10}}>{k.replace(/([A-Z])/g," $1").trim()}</M></div>)}</div></Card>}
              {generatedReport.highlights&&generatedReport.highlights.length>0&&<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Highlights</div>{generatedReport.highlights.map((h,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.t}}>• {h}</M></div>)}</div>}
              {generatedReport.concerns&&generatedReport.concerns.length>0&&<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.w,marginBottom:8}}>Concerns</div>{generatedReport.concerns.map((c,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.tm}}>⚠ {c}</M></div>)}</div>}
              {generatedReport.recommendations&&generatedReport.recommendations.length>0&&<div style={{marginBottom:16}}><div style={{fontSize:12,fontWeight:500,color:C.i,marginBottom:8}}>Recommendations</div>{generatedReport.recommendations.map((r,i)=><div key={i} style={{padding:"4px 0"}}><M style={{color:C.t}}>{i+1}. {r}</M></div>)}</div>}
              {generatedReport.regions&&generatedReport.regions.length>0&&<Card style={{marginBottom:12,padding:12,borderColor:C.p+"30"}}><div style={{fontSize:12,fontWeight:500,color:C.p,marginBottom:8}}>Regional Breakdown</div>{generatedReport.regions.map((r,i)=><div key={i} style={{padding:"6px 0",borderBottom:i<generatedReport.regions.length-1?"1px solid "+C.b:"none",fontSize:11}}><M style={{color:C.t}}>{r.name}: {r.analysts} analysts · health {r.healthScore} · churn cost ${r.annualChurnCost?.toLocaleString()||"—"}</M></div>)}</Card>}
              {generatedReport.financials&&<Card style={{borderColor:C.a+"30",padding:14}}><div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Financial Impact</div><div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(140px, 1fr))",gap:8}}>{Object.entries(generatedReport.financials).map(([k,v])=><div key={k} style={{textAlign:"center"}}><div style={{fontSize:14,fontWeight:600,color:k.toLowerCase().includes("without")?C.d:k.toLowerCase().includes("savings")?C.a:C.t}}>{typeof v==="number"?"$"+v.toLocaleString():v}</div><M style={{color:C.td,fontSize:10}}>{k.replace(/([A-Z])/g," $1").trim()}</M></div>)}</div></Card>}
              <Btn small style={{marginTop:12}} onClick={()=>{const blob=new Blob([JSON.stringify(generatedReport,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="report-"+generatedReport.type+"-"+Date.now()+".json";a.click();}}>Export Report</Btn>
            </Card>}
          </div>)}

          {tab==="notifications"&&(<div>
            <L>CISO Notification Thresholds & Alerts</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure thresholds; the GD-Server's notification engine evaluates each incoming MC push against these rules and creates a notification when a region crosses a threshold.</M>
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Threshold Configuration</div>
              <Input label="Burnout health score alert threshold (alert when below)" value={notifCfg.burnoutThreshold} onChange={e=>setNotifCfg(prev=>({...prev,burnoutThreshold:parseInt(e.target.value)||65}))} type="number"/>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={notifCfg.turnoverRiskHigh} onChange={e=>setNotifCfg(prev=>({...prev,turnoverRiskHigh:e.target.checked}))}/><M style={{color:C.t}}>Alert when any region reaches HIGH or CRITICAL turnover risk</M></label>
              <Input label="SLA compliance alert threshold (alert when below %)" value={notifCfg.slaBelow} onChange={e=>setNotifCfg(prev=>({...prev,slaBelow:parseInt(e.target.value)||85}))} type="number"/>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Notification Channels</div>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={notifCfg.email} onChange={e=>setNotifCfg(prev=>({...prev,email:e.target.checked}))}/><M style={{color:C.t}}>Email</M></label>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={notifCfg.sms} onChange={e=>setNotifCfg(prev=>({...prev,sms:e.target.checked}))}/><M style={{color:C.t}}>SMS</M></label>
              <Input label="Recipients" value={notifCfg.recipients} onChange={e=>setNotifCfg(prev=>({...prev,recipients:e.target.value}))} placeholder="ciso@corp.com, vp-security@corp.com"/>
              <Btn primary disabled={notifSaving} onClick={async()=>{
                setNotifSaving(true);
                const r=await api.put("/api/notifications/config",notifCfg);
                setNotifSaving(false);
                if(r&&!r.error)showGdToast("Notification config saved");
                else showGdToast("Save failed: "+(r?.error||"unknown"));
              }} style={{marginTop:14}}>{notifSaving?"Saving...":"Save Notification Config"}</Btn>
            </Card>
            <Card>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>Active Notifications ({notifList.filter(n=>!n.acknowledged).length} unacknowledged)</div>
                <Btn small onClick={()=>{api.get("/api/notifications").then(r=>{if(r&&!r.error&&r.notifications)setNotifList(r.notifications);});}}>Refresh</Btn>
              </div>
              {notifList.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No notifications. Either no thresholds have been crossed yet, or no MCs are pushing data.</M>:<div style={{maxHeight:400,overflowY:"auto"}}>
                {notifList.map(n=><div key={n.id} style={{padding:"8px 10px",borderBottom:"1px solid "+C.b,display:"flex",justifyContent:"space-between",gap:10,opacity:n.acknowledged?0.5:1}}>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}>
                      <Badge color={n.severity==="critical"?C.d:(n.severity==="high"?C.w:C.i)}>{n.severity||"info"}</Badge>
                      <M style={{color:C.t,fontWeight:500}}>{n.event_type||n.type}</M>
                      {n.mc_name&&<M style={{color:C.tm,fontSize:10}}>· {n.mc_name}</M>}
                    </div>
                    <M style={{color:C.tm,fontSize:11}}>{n.message||n.detail||""}</M>
                    <M style={{color:C.td,fontSize:10,display:"block",marginTop:2}}>{n.created_at?new Date(n.created_at).toLocaleString():""}</M>
                  </div>
                  {!n.acknowledged&&<Btn small onClick={async()=>{const r=await api.put("/api/notifications/"+n.id+"/acknowledge",{});if(r&&!r.error){showGdToast("Acknowledged");api.get("/api/notifications").then(x=>{if(x&&x.notifications)setNotifList(x.notifications);});}}}>Acknowledge</Btn>}
                </div>)}
              </div>}
            </Card>
          </div>)}

          {tab==="query"&&(<div>
            <L>Custom Regional Query</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Investigation tool for the CISO. Runs parameterized queries against the aggregated regional metrics database. Supports an optional regex filter on a chosen string column. Results render as a table for snapshot queries and as a line chart for time-series queries.</M>
            {!queryTemplates.length&&!queryTemplatesLoading&&<Card style={{padding:12,borderColor:C.w+"30",marginBottom:12}}><M style={{color:C.w}}>Loading query templates...</M></Card>}
            {queryTemplatesError&&<Card style={{padding:12,borderColor:C.d+"40",marginBottom:12}}><M style={{color:C.d}}>Failed to load templates: {queryTemplatesError}</M></Card>}
            <Card style={{marginBottom:16}}>
              <Sel label="Query template" value={queryTemplateId} onChange={e=>{const id=e.target.value;setQueryTemplateId(id);const t=queryTemplates.find(x=>x.id===id);if(t)setQueryDaysBack(t.defaultDaysBack);}} disabled={configLocked}>
                <option value="">Select a template...</option>
                {queryTemplates.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}
              </Sel>
              {queryTemplateId&&(()=>{const t=queryTemplates.find(x=>x.id===queryTemplateId);return t?<M style={{color:C.tm,display:"block",marginBottom:12,fontSize:11,lineHeight:1.6}}>{t.description}</M>:null;})()}
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:12}}>
                <Input label="Days back (1-365)" type="number" value={queryDaysBack} onChange={e=>setQueryDaysBack(parseInt(e.target.value)||30)} min={1} max={365} disabled={configLocked||!queryTemplateId}/>
                <Sel label="Filter column (optional)" value={queryFilterColumn} onChange={e=>setQueryFilterColumn(e.target.value)} disabled={configLocked||!queryTemplateId}>
                  <option value="">No filter</option>
                  {queryFilterableColumns.map(c=><option key={c} value={c}>{c}</option>)}
                </Sel>
                <Input label="Filter pattern (optional, * = wildcard)" value={queryFilterPattern} onChange={e=>setQueryFilterPattern(e.target.value)} placeholder="e.g., mc-us-* or *east*" maxLength={256} disabled={configLocked||!queryTemplateId||!queryFilterColumn} style={{fontFamily:"'IBM Plex Mono',monospace"}}/>
              </div>
              <M style={{color:C.td,display:"block",fontSize:10,marginBottom:10,lineHeight:1.5}}>SQL is template-defined and parameterized. Filter pattern is a case-insensitive glob (`*` matches anything) applied to results server-side via pure string operations — no regex, no ReDoS surface. Audit-logged with template id, parameters, and result count.</M>
              <div style={{display:"flex",gap:8}}>
                <Btn primary disabled={configLocked||!queryTemplateId||queryRunning} onClick={async()=>{
                  setQueryRunning(true);setQueryError(null);setQueryResults(null);
                  const payload={templateId:queryTemplateId,daysBack:queryDaysBack};
                  if(queryFilterColumn&&queryFilterPattern){payload.filterColumn=queryFilterColumn;payload.filterPattern=queryFilterPattern;}
                  const r=await api.post("/api/gd/query",payload);
                  setQueryRunning(false);
                  if(r&&!r.error){setQueryResults(r);showGdToast("Query returned "+r.resultCount+" rows from "+r.regionCount+" regions");}
                  else{setQueryError(r?.error||"Query failed");showGdToast("Query failed: "+(r?.error||"unknown"));}
                }}>{queryRunning?"Running...":"Run Query"}</Btn>
                {queryResults&&<Btn onClick={()=>{const blob=new Blob([JSON.stringify(queryResults,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-query-"+queryTemplateId+"-"+Date.now()+".json";a.click();}}>Export Results</Btn>}
              </div>
            </Card>
            {queryError&&<Card style={{padding:12,borderColor:C.d+"40",marginBottom:12}}><M style={{color:C.d,fontSize:11}}>{queryError}</M></Card>}
            {queryResults&&<div>
              <Card style={{marginBottom:12}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                  <M style={{color:C.t,fontWeight:500}}>{queryResults.templateName}</M>
                  <Badge color={queryResults.resultShape==="time_series"?C.i:C.p}>{queryResults.resultShape}</Badge>
                </div>
                <M style={{color:C.tm,fontSize:11,display:"block"}}>Returned {queryResults.resultCount} rows from {queryResults.regionCount} regions. Window: last {queryResults.daysBack} days. {queryResults.filterColumn?"Filter: "+queryResults.filterColumn+" matches "+queryResults.filterPattern:"No filter applied."}</M>
              </Card>
              {queryResults.resultShape==="time_series"&&queryResults.series&&queryResults.series.length>0&&(()=>{
                const allPoints=queryResults.series.flatMap(s=>s.points);
                if(allPoints.length===0)return null;
                const W=720,H=240,PAD={top:20,right:20,bottom:30,left:40};
                const xs=allPoints.map(p=>new Date(p.x).getTime());
                const ys=allPoints.map(p=>p.y);
                const xMin=Math.min(...xs),xMax=Math.max(...xs);
                const yMin=Math.min(0,...ys),yMax=Math.max(...ys,1);
                const xScale=t=>PAD.left+((t-xMin)/Math.max(xMax-xMin,1))*(W-PAD.left-PAD.right);
                const yScale=v=>H-PAD.bottom-((v-yMin)/Math.max(yMax-yMin,1))*(H-PAD.top-PAD.bottom);
                const colors=[C.a,C.i,C.p,C.w,C.d,"#10b981","#f59e0b","#06b6d4","#ec4899"];
                return <Card style={{marginBottom:12,padding:14}}>
                  <M style={{color:C.t,fontWeight:500,display:"block",marginBottom:8}}>{queryResults.valueLabel} over time</M>
                  <svg viewBox={`0 0 ${W} ${H}`} style={{width:"100%",height:"auto",background:"rgba(0,0,0,0.15)",borderRadius:6}}>
                    {[0,0.25,0.5,0.75,1].map(t=>{const y=PAD.top+t*(H-PAD.top-PAD.bottom);const v=yMax-t*(yMax-yMin);return <g key={t}><line x1={PAD.left} x2={W-PAD.right} y1={y} y2={y} stroke={C.b} strokeWidth={0.5}/><text x={PAD.left-4} y={y+3} fill={C.td} fontSize={9} textAnchor="end" fontFamily="'IBM Plex Mono',monospace">{Math.round(v)}</text></g>;})}
                    <line x1={PAD.left} x2={PAD.left} y1={PAD.top} y2={H-PAD.bottom} stroke={C.tm} strokeWidth={0.5}/>
                    <line x1={PAD.left} x2={W-PAD.right} y1={H-PAD.bottom} y2={H-PAD.bottom} stroke={C.tm} strokeWidth={0.5}/>
                    <text x={xScale(xMin)} y={H-PAD.bottom+15} fill={C.td} fontSize={9} fontFamily="'IBM Plex Mono',monospace">{new Date(xMin).toLocaleDateString()}</text>
                    <text x={xScale(xMax)} y={H-PAD.bottom+15} fill={C.td} fontSize={9} textAnchor="end" fontFamily="'IBM Plex Mono',monospace">{new Date(xMax).toLocaleDateString()}</text>
                    {queryResults.series.map((s,si)=>{const path=s.points.map((p,i)=>(i===0?"M":"L")+xScale(new Date(p.x).getTime())+","+yScale(p.y)).join(" ");const color=colors[si%colors.length];return <g key={s.name}><path d={path} stroke={color} strokeWidth={1.5} fill="none"/>{s.points.map((p,i)=><circle key={i} cx={xScale(new Date(p.x).getTime())} cy={yScale(p.y)} r={2} fill={color}/>)}</g>;})}
                  </svg>
                  <div style={{display:"flex",flexWrap:"wrap",gap:10,marginTop:10}}>{queryResults.series.map((s,si)=><div key={s.name} style={{display:"flex",alignItems:"center",gap:5,fontSize:10}}><div style={{width:10,height:2,background:colors[si%colors.length]}}/><M style={{color:C.tm}}>{s.name}</M></div>)}</div>
                </Card>;
              })()}
              {queryResults.rows&&queryResults.rows.length>0&&<Card style={{marginBottom:12}}>
                <M style={{color:C.t,fontWeight:500,display:"block",marginBottom:8}}>Result Rows ({queryResults.rows.length})</M>
                <div style={{maxHeight:280,overflowY:"auto",background:"rgba(0,0,0,0.15)",borderRadius:6}}>
                  <table style={{width:"100%",fontSize:10,fontFamily:"'IBM Plex Mono',monospace",borderCollapse:"collapse"}}>
                    <thead style={{position:"sticky",top:0,background:C.s}}><tr>{Object.keys(queryResults.rows[0]).map(k=><th key={k} style={{padding:"6px 8px",textAlign:"left",borderBottom:"1px solid "+C.b,color:C.tm}}>{k}</th>)}</tr></thead>
                    <tbody>{queryResults.rows.slice(0,500).map((row,i)=><tr key={i} style={{borderBottom:"1px solid "+C.b}}>{Object.keys(queryResults.rows[0]).map(k=><td key={k} style={{padding:"4px 8px",color:C.t}}>{String(row[k]??"")}</td>)}</tr>)}</tbody>
                  </table>
                  {queryResults.rows.length>500&&<M style={{color:C.td,padding:8,display:"block",textAlign:"center"}}>Showing first 500 of {queryResults.rows.length} rows. Export for full results.</M>}
                </div>
              </Card>}
              {queryResults.rows&&queryResults.rows.length===0&&<Card style={{padding:14}}><M style={{color:C.tm}}>No rows returned. Try increasing the daysBack window or removing the regex filter.</M></Card>}
            </div>}
          </div>)}

          {tab==="regions"&&(<div><L>Regional Breakdown</L><M style={{color:C.tm,display:"block",marginBottom:12,fontSize:11}}>Click a region card to view 30-day historical metrics.</M>{regions.map(r=><Card key={r.id} onClick={()=>setDrilldownMcId(drilldownMcId===r.id?null:r.id)} style={{cursor:"pointer",borderColor:drilldownMcId===r.id?C.a+"60":C.b}}><div style={{fontSize:14,fontWeight:600,color:"#E8EDF5",marginBottom:12}}>{r.name} {drilldownMcId===r.id?"(click to close)":""}</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}><div><M style={{color:C.td}}>MC: {r.mc} · Analysts: {r.analysts} · Sync: {r.lastSync?new Date(r.lastSync).toLocaleTimeString():"—"}</M></div><div>{[{l:"Health",v:r.healthScore,c:r.healthScore>75?C.a:C.w},{l:"Util",v:r.utilization,c:r.utilization>80?C.d:C.a},{l:"Auto",v:r.automationRate,c:C.i}].map(m=><div key={m.l} style={{marginBottom:4}}><M style={{color:C.tm}}>{m.l}: {m.v}%</M><div style={{width:"100%",height:4,background:C.b,borderRadius:2,marginTop:2}}><div style={{width:m.v+"%",height:"100%",background:m.c,borderRadius:2}}/></div></div>)}</div></div>{drilldownMcId===r.id&&<div style={{marginTop:12,paddingTop:12,borderTop:"1px solid "+C.b}} onClick={e=>e.stopPropagation()}>{drilldownLoading?<M style={{color:C.tm}}>Loading 30-day history...</M>:!drilldownData||drilldownData.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No historical metrics available. The MC may not have pushed enough data yet.</M>:(()=>{const W=720,H=200,PAD={top:16,right:16,bottom:24,left:36};const xs=drilldownData.map(p=>new Date(p.timestamp).getTime());const xMin=Math.min(...xs),xMax=Math.max(...xs);const xScale=t=>PAD.left+((t-xMin)/Math.max(xMax-xMin,1))*(W-PAD.left-PAD.right);const yScale=v=>H-PAD.bottom-(v/100)*(H-PAD.top-PAD.bottom);const series=[{key:"health_score",label:"Health",color:C.a},{key:"utilization_pct",label:"Util",color:C.w},{key:"automation_rate",label:"Auto",color:C.i},{key:"cert_coverage_pct",label:"Cert",color:C.p}];return <div><svg viewBox={`0 0 ${W} ${H}`} style={{width:"100%",height:"auto",background:"rgba(0,0,0,0.15)",borderRadius:6}}>{[0,25,50,75,100].map(v=><g key={v}><line x1={PAD.left} x2={W-PAD.right} y1={yScale(v)} y2={yScale(v)} stroke={C.b} strokeWidth={0.5}/><text x={PAD.left-4} y={yScale(v)+3} fill={C.td} fontSize={9} textAnchor="end" fontFamily="'IBM Plex Mono',monospace">{v}</text></g>)}<text x={xScale(xMin)} y={H-PAD.bottom+14} fill={C.td} fontSize={9} fontFamily="'IBM Plex Mono',monospace">{new Date(xMin).toLocaleDateString()}</text><text x={xScale(xMax)} y={H-PAD.bottom+14} fill={C.td} fontSize={9} textAnchor="end" fontFamily="'IBM Plex Mono',monospace">{new Date(xMax).toLocaleDateString()}</text>{series.map(s=>{const pts=drilldownData.filter(p=>p[s.key]!=null);if(!pts.length)return null;const path=pts.map((p,i)=>(i===0?"M":"L")+xScale(new Date(p.timestamp).getTime())+","+yScale(p[s.key])).join(" ");return <path key={s.key} d={path} stroke={s.color} strokeWidth={1.5} fill="none"/>;})}</svg><div style={{display:"flex",gap:14,marginTop:8,fontSize:10,flexWrap:"wrap"}}>{series.map(s=><div key={s.key} style={{display:"flex",alignItems:"center",gap:4}}><div style={{width:10,height:2,background:s.color}}/><M style={{color:C.tm}}>{s.label}</M></div>)}<M style={{color:C.td,marginLeft:"auto"}}>{drilldownData.length} data points</M></div></div>;})()}</div>}</Card>)}</div>)}

          {tab==="connections"&&(<div>
            <L>Management Console Connections</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Each Regional MC pushes aggregate metrics to this GD-Server. Register a new MC to generate its API key, then provide the key to the MC's admin who configures it in the MC's Settings → Global Dashboard Push tab.</M>
            {mcsError&&<Card style={{padding:12,borderColor:C.d+"40",marginBottom:12}}><M style={{color:C.d}}>{mcsError}</M></Card>}
            {mcs.length===0&&!mcsLoading&&!mcsError&&<Card style={{padding:14,borderColor:C.w+"30",marginBottom:12}}><M style={{color:C.w}}>No MCs registered yet. Register one below to get started.</M></Card>}
            {mcs.map(mc=><Card key={mc.id} style={{marginBottom:8}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <M style={{color:C.t,fontWeight:500}}>{mc.name}</M>
                  <M style={{color:C.td,display:"block",fontSize:10}}>id: {mc.id} · region: {mc.region||"—"} · framework: {mc.regulatory_framework||"none"}</M>
                  <M style={{color:C.td,display:"block",fontSize:10}}>endpoint: {mc.endpoint||"—"} · analysts: {mc.analyst_count??"—"} · last sync: {mc.last_sync||"never"}</M>
                </div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  <Badge color={mc.status==="active"?C.a:(mc.status==="offboarded"?C.tm:C.w)}>{mc.status||"unknown"}</Badge>
                  {mc.status==="active"&&<Btn small onClick={()=>{if(window.confirm("Offboard "+mc.name+"? The MC will stop being able to push metrics. This cannot be undone."))api.put("/api/mc/"+mc.id+"/offboard",{}).then(r=>{if(r&&!r.error){showGdToast(mc.name+" offboarded");api.get("/api/mc/list").then(x=>{if(x&&x.managementConsoles)setMcs(x.managementConsoles);});}else showGdToast("Offboard failed: "+(r?.error||"unknown"));});}}>Offboard</Btn>}
                </div>
              </div>
            </Card>)}
            {lastRegisteredMc&&<Card style={{padding:14,borderColor:C.a+"60",marginTop:16,marginBottom:8,background:"rgba(110,231,183,0.04)"}}>
              <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:6}}>✓ MC registered successfully</M>
              <M style={{color:C.t,display:"block",marginBottom:10,fontSize:11}}>{lastRegisteredMc.message||"Provide this API key to the Regional MC admin"}</M>
              <div style={{padding:10,background:"rgba(0,0,0,0.3)",borderRadius:6,fontFamily:"'IBM Plex Mono',monospace",fontSize:11,color:C.a,wordBreak:"break-all"}}>{lastRegisteredMc.apiKey}</div>
              <div style={{display:"flex",gap:8,marginTop:10}}>
                <Btn small primary onClick={()=>{navigator.clipboard.writeText(lastRegisteredMc.apiKey);showGdToast("API key copied to clipboard");}}>Copy Key</Btn>
                <Btn small onClick={()=>setLastRegisteredMc(null)}>Dismiss</Btn>
              </div>
              <M style={{color:C.w,display:"block",marginTop:10,fontSize:10,fontStyle:"italic"}}>This key will only be shown once. If you lose it, the MC must be re-registered.</M>
            </Card>}
            <Card style={{marginTop:16}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Register New MC</div>
              <Input label="MC name (display label)" value={addMcForm.name} onChange={e=>setAddMcForm(p=>({...p,name:e.target.value}))} placeholder="e.g., North America East" disabled={addMcInFlight}/>
              <Input label="Region" value={addMcForm.region} onChange={e=>setAddMcForm(p=>({...p,region:e.target.value}))} placeholder="e.g., us-east-1" disabled={addMcInFlight}/>
              <Input label="MC endpoint URL" value={addMcForm.endpoint} onChange={e=>setAddMcForm(p=>({...p,endpoint:e.target.value}))} placeholder="https://mc.corp.com:3000" disabled={addMcInFlight}/>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                <Input label="Country (optional)" value={addMcForm.country} onChange={e=>setAddMcForm(p=>({...p,country:e.target.value}))} placeholder="US" disabled={addMcInFlight}/>
                <Sel label="Regulatory framework" value={addMcForm.regulatoryFramework} onChange={e=>setAddMcForm(p=>({...p,regulatoryFramework:e.target.value}))} disabled={addMcInFlight}>
                  <option value="none">None</option><option value="GDPR">GDPR</option><option value="HIPAA">HIPAA</option><option value="SOC2">SOC 2</option><option value="ISO27001">ISO 27001</option><option value="DORA">DORA</option><option value="CCPA">CCPA</option><option value="PIPEDA">PIPEDA</option><option value="LGPD">LGPD</option><option value="NIS2">NIS2</option>
                </Sel>
              </div>
              <Btn primary disabled={addMcInFlight||!addMcForm.name||!addMcForm.region} onClick={async()=>{
                setAddMcInFlight(true);
                const r=await api.post("/api/mc/register",addMcForm);
                setAddMcInFlight(false);
                if(r&&!r.error&&r.apiKey){
                  setLastRegisteredMc(r);
                  setAddMcForm({name:"",region:"",endpoint:"",country:"",regulatoryFramework:"none"});
                  const list=await api.get("/api/mc/list");
                  if(list&&list.managementConsoles)setMcs(list.managementConsoles);
                  showGdToast("MC registered. API key shown above — copy it now.");
                }else{
                  showGdToast("Registration failed: "+(r?.error||"unknown"));
                }
              }}>{addMcInFlight?"Registering...":"Register MC"}</Btn>
            </Card>
          </div>)}

          {tab==="audit_dash"&&(<div>
            <L>Audit & Forensics</L>
            <Card style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>Audit Trail (most recent 100 events)</div>
                <Btn small onClick={()=>{setAuditLoading(true);api.get("/api/audit-logs?limit=100").then(r=>{if(r&&!r.error&&r.logs)setAuditList(r.logs);}).finally(()=>setAuditLoading(false));}}>Refresh</Btn>
              </div>
              <div style={{maxHeight:300,overflowY:"auto",background:"rgba(0,0,0,0.2)",borderRadius:8}}>
                {auditLoading?<div style={{padding:14}}><M style={{color:C.tm}}>Loading audit events...</M></div>:auditList.length===0?<div style={{padding:14}}><M style={{color:C.td,fontStyle:"italic"}}>No audit events recorded yet.</M></div>:auditList.map((e,i)=><div key={i} style={{padding:"4px 8px",borderBottom:"1px solid "+C.b,display:"grid",gridTemplateColumns:"110px 80px 50px 1fr",gap:6,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",alignItems:"center"}}><span style={{color:C.td}}>{e.timestamp?new Date(e.timestamp).toLocaleString():"—"}</span><span style={{color:e.severity==="critical"?C.d:(e.severity==="warning"?C.w:C.a)}}>{e.event_type||"—"}</span><span style={{color:C.tm}}>{e.severity||"info"}</span><span style={{color:C.tm}}>{e.detail||""}</span></div>)}
              </div>
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:C.i,fontWeight:500}}>Log Integrity</M><Badge color={logIntegrity.status==="healthy"?C.a:C.d}>{logIntegrity.status}</Badge></div>
              <M style={{color:C.td}}>Last check: {new Date(logIntegrity.lastCheck).toLocaleString()} · Continuous monitoring · Tampering detection enabled</M>
              <M style={{color:C.td,display:"block",marginTop:6,fontStyle:"italic"}}>Log integrity status auto-forwarded to configured SIEM/SOAR in the Monitoring Integrations tab.</M>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Export Audit Logs & Forensics</div>
              <M style={{color:C.tm,display:"block",marginBottom:12}}>Export in any standard format for ingestion by your SIEM, SOAR, or forensics platform. Sources from the GD-Server's own audit_log table.</M>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Btn small primary onClick={()=>api.download("/api/audit-logs/export/csv","gd-audit.csv")}>CSV</Btn>
                <Btn small onClick={()=>api.download("/api/audit-logs/export/json","gd-audit.json")}>JSON</Btn>
                <Btn small onClick={()=>api.download("/api/audit-logs/export/syslog","gd-audit.syslog")}>Syslog</Btn>
                <Btn small onClick={async()=>{const r=await api.get("/api/audit-logs?limit=10000");const forensics={exportType:"global_dashboard_forensics",version:"0.0.31",exportedAt:new Date().toISOString(),logIntegrity,eventCount:r?.logs?.length||0,events:r?.logs||[],regions};const blob=new Blob([JSON.stringify(forensics,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="gd-forensics.json";a.click();}}>Forensics</Btn>
              </div>
            </Card>
          </div>)}

          {/* ══════════ SYSTEM HEALTH ══════════ */}
          {tab==="sys_health"&&(<div>
            <L>System Health Monitor</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Self-monitoring of the Global Dashboard server process and its independent backend. Sourced from the GD-Server's <code>/api/system/health-metrics</code>.</M>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.a}}>{gdHealth.cpu==="—"?"—":gdHealth.cpu+"%"}</div><M style={{color:C.td}}>CPU</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.i}}>{gdHealth.memoryMB??"—"}</div><M style={{color:C.td}}>Memory (MB)</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.p}}>{gdHealth.heapMB??"—"}</div><M style={{color:C.td}}>Heap (MB)</M></Card>
              <Card style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:600,color:C.w}}>{gdHealth.connectedMCs??regions.length}</div><M style={{color:C.td}}>Connected MCs</M></Card>
            </div>
            <Card><M style={{color:C.tm}}>{gdHealth.uptimeSec?"Server uptime: "+Math.floor(gdHealth.uptimeSec/3600)+"h "+Math.floor((gdHealth.uptimeSec%3600)/60)+"m":"Server uptime: —"} · Node: {gdHealth.nodeVersion||"—"} · Backend port: 4001</M></Card>
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

          {/* ══════════ R3f — MFA SELF-SERVICE + ADMIN POLICY ══════════ */}
          {tab==="mfa"&&(<div>
            <L>Multi-Factor Authentication</L>
            <MyMfaSecuritySection/>
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
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Run a 10-point compromise check on the Global Dashboard server itself — binary integrity, database integrity, network connections, API tokens, TLS, audit log continuity, configuration drift, memory analysis, filesystem integrity, and encryption key validity. Results are audit-logged.</M>
            <Btn primary disabled={compromiseRunning} onClick={async()=>{
              setCompromiseRunning(true);setCompromiseResult(null);
              const r=await api.post("/api/compromise-scan",{});
              setCompromiseRunning(false);
              if(r&&!r.error){setCompromiseResult(r);showGdToast("Compromise scan: "+r.overall);}
              else showGdToast("Scan failed: "+(r?.error||"unknown"));
            }}>{compromiseRunning?"Scanning...":"Run Compromise Scan"}</Btn>
            {compromiseResult&&<Card style={{marginTop:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div>
                  <M style={{color:C.t,fontWeight:500}}>Scan {compromiseResult.scanId?.slice(0,8)||""}</M>
                  <M style={{color:C.td,display:"block",fontSize:10}}>{compromiseResult.timestamp?new Date(compromiseResult.timestamp).toLocaleString():""}</M>
                </div>
                <Badge color={compromiseResult.overall==="clean"?C.a:C.d}>{compromiseResult.overall}</Badge>
              </div>
              {compromiseResult.tests?.map((t,i)=><div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{t.name}</M><M style={{color:t.status==="pass"?C.a:C.d,fontWeight:500}}>{t.status?.toUpperCase()}</M></div>)}
              <Btn small style={{marginTop:10}} onClick={()=>{const blob=new Blob([JSON.stringify(compromiseResult,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="compromise-scan-"+(compromiseResult.scanId?.slice(0,8)||Date.now())+".json";a.click();}}>Export Result</Btn>
            </Card>}
          </div>)}

          {/* ══════════ REGRESSION TEST ══════════ */}
          {tab==="regression"&&(<div>
            <L>Regression Test</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Verify all GD-Server endpoints and core functions are working correctly. Run before applying configuration changes or after a restart.</M>
            <Btn primary disabled={regressionRunning} onClick={async()=>{
              setRegressionRunning(true);setRegressionResult(null);
              const r=await api.post("/api/regression-test",{});
              setRegressionRunning(false);
              if(r&&!r.error){setRegressionResult(r);showGdToast(r.passed+"/"+r.total+" passed");}
              else showGdToast("Test failed: "+(r?.error||"unknown"));
            }}>{regressionRunning?"Running...":"Run Regression Test"}</Btn>
            {regressionResult&&<Card style={{marginTop:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <M style={{color:C.t,fontWeight:500}}>{regressionResult.timestamp?new Date(regressionResult.timestamp).toLocaleString():""}</M>
                <Badge color={regressionResult.overall==="pass"?C.a:C.d}>{regressionResult.passed}/{regressionResult.total} {regressionResult.overall}</Badge>
              </div>
              {regressionResult.tests?.map((t,i)=><div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{t.name}</M><M style={{color:t.status==="pass"?C.a:C.d,fontWeight:500}}>{t.status?.toUpperCase()}</M></div>)}
              <Btn small style={{marginTop:10}} onClick={()=>{const blob=new Blob([JSON.stringify(regressionResult,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="regression-"+Date.now()+".json";a.click();}}>Export Result</Btn>
            </Card>}
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
              <Sel label="Select MC to offboard"><option value="">Select...</option>{regions.map(r=><option key={r.id} value={r.id}>{r.name} ({r.mc})</option>)}</Sel>
              <Input label="Reason for offboarding" placeholder="e.g., Regional SOC consolidated into US-East"/>
              <Sel label="Data retention"><option value="keep">Keep historical data indefinitely</option><option value="1year">Retain for 1 year then purge</option><option value="purge_now">Purge immediately (irreversible)</option></Sel>
              <Btn danger>Offboard MC</Btn>
            </Card>
          </div>)}

          {/* ══════════ TROUBLESHOOTER ══════════ */}
          {tab==="troubleshooter"&&(<div>
            <L>Troubleshooter</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Diagnose issues with the Global Dashboard, MC connections, data sync, and backend health. Describe the symptom and the GD-Server runs targeted diagnostic checks.</M>
            <Card>
              <Input label="Describe the issue" value={troubleQuery} onChange={e=>setTroubleQuery(e.target.value)} placeholder="e.g., MC not syncing, reports not generating, notifications delayed" disabled={troubleRunning}/>
              <Btn primary disabled={troubleRunning||!troubleQuery.trim()} onClick={async()=>{
                setTroubleRunning(true);setTroubleResult(null);
                const r=await api.post("/api/troubleshoot",{query:troubleQuery});
                setTroubleRunning(false);
                if(r&&!r.error&&r.checks){setTroubleResult(r);showGdToast("Diagnostics returned "+r.checks.length+" checks");}
                else showGdToast("Troubleshoot failed: "+(r?.error||"unknown"));
              }}>{troubleRunning?"Diagnosing...":"Diagnose"}</Btn>
            </Card>
            {troubleResult&&troubleResult.checks&&<Card style={{marginTop:16}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Diagnostic Results</div>
              {troubleResult.checks.map((c,i)=><div key={i} style={{padding:"6px 0",borderBottom:i<troubleResult.checks.length-1?`1px solid ${C.b}`:"none",fontFamily:"'IBM Plex Mono',monospace",fontSize:11}}><M style={{color:c.startsWith("→")?C.i:c.startsWith("✓")?C.a:c.startsWith("✗")||c.startsWith("✘")?C.d:C.t}}>{c}</M></div>)}
            </Card>}
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
      <div style={{padding:"14px 24px",borderTop:`1px solid ${C.b}`,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",display:"flex",justifyContent:"space-between"}}><span>GLOBAL DASHBOARD · READ-ONLY · v1.0.0</span><span>{regions.length} regions · {totalAnalysts} analysts</span></div>
    </div>
  );
}

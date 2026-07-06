// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL CISO DASHBOARD — Read-Only Executive View
// Login, welcome/setup guide, notifications, query, reports, log integrity
// ═══════════════════════════════════════════════════════════════════════════════
import { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";

const C={bg:"#060A10",s:"#0D1117",b:"#1C2333",t:"#E8EDF5",tm:"#8B949E",td:"#6E7681",a:"#6EE7B7",ad:"rgba(110,231,183,0.08)",w:"#F59E0B",d:"#EF4444",p:"#A78BFA",i:"#60A5FA"};
const CSS=`*{margin:0;padding:0;box-sizing:border-box}@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}`;
const M=({children,...p})=><span style={{fontSize:11,fontFamily:"'IBM Plex Mono',monospace",...p.style}}>{children}</span>;
const L=({children})=><div style={{fontSize:15,fontWeight:600,color:"#E8EDF5",marginBottom:16,fontFamily:"'Fraunces',serif"}}>{children}</div>;
const Card=({children,style,...p})=><div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,padding:"18px 20px",marginBottom:14,...style}} {...p}>{children}</div>;
const Btn=({children,primary,small,style,...p})=><button style={{padding:small?"5px 12px":"10px 18px",background:primary?C.ad:"transparent",border:`1px solid ${primary?C.a+"50":C.b}`,borderRadius:8,color:primary?C.a:C.tm,fontSize:small?10:12,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",...style}} {...p}>{children}</button>;
const Badge=({children,color})=><span style={{fontSize:9,padding:"2px 8px",borderRadius:10,background:color+"20",color,fontFamily:"'IBM Plex Mono',monospace",fontWeight:600}}>{children}</span>;
const Input=({label,...p})=><div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<input style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}/></div>;
const Sel=({label,children,...p})=><div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<select style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}>{children}</select></div>;

// ── COMPLIANCE_FRAMEWORKS ───────────────────────────────────────────────────
// The 16 frameworks registered in PR1 (MC) and PR2 (GD). Each entry maps the
// canonical framework id (URL-safe identifier passed as the :framework path
// param to /api/compliance/report/:framework) to its operator-facing display
// label. The two Compliance tabs (Compliance Posture + Cross-Region
// Compliance, both added in PR4) consume this same list so the selector copy
// stays consistent across views. Keep the order stable across releases for
// muscle-memory of CISO users.
const COMPLIANCE_FRAMEWORKS = [
  {id:"hipaa",            label:"HIPAA"},
  {id:"soc2",             label:"SOC 2"},
  {id:"nist_csf",         label:"NIST CSF 2.0"},
  {id:"gdpr",             label:"GDPR"},
  {id:"dora",             label:"DORA"},
  {id:"iso_27001",        label:"ISO/IEC 27001:2022"},
  {id:"fisma",            label:"FISMA / NIST 800-53"},
  {id:"cyber_essentials", label:"UK Cyber Essentials"},
  {id:"nis2",             label:"EU NIS2"},
  {id:"cps234_au",        label:"APRA CPS 234"},
  {id:"ccpa",             label:"CCPA / CPRA"},
  {id:"lgpd",             label:"LGPD (Brazil)"},
  {id:"pipeda",           label:"PIPEDA (Canada)"},
  {id:"pdpa_sg",          label:"PDPA (Singapore)"},
  {id:"appi_jp",          label:"APPI (Japan)"},
  {id:"popia_za",         label:"POPIA (South Africa)"},
];

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
  _baseUrl: 'https://localhost:4001',
  setBaseUrl(url) { this._baseUrl = url; },
  setToken(t) { this._token = t; },
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  // The GD operator app's bridge to the main process, where the hardware device
  // key lives. Null outside Electron (e.g. tests).
  _bridge() { return (typeof window !== 'undefined' && window.firealive) ? window.firealive : null; },
  // Obtain a fresh on-chip proof-of-possession for this request (D28). The server
  // binds req.path without its query string, so the proof is signed over the path
  // alone. Returns null when no bridge or key is available; the server then rejects
  // the request if a proof is required, and the renderer re-authenticates.
  async _popHeader(method, path) {
    const b = this._bridge();
    if (!b || typeof b.invoke !== 'function') return null;
    try {
      const res = await b.invoke('device:signPopProof', { method, path: String(path).split('?')[0] });
      return res && res.proof ? res.proof : null;
    } catch (_) { return null; }
  },
  // Single request path: bearer token, a fresh PoP proof, and (added transparently
  // by Electron's select-client-certificate) the mTLS client cert. On a gate
  // rejection the JSON body's error/code are surfaced so the renderer can re-auth.
  async _send(method, path, data) {
    const headers = this._headers();
    const pop = await this._popHeader(method, path);
    if (pop) headers['x-fa-device-pop'] = pop;
    const init = { method, headers };
    if (data !== undefined) init.body = JSON.stringify(data);
    try {
      const r = await fetch(this._baseUrl + path, init);
      if (r.ok) return await r.json();
      let body = {};
      try { body = await r.json(); } catch (_) { /* non-JSON error response */ }
      return { error: body.error || r.statusText, code: body.code, status: r.status };
    } catch (e) {
      console.warn('[API]', path, e.message);
      return { error: e.message };
    }
  },
  async post(path, data) { return this._send('POST', path, data); },
  async get(path) { return this._send('GET', path); },
  async put(path, data) { return this._send('PUT', path, data); },
  async patch(path, data) { return this._send('PATCH', path, data); },
  async del(path) { return this._send('DELETE', path); },
  async download(path, filename, opts) {
    const method = (opts && opts.method) || 'GET';
    const headers = this._headers();
    const pop = await this._popHeader(method, path);
    if (pop) headers['x-fa-device-pop'] = pop;
    const init = { method, headers };
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
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  MY SECURITY SECTION                                                    ║
// ║                                                                         ║
// ║  Self-service passwordless credential management for the current        ║
// ║  CISO / VP operator. Renders in the MFA tab. Talks to /api/mfa/* on     ║
// ║  the GD-Server — passkey/register-options + register-verify,            ║
// ║  GET/DELETE passkeys, GET certs, certs/revoke — all scoped to           ║
// ║  req.user.id server-side. There is no TOTP. Reuses the module-level     ║
// ║  WebAuthn (de)serialization helpers.                                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function MyMfaSecuritySection() {
  const [passkeys, setPasskeys] = useState(null);   // null = not loaded
  const [certs, setCerts] = useState(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const loadPasskeys = async () => {
    const r = await api.get("/api/mfa/passkeys");
    setPasskeys(r && Array.isArray(r.passkeys) ? r.passkeys : []);
  };
  const loadCerts = async () => {
    const r = await api.get("/api/mfa/certs");
    setCerts(r && Array.isArray(r.certs) ? r.certs : []);
  };
  useEffect(()=>{ loadPasskeys().catch(()=>{}); loadCerts().catch(()=>{}); },[]);

  const addPasskey = async () => {
    setBusy(true); setErr(""); setMsg("");
    try {
      const opt = await api.post("/api/mfa/passkey/register-options", {});
      if (!opt || opt.error || !opt.options || !opt.challengeToken) {
        setBusy(false);
        setErr(opt && opt.error ? String(opt.error) : "Could not start passkey enrollment.");
        return;
      }
      let cred;
      try { cred = await navigator.credentials.create({ publicKey: deserializeRegOptions(opt.options) }); }
      catch (_e) { setBusy(false); setErr("Passkey enrollment was cancelled or failed."); return; }
      if (!cred) { setBusy(false); setErr("No passkey was created."); return; }
      const r = await api.post("/api/mfa/passkey/register-verify", {
        response: serializeAttestation(cred),
        challengeToken: opt.challengeToken,
        label: label.trim() || undefined,
      });
      setBusy(false);
      if (!r || r.error || !r.registered) {
        if (r && r.code === "ENROLL_PASSKEY_NOT_HARDWARE") {
          setErr("This passkey was not accepted. Use a hardware security key (a FIDO2 key or fob) that requires a PIN. Synced or software passkeys (iCloud Keychain, Google Password Manager, Windows Hello) cannot be used to sign in.");
        } else {
          setErr(r && r.error ? String(r.error) : "Passkey verification failed.");
        }
        return;
      }
      setMsg("Passkey enrolled — hardware security key verified."); setLabel(""); loadPasskeys().catch(()=>{});
    } catch (e) {
      setBusy(false);
      setErr(e.message || "Passkey enrollment failed.");
    }
  };

  const removePasskey = async (id) => {
    if (!window.confirm("Remove this passkey?")) return;
    setErr(""); setMsg("");
    const r = await api.del("/api/mfa/passkeys/" + id);
    if (r && r.removed) { setMsg("Passkey removed."); loadPasskeys().catch(()=>{}); }
    else { setErr(r && r.error ? String(r.error) : "Could not remove passkey."); }
  };

  const revokeCert = async (serial) => {
    if (!window.confirm("Revoke certificate " + serial + "? It can no longer secure your connection.")) return;
    setErr(""); setMsg("");
    const r = await api.post("/api/mfa/certs/revoke", { serial });
    if (r && r.revoked) { setMsg("Certificate " + serial + " revoked."); loadCerts().catch(()=>{}); }
    else { setErr(r && r.error ? String(r.error) : "Revocation failed."); }
  };

  const dangerBtn = { color: C.d, borderColor: C.d + "50" };

  return (
    <Card>
      <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:6}}>My Security — Passkeys & Certificates</div>
      <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Manage your own phishing-resistant credentials. Sign-in uses a hardware FIDO2/WebAuthn passkey (a security key with a PIN) — there is no password. A client certificate secures your connection but is not a sign-in method. Keep at least one working passkey enrolled at all times.</M>

      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>Passkeys</div>
      {passkeys===null ? <M style={{color:C.td}}>Loading…</M> : passkeys.length===0 ? <M style={{color:C.td,display:"block",marginBottom:8}}>No passkeys enrolled.</M> : passkeys.map((k,i)=>(
        <div key={k.id||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
          <div style={{minWidth:0}}>
            <M style={{color:C.t,display:"block"}}>{String(k.credential_id||"").slice(0,16)}…{k.is_passwordless?"":" (second-factor)"}</M>
            <M style={{color:C.td,display:"block"}}>added {k.created_at?String(k.created_at).slice(0,10):"—"}{k.last_used_at?(" · last used "+String(k.last_used_at).slice(0,10)):" · never used"}</M>
          </div>
          <Btn small style={dangerBtn} onClick={()=>removePasskey(k.id)}>Remove</Btn>
        </div>
      ))}
      <div style={{display:"flex",gap:8,alignItems:"flex-end",marginTop:10}}>
        <div style={{flex:1}}><Input label="New passkey label (optional)" value={label} onChange={e=>setLabel(e.target.value)} placeholder="e.g. YubiKey 5C" maxLength={64}/></div>
        <Btn primary onClick={addPasskey} disabled={busy}>{busy?"Working…":"Add a passkey"}</Btn>
      </div>

      <div style={{fontSize:12,fontWeight:600,color:C.t,margin:"18px 0 8px"}}>Transport Certificate (mTLS)</div>
      <M style={{color:C.td,display:"block",marginBottom:8,lineHeight:1.6}}>A client certificate secures your connection to the GD-Server (mutual TLS) and binds your session to this device. It is not a sign-in credential — sign-in is always your hardware passkey. Certificates are issued during provisioning or by an administrator; review them here and revoke one you no longer use or that may be compromised.</M>
      {certs===null ? <M style={{color:C.td}}>Loading…</M> : certs.length===0 ? <M style={{color:C.td}}>No certificates issued to you.</M> : certs.map((c,i)=>(
        <div key={c.serial||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
          <div style={{minWidth:0}}>
            <M style={{color:C.t,display:"block"}}>{c.subject||"(no subject)"}</M>
            <M style={{color:C.td,display:"block"}}>serial {c.serial} · {c.status}{c.expires_at?(" · exp "+String(c.expires_at).slice(0,10)):""}</M>
          </div>
          {c.status==="active" ? <Btn small style={dangerBtn} onClick={()=>revokeCert(c.serial)}>Revoke</Btn> : <Badge color={c.status==="revoked"?C.d:C.tm}>{c.status}</Badge>}
        </div>
      ))}

      {msg&&<M style={{color:C.tm,display:"block",marginTop:12}}>{msg}</M>}
      {err&&<M style={{color:C.d,display:"block",marginTop:12}}>{err}</M>}
    </Card>
  );
}


// ── GD FIDO attestation trust anchors (B5n3, ciso) ───────────────────
// Manages the GD-Server's own trusted attestation roots and the optional AAGUID
// model allow-list via /api/iam/fido-* (gated to ciso server-side; the GD
// server audits each change). At least one trusted root must always remain.
function GdSelfProtectionConsole() {
  const EDR_PROVIDERS = ["crowdstrike_falcon","microsoft_defender_endpoint","sentinelone","palo_alto_cortex_xdr","trellix_edr","sophos_intercept_x","vmware_carbon_black","cisco_secure_endpoint","wazuh","elastic_defend","limacharlie"];
  const SEVERITIES = ["info","warning","high","critical"];
  const CHANNELS = ["soar","siem","email","notification","webhook"];
  const [siem,setSiem]=useState({endpoint:"",protocol:"tls"});
  const [soar,setSoar]=useState({endpoint:"",has_auth_token:false});
  const [soarToken,setSoarToken]=useState("");
  const [webhook,setWebhook]=useState({configured:false,host:null});
  const [webhookUrl,setWebhookUrl]=useState("");
  const [matrix,setMatrix]=useState(null);
  const [thresholds,setThresholds]=useState({});
  const [ih,setIh]=useState({master:false,integrations:{kms:{enabled:false},storage:{enabled:false},mc_trust:{enabled:false}}});
  const [ihResults,setIhResults]=useState(null);
  const [ihRunning,setIhRunning]=useState(false);
  const [edr,setEdr]=useState([]);
  const [newEdr,setNewEdr]=useState({provider_type:"crowdstrike_falcon",display_name:"",endpoint:"",credentials:""});
  const [runtime,setRuntime]=useState(null);
  const [msg,setMsg]=useState("");
  const [busy,setBusy]=useState(false);

  const load=async()=>{
    const s=await api.get("/api/self-protection/config/siem"); if(s&&!s.error)setSiem({endpoint:s.endpoint||"",protocol:s.protocol||"tls"});
    const so=await api.get("/api/self-protection/config/soar"); if(so&&!so.error)setSoar({endpoint:so.endpoint||"",has_auth_token:!!so.has_auth_token});
    const w=await api.get("/api/self-protection/config/webhook"); if(w&&!w.error)setWebhook({configured:!!w.configured,host:w.host||null});
    const m=await api.get("/api/self-protection/config/alert-matrix"); if(m&&!m.error)setMatrix(m.matrix||null);
    const t=await api.get("/api/self-protection/config/runtime-thresholds"); if(t&&!t.error)setThresholds(t.thresholds||{});
    const i=await api.get("/api/self-protection/config/integration-health"); if(i&&!i.error)setIh({master:!!i.master,integrations:i.integrations||{kms:{enabled:false},storage:{enabled:false},mc_trust:{enabled:false}}});
    const ir=await api.get("/api/self-protection/integration-health"); if(ir&&!ir.error)setIhResults(ir.ran===false?null:ir);
    const e=await api.get("/api/self-protection/config/edr"); if(e&&!e.error)setEdr(Array.isArray(e.integrations)?e.integrations:[]);
    const rt=await api.get("/api/self-protection/runtime/metrics"); if(rt&&!rt.error)setRuntime(rt);
  };
  useEffect(()=>{ load().catch(()=>{}); },[]);
  const flash=(t)=>{ setMsg(t); setTimeout(()=>setMsg(""),4000); };

  const saveSiem=async()=>{ setBusy(true); const r=await api.put("/api/self-protection/config/siem",{endpoint:siem.endpoint,protocol:siem.protocol}); setBusy(false); flash(r&&!r.error?"SIEM configuration saved":"SIEM save failed: "+(r&&r.error||"error")); };
  const saveSoar=async()=>{ setBusy(true); const body={endpoint:soar.endpoint}; if(soarToken)body.auth_token=soarToken; const r=await api.put("/api/self-protection/config/soar",body); setBusy(false); if(r&&!r.error){setSoarToken("");flash("SOAR configuration saved");load().catch(()=>{});}else flash("SOAR save failed: "+(r&&r.error||"error")); };
  const saveWebhook=async()=>{ setBusy(true); const r=await api.put("/api/self-protection/config/webhook",{url:webhookUrl}); setBusy(false); if(r&&!r.error){setWebhookUrl("");flash("Webhook saved");load().catch(()=>{});}else flash("Webhook save failed: "+(r&&r.error||"error")); };
  const toggleMatrix=(sev,ch)=>{ setMatrix(prev=>{ const next=JSON.parse(JSON.stringify(prev||{})); next[sev]=next[sev]||{}; next[sev][ch]=!next[sev][ch]; return next; }); };
  const saveMatrix=async()=>{ setBusy(true); const r=await api.put("/api/self-protection/config/alert-matrix",{matrix}); setBusy(false); flash(r&&!r.error?"Alert routing saved":"Routing save failed: "+(r&&r.error||"error")); };
  const saveIh=async()=>{ setBusy(true); const r=await api.put("/api/self-protection/config/integration-health",{master:ih.master,integrations:ih.integrations}); setBusy(false); flash(r&&!r.error?"Probe configuration saved":"Save failed: "+(r&&r.error||"error")); };
  const runIh=async()=>{ setIhRunning(true); const r=await api.post("/api/self-protection/integration-health/run",{}); setIhRunning(false); if(r&&!r.error){setIhResults(r);flash("Dependency probe run complete");}else flash("Probe run failed: "+(r&&r.error||"error")); };
  const addEdr=async()=>{ if(!newEdr.display_name.trim()){flash("EDR display name is required");return;} setBusy(true); const body={provider_type:newEdr.provider_type,display_name:newEdr.display_name,enabled:true}; if(newEdr.endpoint)body.endpoint=newEdr.endpoint; if(newEdr.credentials)body.credentials=newEdr.credentials; const r=await api.post("/api/self-protection/config/edr",body); setBusy(false); if(r&&!r.error){setNewEdr({provider_type:"crowdstrike_falcon",display_name:"",endpoint:"",credentials:""});flash("EDR integration added");load().catch(()=>{});}else flash("Add EDR failed: "+(r&&r.error||"error")); };
  const toggleEdr=async(it)=>{ const r=await api.put("/api/self-protection/config/edr/"+it.id,{enabled:!it.enabled}); if(r&&!r.error)load().catch(()=>{}); else flash("Toggle failed: "+(r&&r.error||"error")); };
  const deleteEdr=async(it)=>{ const r=await api.del("/api/self-protection/config/edr/"+it.id); if(r&&!r.error){flash("EDR integration removed");load().catch(()=>{});}else flash("Delete failed: "+(r&&r.error||"error")); };

  const statusColor=(st)=> st==="ok"?C.a:(["disabled","not_configured","not_implemented","deep_skipped"].indexOf(st)>=0?C.td:C.d);

  return (<div>
    <L>Monitoring Integrations</L>
    <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure how the Global Dashboard protects itself: forward its own audit and security events to your SIEM/SOAR, alert on a webhook, probe the GD's own dependencies, and integrate an external EDR. These monitor the GD server itself, never analyst data.</M>
    {msg&&<Card style={{borderColor:C.a+"40"}}><M style={{color:C.a}}>{msg}</M></Card>}

    <Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>SIEM</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>Forward GD audit and security events (CEF) to your SIEM.</M>
      <div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:8}}>
        <Input label="Endpoint (host:port)" value={siem.endpoint} placeholder="siem.corp.com:6514" onChange={e=>setSiem({...siem,endpoint:e.target.value})}/>
        <Sel label="Protocol" value={siem.protocol} onChange={e=>setSiem({...siem,protocol:e.target.value})}><option value="tls">TLS</option><option value="tcp">TCP</option><option value="udp">UDP</option></Sel>
      </div>
      <Btn small primary disabled={busy} onClick={saveSiem}>Save SIEM</Btn>
    </Card>

    <Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>SOAR</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>Dispatch GD security events to your SOAR for automated response.{soar.has_auth_token?" Auth token is set.":""}</M>
      <Input label="Endpoint (https URL)" value={soar.endpoint} placeholder="https://soar.corp.com/ingest" onChange={e=>setSoar({...soar,endpoint:e.target.value})}/>
      <Input label={soar.has_auth_token?"Replace auth token (blank keeps current)":"Auth token (optional)"} type="password" value={soarToken} placeholder="bearer token..." onChange={e=>setSoarToken(e.target.value)}/>
      <Btn small primary disabled={busy} onClick={saveSoar}>Save SOAR</Btn>
    </Card>

    <Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>Alert webhook</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>{webhook.configured?"Currently posting to "+webhook.host+".":"No webhook configured."}</M>
      <Input label="Webhook URL (blank clears)" value={webhookUrl} placeholder="https://hooks.example.com/..." onChange={e=>setWebhookUrl(e.target.value)}/>
      <Btn small primary disabled={busy} onClick={saveWebhook}>Save Webhook</Btn>
    </Card>

    {matrix&&<Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>Alert routing</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>Which channels each severity fans out to (the audit log is always written).</M>
      <table style={{width:"100%",borderCollapse:"collapse",fontSize:10}}>
        <thead><tr><th style={{textAlign:"left",color:C.td,padding:"4px"}}>severity</th>{CHANNELS.map(ch=><th key={ch} style={{color:C.td,padding:"4px"}}>{ch}</th>)}</tr></thead>
        <tbody>{SEVERITIES.map(sev=><tr key={sev}><td style={{color:C.t,padding:"4px"}}>{sev}</td>{CHANNELS.map(ch=><td key={ch} style={{textAlign:"center",padding:"4px"}}><input type="checkbox" checked={!!(matrix[sev]&&matrix[sev][ch])} onChange={()=>toggleMatrix(sev,ch)}/></td>)}</tr>)}</tbody>
      </table>
      <Btn small primary disabled={busy} style={{marginTop:10}} onClick={saveMatrix}>Save Routing</Btn>
    </Card>}

    <Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>Dependency health probes</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>Probe the GD's own dependencies (signing-key store, backup storage, MC trust). Side-effect-free.</M>
      <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={ih.master} onChange={e=>setIh({...ih,master:e.target.checked})}/><M style={{color:C.t}}>Enable probing</M></label>
      {["kms","storage","mc_trust"].map(k=><label key={k} style={{display:"flex",alignItems:"center",gap:8,padding:"3px 0 3px 16px"}}><input type="checkbox" checked={!!(ih.integrations[k]&&ih.integrations[k].enabled)} onChange={e=>setIh({...ih,integrations:{...ih.integrations,[k]:{enabled:e.target.checked}}})}/><M style={{color:C.tm}}>{k}</M></label>)}
      <div style={{display:"flex",gap:8,marginTop:8}}><Btn small primary disabled={busy} onClick={saveIh}>Save</Btn><Btn small disabled={ihRunning} onClick={runIh}>{ihRunning?"Running...":"Run Probe Now"}</Btn></div>
      {ihResults&&ihResults.results&&<div style={{marginTop:10}}>{ihResults.results.map((r,i)=><div key={i} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.t}}>{r.label||r.integration}</M><M style={{color:statusColor(r.status),fontWeight:500}}>{r.status}</M></div>)}</div>}
    </Card>

    <Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>External EDR / endpoint monitoring</div>
      <M style={{color:C.tm,display:"block",marginBottom:8}}>Register an external EDR provider. Credentials are encrypted at rest. The in-platform runtime-monitor provides the host-monitoring baseline regardless.</M>
      {edr.map(it=><div key={it.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><div><M style={{color:C.t,fontWeight:500}}>{it.display_name}</M><M style={{color:C.td,display:"block",fontSize:9}}>{it.provider_type}{it.has_credentials?" - creds set":""}</M></div><div style={{display:"flex",gap:6,alignItems:"center"}}><Badge color={it.enabled?C.a:C.td}>{it.enabled?"enabled":"disabled"}</Badge><Btn small onClick={()=>toggleEdr(it)}>{it.enabled?"Disable":"Enable"}</Btn><Btn small style={{color:C.d,borderColor:C.d+"50"}} onClick={()=>deleteEdr(it)}>Remove</Btn></div></div>)}
      <div style={{marginTop:10,paddingTop:10,borderTop:`1px solid ${C.b}`}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          <Sel label="Provider" value={newEdr.provider_type} onChange={e=>setNewEdr({...newEdr,provider_type:e.target.value})}>{EDR_PROVIDERS.map(pv=><option key={pv} value={pv}>{pv}</option>)}</Sel>
          <Input label="Display name" value={newEdr.display_name} placeholder="Prod Falcon" onChange={e=>setNewEdr({...newEdr,display_name:e.target.value})}/>
          <Input label="Endpoint (optional)" value={newEdr.endpoint} placeholder="https://api.crowdstrike.com" onChange={e=>setNewEdr({...newEdr,endpoint:e.target.value})}/>
          <Input label="Credentials (optional)" type="password" value={newEdr.credentials} placeholder="api key / token" onChange={e=>setNewEdr({...newEdr,credentials:e.target.value})}/>
        </div>
        <Btn small primary disabled={busy} onClick={addEdr}>Add EDR Integration</Btn>
      </div>
    </Card>

    {runtime&&<Card>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>Runtime monitor</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
        <div><div style={{color:C.a,fontWeight:600,fontSize:15}}>{(runtime.cpu==null?0:runtime.cpu)+"%"}</div><M style={{color:C.td}}>CPU</M></div>
        <div><div style={{color:C.i,fontWeight:600,fontSize:15}}>{runtime.memMB==null?0:runtime.memMB}</div><M style={{color:C.td}}>Mem MB</M></div>
        <div><div style={{color:C.p,fontWeight:600,fontSize:15}}>{runtime.fileCount==null?0:runtime.fileCount}</div><M style={{color:C.td}}>FIM files</M></div>
        <div><div style={{color:C.t,fontWeight:600,fontSize:15}}>{runtime.dbReadsPerMin==null?0:runtime.dbReadsPerMin}</div><M style={{color:C.td}}>reads/min</M></div>
      </div>
      {Object.keys(thresholds).length>0&&<M style={{color:C.td,display:"block",marginTop:8}}>Thresholds: {Object.keys(thresholds).map(k=>k+"="+thresholds[k]).join(", ")}</M>}
    </Card>}
  </div>);
}

function GdFidoTrustSection() {
  const dangerBtn = { color: C.d, borderColor: C.d + "50" };
  const [roots, setRoots] = useState(null);
  const [aaguids, setAaguids] = useState(null);
  const [mode, setMode] = useState("");
  const [newRoot, setNewRoot] = useState({vendor:"",label:"",pem:""});
  const [newAaguid, setNewAaguid] = useState({aaguid:"",label:""});
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const r = await api.get("/api/iam/fido-roots");
    setRoots(r && Array.isArray(r.roots) ? r.roots : []);
    const a = await api.get("/api/iam/fido-aaguids");
    setAaguids(a && Array.isArray(a.aaguids) ? a.aaguids : []);
    setMode(a && a.mode ? String(a.mode) : "");
  };
  useEffect(()=>{ load().catch(()=>{}); },[]);

  const addRoot = async () => {
    if (!newRoot.vendor.trim() || !newRoot.label.trim() || !newRoot.pem.trim()) { setMsg("Vendor, label, and root PEM are all required."); return; }
    setBusy(true); setMsg("");
    const r = await api.post("/api/iam/fido-roots", { vendor:newRoot.vendor.trim(), label:newRoot.label.trim(), rootPem:newRoot.pem.trim() });
    setBusy(false);
    if (r && r.added) { setMsg("Trusted attestation root added."); setNewRoot({vendor:"",label:"",pem:""}); load().catch(()=>{}); }
    else { setMsg(r && r.error ? String(r.error) : "Could not add the trusted root."); }
  };
  const removeRoot = async (id) => {
    if (!window.confirm("Remove this trusted attestation root? Keys whose attestation chains only to this root will no longer be accepted at enrollment. At least one root must remain.")) return;
    setMsg("");
    const r = await api.del("/api/iam/fido-roots/" + id);
    if (r && r.removed) { setMsg("Trusted root removed."); load().catch(()=>{}); }
    else { setMsg(r && r.error ? String(r.error) : "Could not remove the trusted root."); }
  };
  const addAaguid = async () => {
    if (!newAaguid.aaguid.trim() || !newAaguid.label.trim()) { setMsg("AAGUID and a model label are required."); return; }
    setBusy(true); setMsg("");
    const r = await api.post("/api/iam/fido-aaguids", { aaguid:newAaguid.aaguid.trim(), label:newAaguid.label.trim() });
    setBusy(false);
    if (r && r.added) { setMsg("Model added to the allow-list."); setNewAaguid({aaguid:"",label:""}); load().catch(()=>{}); }
    else { setMsg(r && r.error ? String(r.error) : "Could not add the AAGUID."); }
  };
  const removeAaguid = async (id) => {
    if (!window.confirm("Remove this model from the allow-list?")) return;
    setMsg("");
    const r = await api.del("/api/iam/fido-aaguids/" + id);
    if (r && r.removed) { setMsg("Model removed from the allow-list."); load().catch(()=>{}); }
    else { setMsg(r && r.error ? String(r.error) : "Could not remove the AAGUID."); }
  };

  return (
    <div>
      <Card style={{marginBottom:12}}>
        <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:8}}>Trusted Attestation Roots</div>
        <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>A passkey is accepted at enrollment only if its attestation certificate chains to one of these trusted vendor roots. Bundled roots ship with FireAlive; add a vendor root (from the vendor's official PKI or the FIDO Alliance metadata service) to accept that vendor's keys. At least one root must always remain.</M>
        {roots===null ? <M style={{color:C.td}}>Loading…</M> : roots.length===0 ? <M style={{color:C.td,display:"block",marginBottom:8}}>No trusted roots. Hardware-key enrollment is refused until at least one is present.</M> : roots.map((r,i)=>(
          <div key={r.id||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
            <div style={{minWidth:0}}>
              <M style={{color:C.t,display:"block"}}>{r.vendor} · {r.label}</M>
              <M style={{color:C.td,display:"block"}}>{r.seeded?"bundled":"admin-added"}{r.sha256?(" · sha256 "+String(r.sha256).slice(0,20)+"…"):""}{r.valid_to?(" · exp "+String(r.valid_to).slice(0,10)):""}</M>
            </div>
            <Btn small style={dangerBtn} onClick={()=>removeRoot(r.id)}>Remove</Btn>
          </div>
        ))}
        <div style={{marginTop:14,paddingTop:12,borderTop:`1px solid ${C.b}`}}>
          <M style={{color:C.t,fontWeight:600,display:"block",marginBottom:8}}>Add a trusted root</M>
          <Input label="Vendor" value={newRoot.vendor} onChange={e=>setNewRoot(p=>({...p,vendor:e.target.value}))} placeholder="e.g. Feitian"/>
          <Input label="Label" value={newRoot.label} onChange={e=>setNewRoot(p=>({...p,label:e.target.value}))} placeholder="e.g. Feitian FIDO Root CA"/>
          <M style={{color:C.tm,marginBottom:4,display:"block"}}>Root certificate (PEM)</M>
          <textarea value={newRoot.pem} onChange={e=>setNewRoot(p=>({...p,pem:e.target.value}))} placeholder="-----BEGIN CERTIFICATE-----" rows={5} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",resize:"vertical",marginBottom:10}}/>
          <Btn primary onClick={addRoot} disabled={busy}>{busy?"Working...":"Add trusted root"}</Btn>
        </div>
      </Card>

      <Card>
        <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:8}}>Model Allow-List (AAGUID)</div>
        <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Optional narrowing. With an empty list, any model from a trusted vendor is accepted{mode?(" (current mode: "+mode+")"):""}. Add AAGUIDs to restrict enrollment to specific authenticator models.</M>
        {aaguids===null ? <M style={{color:C.td}}>Loading…</M> : aaguids.length===0 ? <M style={{color:C.td,display:"block",marginBottom:8}}>No models listed — any model from a trusted vendor is accepted.</M> : aaguids.map((a,i)=>(
          <div key={a.id||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
            <div style={{minWidth:0}}>
              <M style={{color:C.t,display:"block"}}>{a.label}</M>
              <M style={{color:C.td,display:"block",fontFamily:"'IBM Plex Mono',monospace"}}>{a.aaguid}</M>
            </div>
            <Btn small style={dangerBtn} onClick={()=>removeAaguid(a.id)}>Remove</Btn>
          </div>
        ))}
        <Input label="AAGUID" value={newAaguid.aaguid} onChange={e=>setNewAaguid(p=>({...p,aaguid:e.target.value}))} placeholder="ee882879-721c-4913-9775-3dfcf0a8e1c3"/>
        <Input label="Model label" value={newAaguid.label} onChange={e=>setNewAaguid(p=>({...p,label:e.target.value}))} placeholder="e.g. YubiKey 5 Series"/>
        <Btn primary onClick={addAaguid} disabled={busy}>{busy?"Working...":"Add model"}</Btn>
      </Card>
      {msg&&<M style={{color:C.tm,display:"block",marginTop:10}}>{msg}</M>}
    </div>
  );
}

// ── WebAuthn (de)serialization for navigator.credentials ─────────────────────
// The GD-Server speaks base64url JSON (via @simplewebauthn); the browser
// WebAuthn API speaks ArrayBuffers. Convert assertion/creation options in and
// the produced assertion/attestation out.
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
}
function bufToB64url(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function deserializeAuthOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
}
function serializeAssertion(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64url(r.authenticatorData),
      clientDataJSON: bufToB64url(r.clientDataJSON),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
    },
    clientExtensionResults: typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {},
  };
}

// Shared hardware-key MFA step-up (D-stepup). Sensitive server routes gated by
// gdMfaStepUp() require a live, user-verified passkey assertion: fetch a challenge
// from /api/mfa/stepup/options, sign it with the operator's hardware key, and
// resend the sensitive request with body.stepup = { challengeToken, response }.
// Reuses the login flow's deserializeAuthOptions + serializeAssertion. Returns the
// sensitive call's result, or { error } if the step-up could not be completed.
async function stepUp(path, body) {
  const opt = await api.post("/api/mfa/stepup/options");
  if (!opt || opt.error || !opt.options || !opt.challengeToken) {
    return { error: (opt && opt.error) || "Could not start the hardware-key step-up." };
  }
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: deserializeAuthOptions(opt.options) });
  } catch (e) {
    return { error: "Hardware-key step-up was cancelled or failed." };
  }
  return await api.post(path, { ...(body || {}), stepup: { challengeToken: opt.challengeToken, response: serializeAssertion(cred) } });
}
function deserializeRegOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: { ...options.user, id: b64urlToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
}
function serializeAttestation(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64url(r.attestationObject),
      clientDataJSON: bufToB64url(r.clientDataJSON),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [],
    },
    clientExtensionResults: typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {},
  };
}

// ── Passwordless Global Dashboard login ──────────────────────────────────────
// Sign-in is a hardware FIDO2 passkey only (a security key with a PIN); the
// client certificate is transport identity, not a login method. Runs against a
// configurable GD-Server, a one-time CA-trust import (the renderer must trust
// the GD-Server's CA to reach it over HTTPS), and a break-glass panel to enroll
// the first CISO/VP passkey on a fresh deployment using the recovery credential.
function GdLoginScreen({onLoggedIn, firstLaunch, gdServerUrl, setGdServerUrl}) {
  const [error, setError] = useState("");
  // B5e (D25): set when the GD-server fails hardware-anchor attestation (clone)
  const [anchorBlocked, setAnchorBlocked] = useState(null);
  const [busy, setBusy] = useState(false);
  const [caStatus, setCaStatus] = useState(null);   // null=checking; {pinned, unmanaged?}
  const [caPem, setCaPem] = useState("");
  const [caImporting, setCaImporting] = useState(false);
  const [bgOpen, setBgOpen] = useState(false);
  const [bgUsername, setBgUsername] = useState("");
  const [bgRecovery, setBgRecovery] = useState("");
  const [bgBusy, setBgBusy] = useState(false);
  const [bgMsg, setBgMsg] = useState("");

  useEffect(()=>{
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setCaStatus({ pinned: true, unmanaged: true }); return; }
    bridge.invoke("auth:caStatus").then(s=>setCaStatus(s || { pinned: false })).catch(()=>setCaStatus({ pinned: false }));
  },[]);

  const base = () => { api.setBaseUrl((gdServerUrl || "").replace(/\/+$/, "")); };
  // Decode a JWT's cnf binding to distinguish a device-bound session from a
  // first-login bootstrap session (no cnf), which every gated endpoint rejects
  // until this station's device key is registered.
  const isDeviceBound = (token) => {
    try {
      const seg = String(token).split('.')[1];
      if (!seg) return false;
      let b = seg.replace(/-/g, '+').replace(/_/g, '/');
      while (b.length % 4) b += '=';
      const payload = JSON.parse(atob(b));
      return !!(payload && payload.cnf && payload.cnf.jkt);
    } catch (_e) { return false; }
  };

  // Register this station's hardware device key with the GD-Server. Idempotent
  // server-side, and runs on the bootstrap session whose registration endpoint
  // is proof-exempt.
  const registerDeviceKey = async () => {
    const bridge = (typeof window !== 'undefined') ? window.firealive : null;
    if (!bridge || !bridge.invoke) return;
    try {
      const pub = await bridge.invoke('device:getPublicKey');
      if (!pub || !pub.publicKey || !pub.fingerprint) return;
      await api.post('/api/auth/device-key', { publicKey: pub.publicKey, fingerprint: pub.fingerprint });
    } catch (_e) { /* best-effort; a bound login still gates access */ }
  };

  // Build an account-agnostic device-key login proof: fetch a single-use
  // challenge and sign it on-chip. Null when no key is present yet (pre-
  // registration) so the server issues a bootstrap session.
  const buildDeviceKeyProof = async () => {
    const bridge = (typeof window !== 'undefined') ? window.firealive : null;
    if (!bridge || !bridge.invoke) return null;
    try {
      const ch = await api.post('/api/auth/device-key/challenge', {});
      if (!ch || ch.error || !ch.challenge || !ch.challengeToken) return null;
      const signed = await bridge.invoke('device:signLoginChallenge', { challenge: ch.challenge });
      if (!signed || !signed.signature) return null;
      return { challengeToken: ch.challengeToken, signature: signed.signature };
    } catch (_e) { return null; }
  };

  // Finalize a login response. Registers the device key (first login is a
  // cnf-less bootstrap) and returns 'bootstrap' so the caller re-runs the login
  // once for a device-bound token, 'ok' once bound, or 'fail'.
  // B5e (D25): challenge the GD-server to prove control of its hardware instance
  // anchor. Mint a nonce, have the server sign it, and verify via main against the
  // pinned fingerprint. First enrollment pins trust-on-first-use. "ok"/"unpinned"
  // are safe to proceed; "mismatch"/"invalid" must block.
  const verifyServerAnchor = async () => {
    const bridge = (typeof window !== 'undefined') ? window.firealive : null;
    if (!bridge || typeof bridge.invoke !== 'function') return { verdict: 'ok', skipped: true };
    let nonceRes;
    try { nonceRes = await bridge.invoke('anticlone:anchorNonce'); }
    catch (_e) { return { verdict: 'ok', skipped: true }; }
    const nonce = nonceRes && nonceRes.nonce;
    if (!nonce) return { verdict: 'ok', skipped: true };
    const resp = await api.post('/api/instance/anchor-challenge', { nonce: nonce });
    if (!resp || resp.error || !resp.signature || !resp.publicKey || !resp.fingerprint) {
      return { verdict: 'invalid', reason: 'no anchor-challenge response' };
    }
    let v;
    try {
      v = await bridge.invoke('anticlone:verifyAnchor', { nonce: nonce, fingerprint: resp.fingerprint, publicKey: resp.publicKey, signature: resp.signature });
    } catch (_e) {
      return { verdict: 'invalid', reason: 'anchor verification error' };
    }
    if (v && v.verdict === 'unpinned') {
      // B5f (D-B5f-4): first contact pins trust-on-first-use, but only after a
      // blocking operator confirmation. The operator compares this fingerprint
      // out of band with the value the GD server prints at startup; a deliberate
      // confirm pins it, and a declined or failed confirmation refuses.
      let confirm;
      try { confirm = await bridge.invoke('anticlone:confirmAnchorPin', { fingerprint: resp.fingerprint }); }
      catch (_e) { confirm = null; }
      if (!confirm || !confirm.confirmed) {
        return { verdict: 'declined', reason: 'operator did not confirm the GD server anchor fingerprint' };
      }
      let pin;
      try { pin = await bridge.invoke('anticlone:pinAnchor', { fingerprint: resp.fingerprint }); }
      catch (_e) { pin = null; }
      if (!pin || !pin.pinned) {
        return { verdict: 'invalid', reason: (pin && pin.error) ? pin.error : 'anchor pin failed' };
      }
      return { verdict: 'ok', pinned: true };
    }
    return v || { verdict: 'invalid', reason: 'no verdict' };
  };

  const finish = async (r) => {
    if (!r || r.error || !(r.token || r.accessToken) || !r.user) {
      setError(r && typeof r.error === 'string' ? r.error : 'Sign-in failed.');
      return 'fail';
    }
    const token = r.token || r.accessToken;
    api.setToken(token);
    await registerDeviceKey();
    if (!isDeviceBound(token)) return 'bootstrap';
    // B5e (D25): verify the GD-server's hardware anchor before granting access.
    // The session is device-bound here, so the per-request PoP proof is in place;
    // a cloned GD-server cannot sign the anchor nonce and is refused.
    const anchor = await verifyServerAnchor();
    if (anchor && (anchor.verdict === 'mismatch' || anchor.verdict === 'invalid' || anchor.verdict === 'declined')) {
      api.setToken(null);
      setAnchorBlocked({ verdict: anchor.verdict, reason: anchor.reason || null });
      return 'fail';
    }
    onLoggedIn();
    return 'ok';
  };

  const handlePasskeyLogin = async (isRetry) => {
    if (!gdServerUrl || !gdServerUrl.trim()) { setError('Enter the GD-Server URL.'); return; }
    setBusy(true); setError(''); base();
    try {
      const opt = await api.post('/api/auth/login-webauthn/options', {});
      if (!opt || opt.error || !opt.options || !opt.challengeToken) { setBusy(false); setError('Could not start passkey sign-in. Is the GD-Server CA trusted?'); return; }
      let cred;
      try { cred = await navigator.credentials.get({ publicKey: deserializeAuthOptions(opt.options) }); }
      catch (_e) { setBusy(false); setError('Passkey sign-in was cancelled, or no passkey was available.'); return; }
      if (!cred) { setBusy(false); setError('No passkey assertion was produced.'); return; }
      const deviceKeyProof = await buildDeviceKeyProof();
      const r = await api.post('/api/auth/login-webauthn/verify', { response: serializeAssertion(cred), challengeToken: opt.challengeToken, deviceKeyProof });
      setBusy(false);
      const st = await finish(r);
      if (st === 'bootstrap' && !isRetry) return handlePasskeyLogin(true);
    } catch (e) { setBusy(false); setError(e.message || 'Passkey sign-in failed.'); }
  };

  const handleImportCa = async () => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setError("CA import is only available in the desktop app."); return; }
    if (!caPem.trim()) { setError("Paste the GD-Server CA certificate (PEM)."); return; }
    setCaImporting(true); setError("");
    try {
      const res = await bridge.invoke("auth:importCaCert", { pem: caPem.trim() });
      if (!res || !res.ok) { setError(res && res.error ? res.error : "CA import failed."); return; }
      const s = await bridge.invoke("auth:caStatus").catch(()=>null);
      setCaStatus(s || { pinned: true }); setCaPem("");
    } catch (e) { setError(e.message || "CA import failed."); }
    finally { setCaImporting(false); }
  };

  const handleBreakGlassEnroll = async () => {
    if (!gdServerUrl || !gdServerUrl.trim()) { setBgMsg("Enter the GD-Server URL above first."); return; }
    if (!bgUsername.trim() || !bgRecovery.trim()) { setBgMsg("Username and recovery credential are required."); return; }
    setBgBusy(true); setBgMsg(""); base();
    const gate = { recoveryCredential: bgRecovery.trim(), username: bgUsername.trim() };
    try {
      const opt = await api.post("/api/auth/enroll/passkey/options", gate);
      if (!opt || opt.error || !opt.options || !opt.challengeToken) { setBgBusy(false); setBgMsg(opt && opt.error ? String(opt.error) : "Could not start enrollment."); return; }
      let cred;
      try { cred = await navigator.credentials.create({ publicKey: deserializeRegOptions(opt.options) }); }
      catch (_e) { setBgBusy(false); setBgMsg("Passkey creation was cancelled or failed."); return; }
      if (!cred) { setBgBusy(false); setBgMsg("No passkey was created."); return; }
      const r = await api.post("/api/auth/enroll/passkey/verify", { ...gate, response: serializeAttestation(cred), challengeToken: opt.challengeToken });
      setBgBusy(false);
      if (!r || r.error || !r.enrolled) { setBgMsg(r && r.error ? String(r.error) : "Enrollment failed."); return; }
      setBgMsg("Passkey enrolled. You can now sign in with it."); setBgRecovery("");
    } catch (e) { setBgBusy(false); setBgMsg(e.message || "Enrollment failed."); }
  };

  const caUnpinned = caStatus && caStatus.pinned === false;

  if (anchorBlocked) {
    return (
      <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif",padding:20}}>
        <Card style={{maxWidth:520,padding:24,border:"1px solid #7f1d1d"}}>
          <M style={{color:"#fca5a5",fontWeight:700,fontSize:16,display:"block",marginBottom:10}}>{anchorBlocked.verdict === "declined" ? "Server identity not confirmed -- session blocked" : "Server identity check failed -- session blocked"}</M>
          <M style={{color:C.tm,lineHeight:1.6,display:"block",marginBottom:10}}>{anchorBlocked.verdict === "declined" ? "You did not confirm that this GD-Server's anchor fingerprint matches the value provided to you out of band. Until you confirm it, this console will not trust the server." : "This GD-Server could not prove control of its hardware instance anchor. That indicates it was cloned or restored onto different hardware, and this console will not trust it."}</M>
          <M style={{color:C.td,display:"block"}}>{(anchorBlocked.verdict === "declined" ? "Obtain the GD deployment anchor fingerprint from your administrator, then sign in again and confirm it when prompted." : "Do not proceed. Contact your platform administrator and report a possible cloned GD-Server.") + (anchorBlocked.reason ? " Detail: " + anchorBlocked.reason + "." : "")}</M>
        </Card>
      </div>
    );
  }

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <div style={{maxWidth:480,width:"100%",padding:"0 24px"}}>
        <div style={{textAlign:"center",marginBottom:24}}>
          <div style={{fontSize:28,fontWeight:600,color:C.a,fontFamily:"'Fraunces',serif",marginBottom:4}}>FireAlive</div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase"}}>Global Dashboard Login</M>
        </div>
        <Card>
          <Input label="GD-Server URL" value={gdServerUrl} onChange={e=>setGdServerUrl(e.target.value)} placeholder="https://gd.corp.com:4001"/>
          {caUnpinned ? (
            <div>
              <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>Trust the GD-Server CA to connect over HTTPS. Paste the CA certificate (PEM) from the server's /ca-cert endpoint. Done once.</M>
              <textarea value={caPem} onChange={e=>setCaPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" rows={5} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",resize:"vertical",marginBottom:10}}/>
              <Btn primary style={{width:"100%"}} onClick={handleImportCa} disabled={caImporting}>{caImporting?"Importing...":"Import CA certificate"}</Btn>
            </div>
          ) : (
            <div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Sign in with your hardware security key (a FIDO2 passkey with a PIN). There is no password.</M>
              <Btn primary style={{width:"100%"}} onClick={() => handlePasskeyLogin()} disabled={busy}>{busy?"Working...":"Sign in with a passkey"}</Btn>
            </div>
          )}
          {error&&<M style={{color:C.d,display:"block",marginTop:12}}>{error}</M>}
        </Card>
        <Card>
          <button onClick={()=>setBgOpen(o=>!o)} style={{width:"100%",background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",textAlign:"left",fontFamily:"'IBM Plex Mono',monospace"}}>{bgOpen?"\u25be":"\u25b8"} First-time setup / break-glass enrollment</button>
          {bgOpen&&(<div style={{marginTop:12}}>
            <M style={{color:C.td,display:"block",marginBottom:10,lineHeight:1.6}}>Enroll the first CISO/VP passkey on a new deployment using the one-time break-glass recovery credential shown at setup. Requires the operator's username.</M>
            <Input label="Operator username" value={bgUsername} onChange={e=>setBgUsername(e.target.value)} placeholder="ciso"/>
            <Input label="Break-glass recovery credential" value={bgRecovery} onChange={e=>setBgRecovery(e.target.value)} type="password" placeholder="recovery credential"/>
            <Btn primary style={{width:"100%"}} onClick={handleBreakGlassEnroll} disabled={bgBusy}>{bgBusy?"Enrolling...":"Enroll first passkey"}</Btn>
            {bgMsg&&<M style={{color:C.tm,display:"block",marginTop:10}}>{bgMsg}</M>}
          </div>)}
        </Card>
      </div>
    </div>
  );
}

// ── First-run deployment-mode selection (D9) ────────────────────────────────
// Shown once, before login, when no local deployment-mode selection exists.
// The choice is advisory and stored locally (the server's anchor-sealed mode
// is authoritative); it lets the app apply the right virtualization tolerances.
function DeploymentSetup({ onComplete }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [pickSubstrate, setPickSubstrate] = useState(false);
  const choose = async (mode, substrate) => {
    setErr(""); setBusy(true);
    try {
      const bridge = (typeof window !== "undefined") ? window.firealive : null;
      if (!bridge || typeof bridge.invoke !== "function") { onComplete(); return; }
      const r = await bridge.invoke("deployment:setLocalMode", { mode: mode, substrate: substrate });
      if (r && r.error) { setErr(r.error); setBusy(false); return; }
      onComplete();
    } catch (e) {
      setErr(e && e.message ? e.message : "could not save selection");
      setBusy(false);
    }
  };
  const card = (key, title, desc, onClick) => (
    <button key={key} onClick={onClick} disabled={busy} style={{textAlign:"left",padding:"18px 20px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10,color:C.t,cursor:busy?"default":"pointer",opacity:busy?0.6:1,display:"flex",flexDirection:"column",gap:6,maxWidth:420}}>
      <span style={{fontSize:13,fontWeight:600,color:C.t}}>{title}</span>
      <M style={{color:C.tm,fontSize:10,lineHeight:1.5}}>{desc}</M>
    </button>
  );
  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:18,padding:24}}>
      {!pickSubstrate ? (
        <>
          <div style={{textAlign:"center",display:"flex",flexDirection:"column",gap:8,maxWidth:460}}>
            <M style={{color:C.a,fontSize:11,letterSpacing:1}}>FIREALIVE SETUP</M>
            <div style={{color:C.t,fontSize:20,fontWeight:600}}>Select deployment mode</div>
            <M style={{color:C.tm,fontSize:11,lineHeight:1.6}}>Choose how this deployment runs. This sets local virtualization tolerances and is confirmed against the server.</M>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {card("bare-metal","Bare metal","Dedicated physical hardware. Strictest identity enforcement; no live-migration allowances.",()=>choose("bare-metal"))}
            {card("virtualized","Virtualized","Runs in a VM or hypervisor. Allows authorized live migration (vMotion) while still refusing clones.",()=>choose("virtualized"))}
            {card("cloud","Cloud","Confidential VM on AWS, Azure, or GCP with a vTPM root of trust. Requires confidential computing, attested at boot; refuses spot and autoscaled instances.",()=>choose("cloud"))}
            {card("sdn","SDN","Software-defined network spanning multiple sites or clouds. Integrates read-only with the SDN controller; admits FireAlive's own components only from the permitted network segments.",()=>{setErr("");setPickSubstrate("sdn");})}
            {card("sase","SASE / ZTNA","Private (dark) application behind your organization's ZTNA/SASE edge. Reachable only through the connector, with FireAlive's device-bound mTLS preserved end-to-end; refuses clientless TLS-terminating access.",()=>{setErr("");setPickSubstrate("sase");})}
          </div>
        </>
      ) : (
        <>
          <div style={{textAlign:"center",display:"flex",flexDirection:"column",gap:8,maxWidth:460}}>
            <M style={{color:C.a,fontSize:11,letterSpacing:1}}>{"FIREALIVE SETUP / " + (pickSubstrate === "sase" ? "SASE" : "SDN")}</M>
            <div style={{color:C.t,fontSize:20,fontWeight:600}}>{"What does the " + (pickSubstrate === "sase" ? "SASE" : "SDN") + " host run on?"}</div>
            <M style={{color:C.tm,fontSize:11,lineHeight:1.6}}>The substrate sets this host's identity and snapshot tolerances. It is confirmed against the server, which fails closed if the declared substrate is weaker than what it detects.</M>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {card(pickSubstrate + "-bare-metal","Bare metal","Dedicated physical hardware with a hardware TPM. Strictest identity enforcement; no snapshot or live-migration allowances.",()=>choose(pickSubstrate,"bare-metal"))}
            {card(pickSubstrate + "-virtualized","Virtualized","A VM or hypervisor with a vTPM. Adds snapshot and clock-jump tolerances; quarantines a host that looks cloned or rolled back.",()=>choose(pickSubstrate,"virtualized"))}
            {card(pickSubstrate + "-cloud","Cloud","A confidential VM on AWS, Azure, or GCP. Requires confidential computing, attested at boot; refuses spot and autoscaled instances.",()=>choose(pickSubstrate,"cloud"))}
          </div>
          <button onClick={()=>{setErr("");setPickSubstrate(false);}} disabled={busy} style={{background:"none",border:"none",color:C.tm,fontSize:10,cursor:busy?"default":"pointer",textDecoration:"underline",padding:4}}>Back to deployment mode</button>
        </>
      )}
      {err && <M style={{color:C.d,fontSize:10}}>{err}</M>}
    </div>
  );
}

export default function GlobalDashboard() {
  const [stage, setStage] = useState("login");
  const [deployMode, setDeployMode] = useState(undefined); // undefined = checking
  useEffect(()=>{
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || typeof bridge.invoke !== "function") { setDeployMode({ configured: true, unmanaged: true }); return; }
    bridge.invoke("deployment:getLocalMode")
      .then(d=>setDeployMode(d || { configured: false }))
      .catch(()=>setDeployMode({ configured: true, unmanaged: true }));
  },[]);
  const [gdServerUrl, setGdServerUrl] = useState("https://localhost:4001");
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
  const [gdVersion, setGdVersion] = useState(null);
  const [gdToast, setGdToast] = useState(null);
  const showGdToast = (msg) => { setGdToast(msg); setTimeout(() => setGdToast(null), 3000); };
  const [updCfg, setUpdCfg] = useState({enabled:false,frequency:"weekly",dayOfWeek:1,dayOfMonth:1,timeUtc:"03:00"});
  const [updStatus, setUpdStatus] = useState(null); // {currentVersion,enabled,updateAvailable,latestVersion,releaseUrl,lastCheckedAt,lastResult}
  const [updCheck, setUpdCheck] = useState(null); // check-now result: null | "checking" | {result,...} | {error}
  const [updSaving, setUpdSaving] = useState(false);
  const [updBannerDismissed, setUpdBannerDismissed] = useState(()=>{ try { return localStorage.getItem("fa_gd_upd_dismissed")||""; } catch(_e){ return ""; } });
  // R3k C40 — GD Cloud & IaC + CI/CD server-side wiring
  const [gdIacProvider, setGdIacProvider] = useState("");
  const [gdIacTool, setGdIacTool] = useState("");
  const [gdIacResult, setGdIacResult] = useState(null);
  const [gdIacBusy, setGdIacBusy] = useState(false);
  const [gdCloudModeProvider, setGdCloudModeProvider] = useState("");
  const [gdCloudModeDns, setGdCloudModeDns] = useState("");
  // ── B1: Cloud Vulnerability Scan — GD-server's own scanner authorizations + scan-access log ──
  const CLOUD_VULN_SCANNERS = [
    {id:"scoutsuite",l:"ScoutSuite",d:"Multi-cloud posture auditing (AWS, Azure, GCP, OCI)"},
    {id:"prowler",l:"Prowler",d:"AWS/Azure/GCP CIS benchmark checks"},
    {id:"pacu",l:"Pacu",d:"AWS exploitation framework — offensive posture testing"},
    {id:"cloudbrute",l:"CloudBrute",d:"Cloud asset enumeration across providers"},
    {id:"checkov",l:"Checkov",d:"IaC scanning — Terraform, CloudFormation, K8s manifests"},
  ];
  const [cvList, setCvList] = useState([]);
  const [cvLoading, setCvLoading] = useState(false);
  const [cvError, setCvError] = useState(null);
  const [cvForm, setCvForm] = useState(null); // {mode:'add'|'edit', id?, scanner_type, display_name, allowed_cidrs(text), notes, enabled}
  const [cvNewToken, setCvNewToken] = useState(null); // one-time bearer token shown after create
  const [cvLog, setCvLog] = useState([]);
  const [cvLogTotal, setCvLogTotal] = useState(0);
  const [cvChain, setCvChain] = useState(null); // {intact, count, brokenAt?}
  const reloadCloudVuln = async () => {
    setCvLoading(true); setCvError(null);
    try {
      const r = await api.get("/api/cloud-vuln/authorizations");
      if (r && Array.isArray(r.authorizations)) setCvList(r.authorizations);
      else if (r && r.error) setCvError(r.error);
      const lg = await api.get("/api/cloud-vuln/access-log?limit=100");
      if (lg && Array.isArray(lg.entries)) { setCvLog(lg.entries); setCvLogTotal(lg.total||lg.entries.length); }
    } catch (e) { setCvError(e.message); }
    setCvLoading(false);
  };
  useEffect(() => { reloadCloudVuln(); }, []);
  const [gdCicdPlatform, setGdCicdPlatform] = useState("github-actions");
  const [gdCicdPurpose, setGdCicdPurpose] = useState("custom-build");
  const [gdCicdResult, setGdCicdResult] = useState(null);
  const [gdCicdBusy, setGdCicdBusy] = useState(false);
  const GD_IAC_TOOLS_BY_PROVIDER = {
    aws:   ["terraform","pulumi","cloudformation"],
    azure: ["terraform","pulumi","bicep"],
    gcp:   ["terraform","pulumi","gcp-dm"],
  };
  const GD_CLOUD_MODE_LABELS = { aws:"AWS (SEV-SNP + NitroTPM)", azure:"Azure Confidential VM (Trusted Launch)", gcp:"GCP Confidential VM (Shielded VM)" };
  // R3k C41 — GD Full-suite backup wiring
  const [gdBackupBusy, setGdBackupBusy] = useState(false);
  const [gdBackupResult, setGdBackupResult] = useState(null);
  const [gdBackupStrategy, setGdBackupStrategy] = useState("v2");
  const [gdBackups, setGdBackups] = useState([]);
  const [gdVerifyResults, setGdVerifyResults] = useState({});
  const [erSources, setErSources] = useState([]);
  const [erSelSrc, setErSelSrc] = useState("");
  const [erBackups, setErBackups] = useState([]);
  const [erPreview, setErPreview] = useState(null);
  const [erApproval, setErApproval] = useState(null);
  const [erReason, setErReason] = useState("");
  const [restorePoints, setRestorePoints] = useState([]);
  const [rpPreview, setRpPreview] = useState(null);
  const [bskKeys, setBskKeys] = useState([]);
  const [bskShowAdd, setBskShowAdd] = useState(false);
  const [bskPasteText, setBskPasteText] = useState("");
  const [bskLabel, setBskLabel] = useState("");
  const [configSnapshots, setConfigSnapshots] = useState([]);
  const [cbRetention, setCbRetention] = useState(null);
  const [cbBusy, setCbBusy] = useState(false);
  const [cbDiff, setCbDiff] = useState(null);
  const loadConfigBaseline = async () => {
    const r = await api.get("/api/config-baseline");
    if (!r.error) { setConfigSnapshots(r.snapshots || []); setCbRetention(r.retention != null ? r.retention : null); }
  };
  const addA = (event, detail) => setGdAudit(a => [{ ts: new Date().toISOString(), event: event, detail: detail }, ...a]);
  const [gdVerifyingId, setGdVerifyingId] = useState(null);
  const [gdChain, setGdChain] = useState(null);
  const [gdChainVerify, setGdChainVerify] = useState(null);
  const [gdChainBusy, setGdChainBusy] = useState(false);
  const [dataSov, setDataSov] = useState(null);
  const [dataSovCfg, setDataSovCfg] = useState(null);
  const [dataSovSaving, setDataSovSaving] = useState(false);
  const [dataSovMsg, setDataSovMsg] = useState(null);
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
  // R3l C34: Forensic Export — vp creates, ciso (separate-actor) deletes.
  // Server returns 403 to non-vp POST and to non-ciso or same-actor DELETE.
  const [forensicForm, setForensicForm] = useState({
    rationale: '',
    timeWindowStart: '',
    timeWindowEnd: '',
    eventTypeFilter: '',
    outputFormats: ['json-lines', 'csv'],
    includeAuditLog: true,
    includeBackupChain: true,
    includeIncidentRecords: true,
    includeAuthenticationLogs: true,
    includeUserAccessLogs: true,
  });
  const [forensicCreateInFlight, setForensicCreateInFlight] = useState(false);
  const [forensicCreateError, setForensicCreateError] = useState(null);
  const [forensicCreateResult, setForensicCreateResult] = useState(null);
  const [forensicExports, setForensicExports] = useState([]);
  const [forensicLoadState, setForensicLoadState] = useState({ loaded: false, error: null });
  const [forensicChain, setForensicChain] = useState(null);
  const [forensicChainOpen, setForensicChainOpen] = useState(false);
  const [forensicManifest, setForensicManifest] = useState(null);
  const [forensicManifestOpen, setForensicManifestOpen] = useState(false);
  const [forensicDeleteInFlight, setForensicDeleteInFlight] = useState({});
  const [forensicDeleteError, setForensicDeleteError] = useState(null);
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
  const [logIntegrity, setLogIntegrity] = useState(null);
  const [logIntegrityLoading, setLogIntegrityLoading] = useState(false);
  // Regions — loaded from GD-Server's GET /api/metrics/global on app entry.
  // The GD-Server's response shape uses snake_case columns from the SQLite
  // regional_metrics table; we map to the camelCase shape the rest of the
  // UI expects so the views below didn't have to change.
  const [regions, setRegions] = useState([]);
  const [regionsLoading, setRegionsLoading] = useState(false);
  const [regionsError, setRegionsError] = useState(null);

  // Compliance Posture tab — fetches THIS GD's own compliance report
  // per-framework via PR2's GET /api/compliance/report/:framework.
  // Selector + fetch state added in C2; rendering of summary +
  // verifiedControls + customerResponsibility lands in C3-C4.
  const [postureFramework, setPostureFramework] = useState("");
  const [postureReport, setPostureReport] = useState(null);
  const [postureLoading, setPostureLoading] = useState(false);
  const [postureError, setPostureError] = useState(null);

  // Cross-Region Compliance tab — fetches the framework x MC rollup
  // matrix via PR3 C37's GET /api/compliance/rollup. The endpoint returns
  // a flat list of {framework, mc_id, mc_name, region, passed, total,
  // last_push_at, has_drilldown} cells; the UI groups by framework for
  // the matrix display. per_control_status is deliberately excluded
  // from this endpoint per the layered payload-size pattern (PR3 lock);
  // drilldown into per-control detail comes via C38/C39 endpoints which
  // are wired in C7-C8 of PR4. Filter controls (framework/mc_id/region)
  // are added in C6.
  const [rollupData, setRollupData] = useState(null);
  const [rollupLoading, setRollupLoading] = useState(false);
  const [rollupError, setRollupError] = useState(null);
  // Filters for the Cross-Region matrix (added in C6). Empty string means
  // "no filter on this axis." Applied client-side against the unfiltered
  // rollupData so the dropdown option sets stay stable across filter
  // changes — selecting one filter never hides another filter's options.
  // The C37 endpoint also accepts these as query params for future
  // programmatic / shareable-URL access; client-side filtering is the
  // C6 implementation since rollupData is small (max ~800 cells for 50
  // MCs x 16 frameworks).
  const [rollupFilterFramework, setRollupFilterFramework] = useState("");
  const [rollupFilterMcId, setRollupFilterMcId] = useState("");
  const [rollupFilterRegion, setRollupFilterRegion] = useState("");

  // ── R3h: Helper Recognition leaderboard state ────────────────────────────
  // hrMatrix is the cross-MC aggregation from GET /api/leaderboard/regional —
  // one entry per active MC with that MC's top-10 opted-in helpers inline.
  // hrDrilldownMcId, when non-null, switches the tab body to the per-MC
  // drilldown view fetched from GET /api/leaderboard/mc/:id (returns the
  // full top-50 plus signature_fingerprint for forensic display). The
  // drilldown is dismissed by setting hrDrilldownMcId back to null,
  // returning the user to the matrix view.
  const [hrMatrix, setHrMatrix] = useState(null);
  const [hrMatrixLoading, setHrMatrixLoading] = useState(false);
  const [hrMatrixError, setHrMatrixError] = useState(null);
  const [hrDrilldownMcId, setHrDrilldownMcId] = useState(null);
  const [hrDrilldownData, setHrDrilldownData] = useState(null);
  const [hrDrilldownLoading, setHrDrilldownLoading] = useState(false);
  const [hrDrilldownError, setHrDrilldownError] = useState(null);

  // Per-cell full-report metadata list (added in C7). Clicking a matrix
  // row sets selectedCell to {mc_id, framework}; the useEffect below
  // fires PR3 C38's GET /api/mc/:id/full-reports?framework=<fw> and the
  // result is rendered inline beneath the clicked row. Clicking the same
  // row again clears selectedCell (toggle). report_json bodies are
  // deliberately excluded from C38's response per the layered payload-
  // size pattern; per-report detail (the actual control body) is
  // fetched by C8 via C39 when the user clicks a specific report row.
  const [selectedCell, setSelectedCell] = useState(null);
  const [reportsList, setReportsList] = useState(null);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [reportsError, setReportsError] = useState(null);

  // Per-report parsed body (added in C8). Clicking a report row in the
  // C7 expansion sets selectedReportId; the useEffect below fires PR3
  // C39's GET /api/mc/:id/full-reports/:reportId and the parsed body
  // renders inline beneath the clicked report row. C39 is the ONLY
  // endpoint that returns the report_json payload (C37/C38 exclude it
  // per the layered payload-size pattern). The parsed body has the
  // same shape Phase 1 renders for THIS GD's own posture — framework
  // header, 4-up summary, verifiedControls list with status badges,
  // customerResponsibility list — but reads from a stored MC report
  // rather than a live generation. selectedReportId is cleared when
  // selectedCell changes (different cell = different report list,
  // so no carry-over).
  const [selectedReportId, setSelectedReportId] = useState(null);
  const [reportDetail, setReportDetail] = useState(null);
  const [reportDetailLoading, setReportDetailLoading] = useState(false);
  const [reportDetailError, setReportDetailError] = useState(null);

  // Mailbox-pattern Request Full Report flow (added in C9). Clicking
  // the per-cell Request Full Report button POSTs PR3 C33's
  // /api/mc/:id/full-report-requests with body {framework}; on 201
  // success the requestId + requested_at are recorded in
  // submittedRequests so the cell's panel immediately renders a
  // "request pending fulfillment" state. The MC observes the pending
  // row on its next compliance tick (default 24h cadence) and pushes
  // the fulfillment via the mailbox-pattern flow; the fulfillment
  // shows up in the C7 reports list on next refresh. submittedRequests
  // is in-memory only — refreshing the GD or switching tabs and back
  // resets to whatever the next C5 rollup fetch reports.
  const [submittingFullReport, setSubmittingFullReport] = useState(false);
  const [submittedRequests, setSubmittedRequests] = useState([]);
  const [submitFullReportError, setSubmitFullReportError] = useState(null);

  // Signing-key admin queue (added in C11). Renders at the top of the
  // MC Connections tab as a cross-MC "Pending Signing Key Approvals"
  // card sourced from PR3 C20's GET /api/signing-keys/pending. Each
  // entry: {id, mcId, mcName, fingerprint, submittedAt}. The endpoint
  // is gated to ['ciso', 'signing_key_approver'] roles — VP and
  // readonly users get a 403 which surfaces as the error message.
  // Approve / reject actions on individual entries land in C13 + C14.
  const [pendingKeys, setPendingKeys] = useState(null);
  const [pendingKeysLoading, setPendingKeysLoading] = useState(false);
  const [pendingKeysError, setPendingKeysError] = useState(null);

  // Per-MC signing-keys history panel (added in C12). Clicking the
  // "View keys" affordance on a connections-tab MC row toggles the
  // expansion and fetches PR3 C20's other surface
  // GET /api/mc/:id/signing-keys. Returns the FULL key history for
  // that MC — approved, pending, AND rejected rows, with their
  // approved_at / rotated_out_at / approved_by_role / rejected_at /
  // rejected_reason metadata. This is the ONLY UI surface where
  // rejected_reason is exposed — the MC-facing status endpoint (C21)
  // strips it per the privacy invariant. Single-open pattern: only
  // one MC's keys panel is open at a time (clicking a second one
  // closes the first).
  const [expandedMcKeysFor, setExpandedMcKeysFor] = useState(null);
  const [mcKeysData, setMcKeysData] = useState(null);
  const [mcKeysLoading, setMcKeysLoading] = useState(false);
  const [mcKeysError, setMcKeysError] = useState(null);

  // Approve-action in-flight tracker (added in C13). Holds the keyId
  // of the currently-approving key so the Approve button on that
  // specific row can disable itself during the POST; other Approve
  // buttons in the queue or per-MC panel remain interactive. Cleared
  // on settle (success or error). approveError surfaces the last
  // server-side failure message (e.g. CONFIRMATION_FINGERPRINT_MISMATCH
  // when the optional double-check fingerprint disagrees with the
  // stored value; INVALID_STATE on a duplicate-click race; etc.).
  const [approvingKeyId, setApprovingKeyId] = useState(null);
  const [approveError, setApproveError] = useState(null);

  // Reject-action modal state (added in C14). Reject is a destructive
  // permanent state transition that captures a free-form rationale —
  // window.confirm cannot host a multi-line textarea so the reject
  // flow uses an inline modal overlay instead. rejectModalKey holds
  // the target row context ({mcId, keyId, fingerprint, mcName}) while
  // the modal is open; null when closed. rejectReason is the textarea
  // value. rejecting gates the Submit button during the POST.
  // rejectErrorInline surfaces server-side validation failures
  // (INVALID_REASON for empty/over-cap reasons; INVALID_STATE for
  // race conditions) inside the modal so the operator can correct
  // and retry without losing their typed reason.
  const [rejectModalKey, setRejectModalKey] = useState(null);
  const [rejectReason, setRejectReason] = useState("");
  const [rejecting, setRejecting] = useState(false);
  const [rejectErrorInline, setRejectErrorInline] = useState(null);

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
    api.get('/api/backup').then(r => {
      if (r && !r.error) setGdBackups(r.backups || []);
    });
    api.get('/api/backup/chain').then(r => {
      if (r && !r.error) setGdChain(r);
    });
  }, [stage, tab]);

  // Load the live data-residency posture and the editable policy config when the
  // Data Sovereignty tab is active.
  useEffect(() => {
    if (stage !== "app" || tab !== "data_sov") return;
    api.get('/api/data-residency/posture').then(r => {
      if (r && !r.error) setDataSov(r);
    });
    api.get('/api/data-residency/config').then(r => {
      if (r && !r.error) setDataSovCfg(r);
    });
  }, [stage, tab]);

  // Update one category's mode or permitted regions in the editable policy.
  const setDataSovCat = (cat, field, value) => setDataSovCfg(cfg => ({
    ...cfg,
    categories: { ...(cfg.categories || {}), [cat]: { ...((cfg.categories || {})[cat] || {}), [field]: value } },
  }));

  // Save the edited policy, then refresh the posture so the verdicts below update.
  const saveDataSovCfg = async () => {
    if (!dataSovCfg) return;
    setDataSovSaving(true); setDataSovMsg(null);
    const r = await api.put('/api/data-residency/config', dataSovCfg);
    if (r.error) {
      setDataSovMsg({ ok: false, text: r.message || r.error });
    } else {
      setDataSovMsg({ ok: true, text: 'Policy saved.' });
      const p = await api.get('/api/data-residency/posture');
      if (p && !p.error) setDataSov(p);
    }
    setDataSovSaving(false);
  };

  // Verify a single backup: the server re-hashes the archive and manifest and checks
  // the Ed25519 signature, returning verified / tampered / missing.
  const verifyGdBackup = async (id) => {
    setGdVerifyingId(id);
    const r = await api.post(`/api/backup/${id}/verify`, {});
    setGdVerifyResults(prev => ({ ...prev, [id]: r && r.error ? { status: 'error', message: r.message || r.error } : r }));
    setGdVerifyingId(null);
  };

  // Verify the whole attestation chain: hash linkage plus each entry's signature.
  const verifyGdChain = async () => {
    setGdChainBusy(true); setGdChainVerify(null);
    const r = await api.post('/api/backup/chain/verify', {});
    setGdChainVerify(r && r.error ? { ok: false, reason: r.message || r.error } : r);
    setGdChainBusy(false);
  };

  // Load the GD-Server app version once the app is entered (any role), so the
  // header, footer, and App Updates view show the live shipped version instead
  // of a hardcoded string. Runs once when the app stage is reached.
  useEffect(() => {
    if (stage !== "app" || gdVersion) return;
    api.get("/api/system/version").then(r => {
      if (r && !r.error && r.version) setGdVersion(r.version);
    });
  }, [stage, gdVersion]);

  // B5r: load the update schedule config + current status once the app is
  // entered, so the App Updates tab and the update-available banner reflect
  // server state. Detect-and-notify only; nothing is downloaded or installed.
  useEffect(() => {
    if (stage !== "app") return;
    api.get("/api/auto-update/config").then(r => { if (r && r.config) setUpdCfg(pr => ({ ...pr, ...r.config })); });
    api.get("/api/auto-update/status").then(r => { if (r && !r.error) setUpdStatus(r); });
  }, [stage]);

  const gdCheckUpdate = async () => {
    setUpdCheck("checking");
    try {
      const r = await api.post("/api/auto-update/check-now", {});
      setUpdCheck(r && !r.error ? r : (r || { result: "source_unreachable" }));
      api.get("/api/auto-update/status").then(s => { if (s && !s.error) setUpdStatus(s); });
    } catch (e) {
      setUpdCheck({ result: "source_unreachable" });
    }
  };
  const gdSaveUpdCfg = async () => {
    setUpdSaving(true);
    try {
      const r = await api.put("/api/auto-update/config", updCfg);
      if (r && r.error) { showGdToast("Save failed: " + r.error); }
      else { if (r && r.config) setUpdCfg(pr => ({ ...pr, ...r.config })); showGdToast("Update schedule saved"); }
    } catch (e) {
      showGdToast("Save failed");
    } finally { setUpdSaving(false); }
  };

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
    // Cross-MC pending signing-key approval queue (PR3 C20, added in
    // PR4 C11). Endpoint is gated to ['ciso','signing_key_approver'].
    // A VP or readonly user landing on the connections tab will see
    // the queue's error state ("403 forbidden" or equivalent) rather
    // than a populated list — by design; trust-registry read access
    // is scoped tighter than the connection-management surface.
    setPendingKeysLoading(true);
    setPendingKeysError(null);
    api.get('/api/signing-keys/pending').then(r => {
      if (r && !r.error && Array.isArray(r.pending)) {
        setPendingKeys(r.pending);
      } else {
        setPendingKeysError(r?.error || 'Failed to load pending signing-key approvals');
      }
    }).finally(() => setPendingKeysLoading(false));
  }, [stage, tab]);

  // Per-MC signing-keys history fetch (PR4 C12). Fires whenever the
  // operator expands a different MC's keys panel; resets when the
  // panel is collapsed. Cleared on tab leave by the cleanup effect
  // below so re-entering connections starts with no panel open.
  useEffect(() => {
    if (!expandedMcKeysFor) {
      setMcKeysData(null);
      setMcKeysError(null);
      return;
    }
    setMcKeysLoading(true);
    setMcKeysError(null);
    setMcKeysData(null);
    const url = '/api/mc/' + encodeURIComponent(expandedMcKeysFor) + '/signing-keys';
    api.get(url).then(r => {
      if (r && !r.error && Array.isArray(r.keys)) {
        setMcKeysData(r);
      } else {
        setMcKeysError(r?.error || 'Failed to load signing-key history');
      }
    }).finally(() => setMcKeysLoading(false));
  }, [expandedMcKeysFor]);

  // Collapse the per-MC keys panel when leaving the connections tab
  // so re-entering the tab starts clean. The data fetched is small
  // and re-fetching on next expand is fine.
  useEffect(() => {
    if (tab !== "connections" && expandedMcKeysFor !== null) {
      setExpandedMcKeysFor(null);
    }
  }, [tab, expandedMcKeysFor]);

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

  // B5a: auto-verify the audit-log hash chain once when the Audit tab opens.
  // The verify endpoint also advances the signed checkpoint; the Verify Now
  // button on the Log Integrity card re-runs it on demand.
  useEffect(() => {
    if (stage !== "app" || tab !== "audit_dash") return;
    if (logIntegrity !== null || logIntegrityLoading) return;
    setLogIntegrityLoading(true);
    api.get("/api/audit/integrity").then(r => setLogIntegrity(r || null)).finally(() => setLogIntegrityLoading(false));
  }, [stage, tab]);

  // R3l C34: Tab-gated forensic-export list fetch.
  useEffect(() => {
    if (stage !== "app" || tab !== "forensic_exports") return;
    let cancelled = false;
    api.get('/api/forensic-exports').then((r) => {
      if (cancelled) return;
      if (!r || r.error) {
        setForensicLoadState({ loaded: false, error: (r && r.error) || 'request_failed' });
        return;
      }
      setForensicExports(Array.isArray(r.exports) ? r.exports : []);
      setForensicLoadState({ loaded: true, error: null });
    }).catch((e) => {
      if (cancelled) return;
      setForensicLoadState({ loaded: false, error: (e && e.message) || 'request_failed' });
    });
    return () => { cancelled = true; };
  }, [stage, tab]);

  const ALL_FORENSIC_FORMATS = [
    'sleuth-kit-bodyfile', 'json-lines', 'plaso-l2t-csv',
    'cef', 'evtx-xml', 'stix-21', 'dfxml', 'csv',
  ];
  const toggleForensicFormat = (fmt) => {
    setForensicForm((prev) => {
      const has = prev.outputFormats.includes(fmt);
      return { ...prev, outputFormats: has ? prev.outputFormats.filter((f) => f !== fmt) : [...prev.outputFormats, fmt] };
    });
  };
  const submitForensicExport = async () => {
    if (forensicCreateInFlight) return;
    if (!forensicForm.outputFormats || forensicForm.outputFormats.length === 0) {
      setForensicCreateError('Select at least one output format');
      return;
    }
    setForensicCreateInFlight(true);
    setForensicCreateError(null);
    setForensicCreateResult(null);
    try {
      const body = {
        rationale: forensicForm.rationale || null,
        timeWindowStart: forensicForm.timeWindowStart || null,
        timeWindowEnd: forensicForm.timeWindowEnd || null,
        eventTypeFilter: forensicForm.eventTypeFilter || null,
        outputFormats: forensicForm.outputFormats,
        includeAuditLog: forensicForm.includeAuditLog,
        includeBackupChain: forensicForm.includeBackupChain,
        includeIncidentRecords: forensicForm.includeIncidentRecords,
        includeAuthenticationLogs: forensicForm.includeAuthenticationLogs,
        includeUserAccessLogs: forensicForm.includeUserAccessLogs,
      };
      const r = await api.post('/api/forensic-exports', body);
      if (!r || r.error) {
        setForensicCreateError((r && r.error) || 'request_failed');
      } else {
        setForensicCreateResult(r);
        const refresh = await api.get('/api/forensic-exports');
        if (refresh && !refresh.error && Array.isArray(refresh.exports)) {
          setForensicExports(refresh.exports);
        }
      }
    } catch (e) {
      setForensicCreateError((e && e.message) || 'request_failed');
    } finally {
      setForensicCreateInFlight(false);
    }
  };
  const downloadForensicArchive = async (id) => {
    await api.download('/api/forensic-exports/' + encodeURIComponent(id) + '/download', 'firealive-gd-forensic-' + id + '.tar.gz');
  };
  const viewForensicManifest = async (id) => {
    setForensicManifest(null);
    setForensicManifestOpen(true);
    const r = await api.get('/api/forensic-exports/' + encodeURIComponent(id) + '/manifest');
    setForensicManifest(r);
  };
  const viewForensicChain = async () => {
    setForensicChain(null);
    setForensicChainOpen(true);
    const r = await api.get('/api/forensic-exports/chain');
    setForensicChain(r);
  };
  const deleteForensicExport = async (id) => {
    if (forensicDeleteInFlight[id]) return;
    if (!window.confirm('Delete forensic export ' + id + '? This is irreversible (the chain entry is preserved). CISO role required and you must NOT be the original VP requester (separate-actor enforcement).')) return;
    setForensicDeleteInFlight((prev) => ({ ...prev, [id]: true }));
    setForensicDeleteError(null);
    try {
      const r = await api.del('/api/forensic-exports/' + encodeURIComponent(id));
      if (!r || r.error) {
        setForensicDeleteError((r && r.error) || 'request_failed');
      } else {
        const refresh = await api.get('/api/forensic-exports');
        if (refresh && !refresh.error && Array.isArray(refresh.exports)) {
          setForensicExports(refresh.exports);
        }
      }
    } catch (e) {
      setForensicDeleteError((e && e.message) || 'request_failed');
    } finally {
      setForensicDeleteInFlight((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  };

  // Load region drilldown history whenever drilldownMcId changes.
  useEffect(() => {
    if (stage !== "app" || !drilldownMcId) return;
    setDrilldownLoading(true);
    setDrilldownData(null);
    api.get('/api/metrics/history/' + drilldownMcId + '?days=30').then(r => {
      if (r && !r.error && r.history) setDrilldownData(r.history);
    }).finally(() => setDrilldownLoading(false));
  }, [stage, drilldownMcId]);

  // Load cross-region rollup matrix when the Cross-Region Compliance
  // tab is active. The endpoint returns active MCs only (server-side
  // JOIN filter on status='active'); offboarded MCs' historical rollup
  // rows are excluded server-side and stay out of the heat-map view.
  // Filter controls (framework / mc_id / region) wire in C6 and will
  // pass query params to the same endpoint.
  useEffect(() => {
    if (stage !== "app" || tab !== "compliance_xregion") return;
    setRollupLoading(true);
    setRollupError(null);
    api.get('/api/compliance/rollup').then(r => {
      if (r && !r.error && Array.isArray(r.rollups)) {
        setRollupData(r.rollups);
      } else {
        setRollupError(r?.error || 'Failed to load cross-region rollup');
      }
    }).finally(() => setRollupLoading(false));
  }, [stage, tab]);

  // R3h: Load Helper Recognition matrix when the tab is active. Returns
  // one entry per active MC with that MC's top-10 inline (limit=10 is
  // the default; client could pass ?limit=N for a wider view in a future
  // iteration). The matrix view is the primary surface; drilldown into
  // a specific MC is triggered by clicking the MC's card.
  useEffect(() => {
    if (stage !== "app" || tab !== "helper_recognition") return;
    setHrMatrixLoading(true);
    setHrMatrixError(null);
    api.get('/api/leaderboard/regional?limit=10').then(r => {
      if (r && !r.error && Array.isArray(r.matrix)) {
        setHrMatrix(r.matrix);
      } else {
        setHrMatrixError(r?.error || 'Failed to load Helper Recognition matrix');
      }
    }).finally(() => setHrMatrixLoading(false));
  }, [stage, tab]);

  // R3h: Load per-MC drilldown when hrDrilldownMcId is set. Endpoint
  // returns the full top-50 for the MC plus the signature_fingerprint
  // on each row for forensic provenance display. Setting hrDrilldown
  // McId to null returns the user to the matrix view without firing
  // another fetch.
  useEffect(() => {
    if (stage !== "app" || !hrDrilldownMcId) return;
    setHrDrilldownLoading(true);
    setHrDrilldownData(null);
    setHrDrilldownError(null);
    api.get('/api/leaderboard/mc/' + hrDrilldownMcId).then(r => {
      if (r && !r.error) {
        setHrDrilldownData(r);
      } else {
        setHrDrilldownError(r?.error || 'Failed to load per-MC leaderboard');
      }
    }).finally(() => setHrDrilldownLoading(false));
  }, [stage, hrDrilldownMcId]);

  // Load per-MC full-report metadata when a cell is selected (C7).
  // Endpoint: PR3 C38's GET /api/mc/:id/full-reports?framework=<fw>.
  // Returns metadata only (id, framework, received_at, expires_at,
  // signature_fingerprint, bytes); the actual report body comes via
  // C39 wired in C8. Strict server-side limits apply (default 50,
  // max 200); the UI shows what the server returns without paging.
  // selectedCell null clears the panel.
  useEffect(() => {
    if (!selectedCell) { setReportsList(null); setReportsError(null); return; }
    setReportsLoading(true);
    setReportsError(null);
    setReportsList(null);
    const url = '/api/mc/' + encodeURIComponent(selectedCell.mc_id) +
                '/full-reports?framework=' + encodeURIComponent(selectedCell.framework);
    api.get(url).then(r => {
      if (r && !r.error && Array.isArray(r.reports)) {
        setReportsList(r.reports);
      } else {
        setReportsError(r?.error || 'Failed to load full-report list');
      }
    }).finally(() => setReportsLoading(false));
  }, [selectedCell]);

  // Load per-report parsed body when a report row is clicked (C8).
  // Endpoint: PR3 C39's GET /api/mc/:id/full-reports/:reportId. ONLY
  // endpoint that returns the report_json payload (under the `data`
  // field — the field is named `data` rather than `report` to avoid
  // collision with the outer `report:` wrapper key per the PR3 C39
  // contract). Cross-MC enumeration closure applies: a report id
  // belonging to a different MC returns the SAME 404 message as a
  // nonexistent id, so the UI can't probe other MCs' id space.
  // selectedReportId null clears the panel.
  useEffect(() => {
    if (!selectedReportId || !selectedCell) {
      setReportDetail(null);
      setReportDetailError(null);
      return;
    }
    setReportDetailLoading(true);
    setReportDetailError(null);
    setReportDetail(null);
    const url = '/api/mc/' + encodeURIComponent(selectedCell.mc_id) +
                '/full-reports/' + encodeURIComponent(selectedReportId);
    api.get(url).then(r => {
      if (r && !r.error && r.report) {
        setReportDetail(r.report);
      } else {
        setReportDetailError(r?.error || 'Failed to load full-report detail');
      }
    }).finally(() => setReportDetailLoading(false));
  }, [selectedReportId, selectedCell]);

  // Approve a pending signing key (added in C13). Used by both the
  // C11 cross-MC pending queue and the C12 per-MC keys panel. Issues
  // a window.confirm with the fingerprint inlined so the operator
  // sees the value they are committing to before the POST fires — a
  // last-mile guard against approving the wrong row from muscle
  // memory. Sends the fingerprint as confirmation_fingerprint in the
  // request body, exercising PR3 C19's optional CISO-side double-
  // check: the server compares the value to the stored fingerprint
  // and returns 400 CONFIRMATION_FINGERPRINT_MISMATCH on disagree,
  // catching UI bugs and copy-paste errors that might otherwise
  // silently approve the wrong key. On success, refetches both
  // surfaces (cross-MC pending queue and the open per-MC panel, if
  // any) so the approved key transitions out of pending state in
  // both views without a manual refresh. Server-side audit event
  // MC_SIGNING_KEY_APPROVED captures user_id, role, mc, keyId,
  // fingerprint, and action (approved_initial vs approved_replacement
  // for rotation events).
  const handleApproveKey = async (mcId, keyId, fingerprint, mcName) => {
    const confirmMessage =
      "Approve signing key #" + keyId + " for " + (mcName || mcId) + "?\n\n" +
      "Fingerprint:\n" + fingerprint + "\n\n" +
      "Verify this fingerprint OUT OF BAND with the MC operator (phone, in-person, separate encrypted channel) BEFORE confirming. Approval is recorded permanently in the GD audit log.";
    if (!window.confirm(confirmMessage)) return;
    setApprovingKeyId(keyId);
    setApproveError(null);
    const url = "/api/mc/" + encodeURIComponent(mcId) +
                "/signing-keys/" + encodeURIComponent(keyId) + "/approve";
    const r = await api.post(url, { confirmation_fingerprint: fingerprint });
    setApprovingKeyId(null);
    if (r && !r.error && r.ok) {
      const verb = r.action === "approved_replacement" ? "approved (rotation)" : "approved";
      showGdToast("Signing key #" + keyId + " " + verb + " for " + (mcName || mcId));
      api.get('/api/signing-keys/pending').then(x => {
        if (x && !x.error && Array.isArray(x.pending)) setPendingKeys(x.pending);
      });
      if (expandedMcKeysFor === mcId) {
        api.get('/api/mc/' + encodeURIComponent(mcId) + '/signing-keys').then(x => {
          if (x && !x.error && Array.isArray(x.keys)) setMcKeysData(x);
        });
      }
    } else {
      const msg = r?.error || 'Approve failed';
      setApproveError(msg);
      showGdToast("Approve failed: " + msg);
    }
  };

  // Reject-modal lifecycle helpers (added in C14). openRejectModal
  // primes the form with the target row context and resets the
  // textarea + error slot. closeRejectModal returns to the resting
  // state without firing the POST. handleSubmitReject performs the
  // PR3 C19 reject POST with the user-entered reason in the body;
  // server enforces non-empty (after trim) and ≤500 chars
  // (REASON_MAX_LEN). Client-side mirrors the same guards so the
  // operator sees a fast inline error rather than a server round-
  // trip on a trivially-invalid input. Reason is captured server-
  // side in the audit log + signing_keys.rejected_reason; the
  // MC-facing status endpoint (PR3 C21) strips it per the privacy
  // invariant.
  const REJECT_REASON_MAX = 500;
  const openRejectModal = (mcId, keyId, fingerprint, mcName) => {
    setRejectModalKey({ mcId, keyId, fingerprint, mcName });
    setRejectReason("");
    setRejectErrorInline(null);
  };
  const closeRejectModal = () => {
    setRejectModalKey(null);
    setRejectReason("");
    setRejectErrorInline(null);
  };
  const handleSubmitReject = async () => {
    if (!rejectModalKey) return;
    const trimmed = rejectReason.trim();
    if (!trimmed) {
      setRejectErrorInline("Reason is required.");
      return;
    }
    if (trimmed.length > REJECT_REASON_MAX) {
      setRejectErrorInline("Reason exceeds " + REJECT_REASON_MAX + " characters.");
      return;
    }
    setRejecting(true);
    setRejectErrorInline(null);
    const { mcId, keyId, mcName } = rejectModalKey;
    const url = "/api/mc/" + encodeURIComponent(mcId) +
                "/signing-keys/" + encodeURIComponent(keyId) + "/reject";
    const r = await api.post(url, { reason: trimmed });
    setRejecting(false);
    if (r && !r.error && r.ok) {
      showGdToast("Signing key #" + keyId + " rejected for " + (mcName || mcId));
      setRejectModalKey(null);
      setRejectReason("");
      api.get('/api/signing-keys/pending').then(x => {
        if (x && !x.error && Array.isArray(x.pending)) setPendingKeys(x.pending);
      });
      if (expandedMcKeysFor === mcId) {
        api.get('/api/mc/' + encodeURIComponent(mcId) + '/signing-keys').then(x => {
          if (x && !x.error && Array.isArray(x.keys)) setMcKeysData(x);
        });
      }
    } else {
      setRejectErrorInline(r?.error || "Reject failed");
    }
  };

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
    {id:"compromise",label:"Compromise Scan"},{id:"regression",label:"Regression Test"},{id:"vuln_scan",label:"Cloud Vuln Scan"},
    {id:"cloud_iac",label:"Cloud & IaC"},{id:"sdn_sase",label:"SDN / SASE"},{id:"ha_cluster",label:"HA & Clustering"},
    {id:"backup",label:"Backup & Restore"},{id:"restore",label:"Restore"},{id:"data_sov",label:"Data Sovereignty"},{id:"recert",label:"Recertification"},
    {id:"compliance_posture",label:"Compliance Posture"},{id:"compliance_xregion",label:"Cross-Region Compliance"},
    {id:"helper_recognition",label:"Helper Recognition"},
    {id:"troubleshooter",label:"Troubleshooter"},{id:"app_updates",label:"App Updates"},
    {id:"audit_dash",label:"Audit & Forensics"},{id:"forensic_exports",label:"Forensic Exports"},
  ];

  // LOGIN
  if (deployMode === undefined) return null;
  if (!deployMode.configured) return <DeploymentSetup onComplete={()=>setDeployMode({ configured: true })} />;
  if(stage==="login") return <GdLoginScreen onLoggedIn={()=>setStage(firstLaunch?"welcome":"app")} firstLaunch={firstLaunch} gdServerUrl={gdServerUrl} setGdServerUrl={setGdServerUrl} />;

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
      {/* Reject-signing-key modal (PR4 C14). Renders only when a reject flow is active. */}
      {rejectModalKey&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.75)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000,padding:20}} onClick={()=>{if(!rejecting)closeRejectModal();}}>
        <Card style={{maxWidth:560,width:"100%",cursor:"default",borderColor:C.d+"60"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:14,fontWeight:600,color:C.d,fontFamily:"'Fraunces',serif",marginBottom:6}}>Reject signing key</div>
          <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.5,fontSize:11}}>You are about to reject signing key #{rejectModalKey.keyId} for <span style={{color:C.t,fontWeight:500}}>{rejectModalKey.mcName||rejectModalKey.mcId}</span>. The MC's pending key will be marked rejected and will never become verifiable. Rejection is permanent and recorded in the GD audit log.</M>
          <div style={{padding:"6px 8px",background:"rgba(0,0,0,0.3)",borderLeft:`2px solid ${C.d}`,borderRadius:4,marginBottom:10}}>
            <M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>fingerprint</M>
            <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{rejectModalKey.fingerprint||"—"}</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:4,fontSize:10,fontWeight:500}}>Reason (required) <span style={{color:C.td,fontWeight:400}}>— recorded server-side in audit log + visible in this admin panel only. NEVER exposed to the MC.</span></M>
          <textarea value={rejectReason} onChange={e=>setRejectReason(e.target.value)} disabled={rejecting} rows={4} placeholder="e.g. fingerprint did not match out-of-band verification on 2026-05-13 with MC operator J. Doe (Slack DM)" style={{width:"100%",boxSizing:"border-box",padding:"8px 10px",background:"rgba(0,0,0,0.3)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:11,fontFamily:"'DM Sans',sans-serif",lineHeight:1.4,resize:"vertical"}}/>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:4,marginBottom:8}}>
            <M style={{color:rejectReason.length>REJECT_REASON_MAX?C.d:C.td,fontSize:9}}>{rejectReason.length}/{REJECT_REASON_MAX} characters</M>
          </div>
          {rejectErrorInline&&<M style={{color:C.d,display:"block",marginBottom:8,fontSize:10}}>{rejectErrorInline}</M>}
          <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:4}}>
            <Btn small disabled={rejecting} onClick={closeRejectModal}>Cancel</Btn>
            <Btn small primary disabled={rejecting||!rejectReason.trim()||rejectReason.length>REJECT_REASON_MAX} onClick={handleSubmitReject}>{rejecting?"Rejecting...":"Submit Reject"}</Btn>
          </div>
        </Card>
      </div>}
      {updStatus&&updStatus.updateAvailable&&updStatus.latestVersion&&updStatus.latestVersion!==updBannerDismissed&&(
        <div style={{padding:"10px 24px",background:C.i+"18",color:C.i,fontSize:12,display:"flex",justifyContent:"space-between",alignItems:"center",borderBottom:`1px solid ${C.i}40`,fontFamily:"'IBM Plex Mono',monospace"}}>
          <span>A new FireAlive version is available: {updStatus.latestVersion}.{updStatus.releaseUrl&&<> <a href={updStatus.releaseUrl} target="_blank" rel="noopener noreferrer" style={{color:C.i,textDecoration:"underline"}}>Release notes</a></>} — download and test before applying.</span>
          <button onClick={()=>{const v=updStatus.latestVersion;setUpdBannerDismissed(v);try{localStorage.setItem("fa_gd_upd_dismissed",v);}catch(_e){}}} style={{marginLeft:12,background:"transparent",border:"none",color:C.i,cursor:"pointer",textDecoration:"underline",fontSize:11,whiteSpace:"nowrap"}}>dismiss</button>
        </div>
      )}
      <div style={{borderBottom:`1px solid ${C.b}`,background:C.s,padding:"16px 24px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase",fontSize:9,display:"block",marginBottom:6}}>
            <span style={{display:"inline-block",width:5,height:5,borderRadius:"50%",background:C.a,marginRight:6,boxShadow:`0 0 6px ${C.a}`}}/>FireAlive Global Dashboard · Read-Only · v{gdVersion||"…"}</M>
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
          <button onClick={async()=>{if(configLocked){const opt=await api.post("/api/config/lock/unlock-options",{});if(!opt||opt.error||!opt.options||!opt.challengeToken){showGdToast("Could not start unlock: "+(opt?.error||"unknown error"));return;}let cred;try{cred=await navigator.credentials.get({publicKey:deserializeAuthOptions(opt.options)});}catch(e){showGdToast("Passkey unlock cancelled");return;}const r=await api.post("/api/config/lock",{action:"unlock",response:serializeAssertion(cred),challengeToken:opt.challengeToken});if(r&&!r.error){setConfigLocked(!!r.lock_active);showGdToast("Configurations unlocked");}else{showGdToast("Unlock failed: "+(r?.error||"unknown error"));}}else{const r=await api.post("/api/config/lock",{action:"lock"});if(r&&!r.error){setConfigLocked(!!r.lock_active);showGdToast("Configurations locked");}else{showGdToast("Lock failed: "+(r?.error||"unknown error"));}}}} style={{width:"100%",marginTop:8,padding:"8px 12px",background:configLocked?"rgba(239,68,68,0.06)":"rgba(110,231,183,0.06)",border:`1px solid ${configLocked?"rgba(239,68,68,0.2)":"rgba(110,231,183,0.2)"}`,borderRadius:8,color:configLocked?C.d:C.a,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{configLocked?"Unlock to Make Changes":"Lock All Configs"}</button>
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
              <Btn small primary style={{marginTop:12,marginRight:8}} onClick={async()=>{
                const ok=await api.download("/api/reports/generate","firealive-gd-report-"+generatedReport.type+"-"+new Date().toISOString().slice(0,10)+".pdf",{method:"POST",body:{type:generatedReport.type,format:"pdf"}});
                showGdToast(ok?"Signed PDF downloaded":"PDF download failed");
              }}>Download PDF</Btn>
              <Btn small primary style={{marginTop:12,marginRight:8}} onClick={async()=>{
                const ok=await api.download("/api/reports/generate","firealive-gd-report-"+generatedReport.type+"-"+new Date().toISOString().slice(0,10)+".docx",{method:"POST",body:{type:generatedReport.type,format:"docx"}});
                showGdToast(ok?"Signed DOCX downloaded":"DOCX download failed");
              }}>Download DOCX</Btn>
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
            {/* Pending Signing Key Approvals (PR4 C11 — read-side only; approve/reject in C13-C14). */}
            <Card style={{marginBottom:12,borderColor:(pendingKeys&&pendingKeys.length>0)?C.w+"40":C.b}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",fontFamily:"'Fraunces',serif"}}>Pending Signing Key Approvals</div>
                {pendingKeys&&<Badge color={pendingKeys.length>0?C.w:C.a}>{pendingKeys.length}</Badge>}
              </div>
              <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:10,lineHeight:1.5}}>Cryptographic trust establishment requires manual CISO approval per role segregation policy (ISO 27001 A.6.1.2). Verify each pending fingerprint OUT OF BAND with the MC operator before approving. Once approved the MC's signed pushes will verify against this key; without approval the MC's pushes are rejected at ingest with INGEST_SIGNATURE_REJECTED (severity=critical).</M>
              {pendingKeysLoading&&<M style={{color:C.tm,fontStyle:"italic",display:"block"}}>Loading approval queue...</M>}
              {pendingKeysError&&<M style={{color:C.d,display:"block"}}>{pendingKeysError}</M>}
              {pendingKeys&&!pendingKeysLoading&&pendingKeys.length===0&&<M style={{color:C.a,fontStyle:"italic",display:"block"}}>No keys awaiting review.</M>}
              {pendingKeys&&!pendingKeysLoading&&pendingKeys.length>0&&<div>
                {pendingKeys.map((k,i)=><div key={k.id} style={{padding:"10px 0",borderBottom:i<pendingKeys.length-1?`1px solid ${C.b}`:"none"}}>
                  <div style={{display:"flex",alignItems:"flex-start",gap:10,marginBottom:4}}>
                    <Badge color={C.w}>PENDING</Badge>
                    <div style={{flex:1,minWidth:0}}>
                      <M style={{color:C.t,fontWeight:500,display:"block"}}>{k.mcName||k.mcId}</M>
                      <M style={{color:C.td,display:"block",fontSize:10}}>mc: {k.mcId} · key #{k.id} · submitted {k.submittedAt?new Date(k.submittedAt).toLocaleString():"—"}</M>
                    </div>
                  </div>
                  <div style={{padding:"6px 8px",background:"rgba(0,0,0,0.25)",borderLeft:`2px solid ${C.w}`,borderRadius:4,marginTop:4}}>
                    <M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>fingerprint</M>
                    <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{k.fingerprint||"—"}</M>
                  </div>
                  <div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}>
                    <Btn small primary disabled={approvingKeyId===k.id} onClick={()=>handleApproveKey(k.mcId,k.id,k.fingerprint,k.mcName)}>{approvingKeyId===k.id?"Approving...":"Approve"}</Btn>
                    <Btn small disabled={approvingKeyId===k.id} onClick={()=>openRejectModal(k.mcId,k.id,k.fingerprint,k.mcName)}>Reject</Btn>
                  </div>
                </div>)}
                {approveError&&<M style={{color:C.d,display:"block",marginTop:8,fontSize:10}}>{approveError}</M>}
                <M style={{color:C.td,display:"block",marginTop:8,fontSize:9,fontStyle:"italic"}}>Verify fingerprint OUT OF BAND before approving; reject with rationale captured for the audit log otherwise.</M>
              </div>}
            </Card>
            {mcsError&&<Card style={{padding:12,borderColor:C.d+"40",marginBottom:12}}><M style={{color:C.d}}>{mcsError}</M></Card>}
            {mcs.length===0&&!mcsLoading&&!mcsError&&<Card style={{padding:14,borderColor:C.w+"30",marginBottom:12}}><M style={{color:C.w}}>No MCs registered yet. Register one below to get started.</M></Card>}
            {mcs.length>0&&Array.isArray(pendingKeys)&&pendingKeys.length>0&&(()=>{
              // C15: surface the count of distinct MCs needing signing-key
              // review at the top of the MC list. Distinct count rather
              // than raw row count because the same MC can have multiple
              // pending submissions (rotation events submitting before
              // the prior pending is resolved).
              const distinctMcs = new Set(pendingKeys.map(k=>k.mcId));
              return <M style={{color:C.w,display:"block",fontSize:11,fontStyle:"italic",marginBottom:8}}>{distinctMcs.size} MC{distinctMcs.size===1?"":"s"} below {distinctMcs.size===1?"has":"have"} signing keys awaiting review — look for the amber "Review keys" affordance.</M>;
            })()}
            {mcs.map(mc=>{
              const keysOpen = expandedMcKeysFor===mc.id;
              // Per-MC handshake state (PR4 C15). Derived from the already-
              // fetched cross-MC pending queue rather than a per-MC fetch —
              // the queue tells us which MCs have one or more pending
              // submissions awaiting approval, which is the actionable
              // surface. Other states (approved / rejected / none) are
              // visible in the Keys panel on expand; the badge here
              // focuses operator attention on cards with action items
              // without scaling fetch count linearly with MC count.
              const mcPendingCount = Array.isArray(pendingKeys) ? pendingKeys.filter(k=>k.mcId===mc.id).length : 0;
              const hasPendingKeys = mcPendingCount > 0;
              const cardBorder = keysOpen ? C.a+"40" : hasPendingKeys ? C.w+"40" : C.b;
              return <Card key={mc.id} style={{marginBottom:8,borderColor:cardBorder}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div>
                    <M style={{color:C.t,fontWeight:500}}>{mc.name}</M>
                    <M style={{color:C.td,display:"block",fontSize:10}}>id: {mc.id} · region: {mc.region||"—"} · framework: {mc.regulatory_framework||"none"}</M>
                    <M style={{color:C.td,display:"block",fontSize:10}}>endpoint: {mc.endpoint||"—"} · analysts: {mc.analyst_count??"—"} · last sync: {mc.last_sync||"never"}</M>
                  </div>
                  <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",justifyContent:"flex-end"}}>
                    <Badge color={mc.status==="active"?C.a:(mc.status==="offboarded"?C.tm:C.w)}>{mc.status||"unknown"}</Badge>
                    {hasPendingKeys&&<Badge color={C.w}>{mcPendingCount} PENDING KEY{mcPendingCount===1?"":"S"}</Badge>}
                    <Btn small primary={hasPendingKeys} onClick={()=>setExpandedMcKeysFor(keysOpen?null:mc.id)}>{keysOpen?"Hide keys":hasPendingKeys?"Review keys":"Keys"}</Btn>
                    {mc.status==="active"&&<Btn small onClick={()=>{if(window.confirm("Offboard "+mc.name+"? The MC will stop being able to push metrics. This cannot be undone."))api.put("/api/mc/"+mc.id+"/offboard",{}).then(r=>{if(r&&!r.error){showGdToast(mc.name+" offboarded");api.get("/api/mc/list").then(x=>{if(x&&x.managementConsoles)setMcs(x.managementConsoles);});}else showGdToast("Offboard failed: "+(r?.error||"unknown"));});}}>Offboard</Btn>}
                  </div>
                </div>
                {keysOpen&&<div style={{marginTop:12,padding:"10px 12px",background:"rgba(0,0,0,0.2)",borderLeft:`2px solid ${C.a}`,borderRadius:"0 6px 6px 0"}}>
                  <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:10,fontWeight:500}}>Signing-key history for {mc.name}</M>
                  {mcKeysLoading&&<M style={{color:C.tm,fontStyle:"italic",display:"block"}}>Loading key history...</M>}
                  {mcKeysError&&<M style={{color:C.d,display:"block"}}>{mcKeysError}</M>}
                  {mcKeysData&&!mcKeysLoading&&Array.isArray(mcKeysData.keys)&&mcKeysData.keys.length===0&&<M style={{color:C.td,fontStyle:"italic",display:"block"}}>No signing keys on file for this MC. The MC's first signed push will register a pending key here.</M>}
                  {mcKeysData&&!mcKeysLoading&&Array.isArray(mcKeysData.keys)&&mcKeysData.keys.length>0&&<div>
                    {mcKeysData.keys.map((k,i)=>{
                      const sc = k.approvalStatus==="approved"?C.a:k.approvalStatus==="rejected"?C.d:C.w;
                      const sl = k.approvalStatus==="approved"?"APPROVED":k.approvalStatus==="rejected"?"REJECTED":"PENDING";
                      return <div key={k.id} style={{padding:"10px 0",borderBottom:i<mcKeysData.keys.length-1?`1px solid ${C.b}`:"none"}}>
                        <div style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                          <Badge color={sc}>{sl}</Badge>
                          {k.isActive&&<Badge color={C.a}>ACTIVE</Badge>}
                          {k.rotatedOutAt&&<Badge color={C.tm}>ROTATED</Badge>}
                          <M style={{color:C.t,fontWeight:500,fontSize:11}}>key #{k.id}</M>
                          <M style={{color:C.td,fontSize:10}}>registered {k.registeredAt?new Date(k.registeredAt).toLocaleString():"—"}</M>
                        </div>
                        <div style={{padding:"6px 8px",background:"rgba(0,0,0,0.3)",borderLeft:`2px solid ${sc}`,borderRadius:4,marginTop:4,marginBottom:4}}>
                          <M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>fingerprint</M>
                          <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{k.fingerprint||"—"}</M>
                        </div>
                        {k.approvalStatus==="approved"&&<M style={{color:C.tm,display:"block",fontSize:9}}>approved {k.approvedAt?new Date(k.approvedAt).toLocaleString():"—"} by user #{k.approvedByUserId??"—"} (role: {k.approvedByRole||"—"})</M>}
                        {k.rotatedOutAt&&<M style={{color:C.tm,display:"block",fontSize:9}}>rotated out {new Date(k.rotatedOutAt).toLocaleString()}</M>}
                        {k.approvalStatus==="rejected"&&<div style={{marginTop:4,padding:"6px 8px",background:"rgba(239,68,68,0.06)",borderLeft:`2px solid ${C.d}`,borderRadius:4}}>
                          <M style={{color:C.d,display:"block",fontSize:9,fontWeight:500}}>rejected {k.rejectedAt?new Date(k.rejectedAt).toLocaleString():"—"}</M>
                          {k.rejectedReason&&<M style={{color:C.t,display:"block",fontSize:10,marginTop:2,lineHeight:1.5}}>reason: {k.rejectedReason}</M>}
                        </div>}
                        {k.notes&&<M style={{color:C.tm,display:"block",fontSize:9,marginTop:4,fontStyle:"italic"}}>notes: {k.notes}</M>}
                        {k.approvalStatus==="pending_approval"&&<div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}>
                          <Btn small primary disabled={approvingKeyId===k.id} onClick={()=>handleApproveKey(mc.id,k.id,k.fingerprint,mc.name)}>{approvingKeyId===k.id?"Approving...":"Approve"}</Btn>
                          <Btn small disabled={approvingKeyId===k.id} onClick={()=>openRejectModal(mc.id,k.id,k.fingerprint,mc.name)}>Reject</Btn>
                        </div>}
                      </div>;
                    })}
                  </div>}
                  <M style={{color:C.td,display:"block",marginTop:8,fontSize:9,fontStyle:"italic"}}>This panel is the only UI surface that exposes rejected_reason. The MC operator sees a generic "contact your CISO" status; full rationale lives in the GD audit log + this view.</M>
                </div>}
              </Card>;
            })}
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
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <M style={{color:C.i,fontWeight:500}}>Log Integrity</M>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <Badge color={!logIntegrity?C.tm:(logIntegrity.error?C.w:(logIntegrity.intact?C.a:C.d))}>{!logIntegrity?(logIntegrityLoading?"checking…":"not verified"):(logIntegrity.error?"unavailable":(logIntegrity.intact?"intact":"tamper detected"))}</Badge>
                  <Btn small primary disabled={logIntegrityLoading} onClick={()=>{setLogIntegrityLoading(true);api.get("/api/audit/integrity").then(r=>setLogIntegrity(r||null)).finally(()=>setLogIntegrityLoading(false));}}>{logIntegrityLoading?"Verifying…":"Verify Now"}</Btn>
                </div>
              </div>
              {logIntegrity&&!logIntegrity.error&&<M style={{color:C.td,display:"block"}}>{logIntegrity.intact?`${logIntegrity.entriesVerified!=null?logIntegrity.entriesVerified+" entries verified · ":""}SHA-256 hash chain + Ed25519-signed checkpoints`:`Chain break — reason: ${logIntegrity.reason||"unknown"}${logIntegrity.brokenAt!=null?" at id "+logIntegrity.brokenAt:""}`}</M>}
              {logIntegrity&&logIntegrity.checkpoint&&<M style={{color:C.td,display:"block",marginTop:6}}>Signed checkpoint #{logIntegrity.checkpoint.id} · head id {logIntegrity.checkpoint.head_id} · notarized {logIntegrity.checkpoint.created_at?new Date(logIntegrity.checkpoint.created_at).toLocaleString():"—"}</M>}
              {logIntegrity&&logIntegrity.error&&<M style={{color:C.w,display:"block"}}>Verification unavailable: {logIntegrity.error}</M>}
              {!logIntegrity&&!logIntegrityLoading&&<M style={{color:C.td,display:"block",fontStyle:"italic"}}>Click Verify Now to recompute the chain and validate the latest signed checkpoint.</M>}
              <M style={{color:C.td,display:"block",marginTop:6,fontStyle:"italic"}}>Tamper-evident from baseline establishment at deployment. A periodic check also runs hourly and records a critical audit event on any break.</M>
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

          {/* R3l C34: Forensic Export — vp creates / ciso (separate-actor) deletes */}
          {tab==="forensic_exports"&&(<div>
            <L>Forensic Export</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>SOC-grade forensic exports of the GD-server's audit data. Each export bundles selected data slices into the chosen forensic formats (8 supported), signs the manifest with Ed25519 from the GD's own Tier-1 KEK, and (optionally) attests with Cosign. The full chain of operations is recorded in the append-only forensic_export_chain.</M>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}><b style={{color:C.t}}>Separate-actor enforcement:</b> exports are created by the VP; deletion requires the CISO role AND a different user than the original requester. The chain entry survives any deletion. This is a stricter workflow than the legacy &quot;Forensics&quot; button on the Audit &amp; Forensics tab, which just dumps the current audit log as JSON.</M>

            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:12}}>New Forensic Export</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
                <div>
                  <M style={{color:C.tm,display:"block",marginBottom:4}}>Time window start (ISO 8601, optional)</M>
                  <input type="text" value={forensicForm.timeWindowStart} onChange={e=>setForensicForm({...forensicForm,timeWindowStart:e.target.value})} placeholder="2026-01-01T00:00:00Z" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
                </div>
                <div>
                  <M style={{color:C.tm,display:"block",marginBottom:4}}>Time window end (ISO 8601, optional)</M>
                  <input type="text" value={forensicForm.timeWindowEnd} onChange={e=>setForensicForm({...forensicForm,timeWindowEnd:e.target.value})} placeholder="2026-12-31T23:59:59Z" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
                </div>
              </div>
              <div style={{marginBottom:12}}>
                <M style={{color:C.tm,display:"block",marginBottom:4}}>Event type filter (comma-separated, optional)</M>
                <input type="text" value={forensicForm.eventTypeFilter} onChange={e=>setForensicForm({...forensicForm,eventTypeFilter:e.target.value})} placeholder="LOGIN_FAILED,FORENSIC_EXPORT_CREATED,FORENSIC_EXPORT_DELETED" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
              </div>
              <div style={{marginBottom:12}}>
                <M style={{color:C.tm,display:"block",marginBottom:6}}>Rationale (recorded in audit log; recommended for compliance)</M>
                <textarea value={forensicForm.rationale} onChange={e=>setForensicForm({...forensicForm,rationale:e.target.value})} placeholder="Reason for this forensic export (incident ID, audit ticket, regulator request…)" rows={2} style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"inherit",resize:"vertical"}}/>
              </div>
              <div style={{marginBottom:12}}>
                <M style={{color:C.tm,display:"block",marginBottom:6}}>Output formats (one file per format inside the archive)</M>
                <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                  {ALL_FORENSIC_FORMATS.map(fmt=>(
                    <button key={fmt} onClick={()=>toggleForensicFormat(fmt)} style={{padding:"5px 10px",background:forensicForm.outputFormats.includes(fmt)?C.a:"rgba(255,255,255,0.03)",border:`1px solid ${forensicForm.outputFormats.includes(fmt)?C.a:C.b}`,borderRadius:4,color:forensicForm.outputFormats.includes(fmt)?"#000":C.t,fontSize:11,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{fmt}</button>
                  ))}
                </div>
              </div>
              <div style={{marginBottom:12}}>
                <M style={{color:C.tm,display:"block",marginBottom:6}}>Slices to include</M>
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
                  {[
                    ["includeAuditLog","Audit log"],
                    ["includeBackupChain","Backup chain"],
                    ["includeIncidentRecords","Incident retros"],
                    ["includeAuthenticationLogs","Auth log"],
                    ["includeUserAccessLogs","Session log"],
                  ].map(([key,lbl])=>(
                    <label key={key} style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",color:C.t,fontSize:12}}>
                      <input type="checkbox" checked={forensicForm[key]} onChange={e=>setForensicForm({...forensicForm,[key]:e.target.checked})}/>
                      {lbl}
                    </label>
                  ))}
                </div>
              </div>
              {forensicCreateError&&(<Card style={{marginBottom:12,borderColor:C.d+"60"}}><M style={{color:C.d}}>Create failed: {forensicCreateError}</M></Card>)}
              {forensicCreateResult&&(<Card style={{marginBottom:12,borderColor:C.a+"60"}}><M style={{color:C.a}}>Created export <code>{forensicCreateResult.id}</code> ({forensicCreateResult.sizeBytes} bytes, sha256 {(forensicCreateResult.archiveSha256||"").slice(0,16)}…)</M></Card>)}
              <div style={{display:"flex",gap:8}}>
                <Btn small primary onClick={submitForensicExport} disabled={forensicCreateInFlight}>{forensicCreateInFlight?"Creating…":"Create Forensic Export"}</Btn>
                <Btn small onClick={viewForensicChain}>View Chain</Btn>
              </div>
            </Card>

            {forensicChainOpen&&(<Card style={{marginBottom:16,borderColor:C.i+"60"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>Forensic Export Chain</div>
                <button onClick={()=>setForensicChainOpen(false)} style={{background:"transparent",border:"none",color:C.tm,fontSize:14,cursor:"pointer"}}>✕</button>
              </div>
              {!forensicChain&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading chain…</M>)}
              {forensicChain&&forensicChain.error&&(<M style={{color:C.d}}>Error: {forensicChain.error}</M>)}
              {forensicChain&&!forensicChain.error&&(<div>
                {forensicChain.active_signing_key&&(<div style={{marginBottom:10,padding:8,background:"rgba(255,255,255,0.02)",border:`1px solid ${C.b}`,borderRadius:4}}>
                  <M style={{color:C.td,display:"block"}}>Active signing key</M>
                  <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>id: {forensicChain.active_signing_key.id}</M>
                  <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>fingerprint: {forensicChain.active_signing_key.fingerprint}</M>
                </div>)}
                <div style={{maxHeight:300,overflowY:"auto",fontFamily:"'IBM Plex Mono',monospace",fontSize:10}}>
                  {(forensicChain.chain||[]).map(c=>(
                    <div key={c.id} style={{padding:"6px 8px",borderBottom:`1px solid ${C.b}`,display:"flex",gap:10}}>
                      <span style={{color:C.td,minWidth:50}}>#{c.id}</span>
                      <span style={{color:C.a,minWidth:160}}>{c.event_type}</span>
                      <span style={{color:C.tm,minWidth:90}}>{c.created_at}</span>
                      <span style={{color:C.t,wordBreak:"break-all"}}>{c.export_ref} / actor:{c.actor_user_id} / hash:{(c.this_hash||"").slice(0,12)}…</span>
                    </div>
                  ))}
                  {(forensicChain.chain||[]).length===0&&(<M style={{color:C.tm,fontStyle:"italic",padding:8,display:"block"}}>No chain entries yet.</M>)}
                </div>
              </div>)}
            </Card>)}

            {forensicManifestOpen&&(<Card style={{marginBottom:16,borderColor:C.i+"60"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>Export Manifest</div>
                <button onClick={()=>setForensicManifestOpen(false)} style={{background:"transparent",border:"none",color:C.tm,fontSize:14,cursor:"pointer"}}>✕</button>
              </div>
              {!forensicManifest&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading manifest…</M>)}
              {forensicManifest&&forensicManifest.error&&(<M style={{color:C.d}}>Error: {forensicManifest.error}</M>)}
              {forensicManifest&&!forensicManifest.error&&(<pre style={{maxHeight:400,overflow:"auto",fontFamily:"'IBM Plex Mono',monospace",fontSize:10,color:C.t,background:"rgba(0,0,0,0.3)",padding:10,borderRadius:4,whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{JSON.stringify(forensicManifest,null,2)}</pre>)}
            </Card>)}

            {forensicDeleteError&&(<Card style={{marginBottom:16,borderColor:C.d+"60"}}><M style={{color:C.d}}>Last delete failed: {forensicDeleteError}</M></Card>)}

            {!forensicLoadState.loaded&&!forensicLoadState.error&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading exports…</M>)}
            {forensicLoadState.error&&(<Card style={{borderColor:C.w+"60"}}><M style={{color:C.w}}>Could not load exports: {forensicLoadState.error}</M></Card>)}
            {forensicLoadState.loaded&&forensicExports.length===0&&(<Card><M style={{color:C.tm,fontStyle:"italic"}}>No forensic exports yet. Use the form above to create one.</M></Card>)}
            {forensicLoadState.loaded&&forensicExports.length>0&&(<Card style={{padding:0,overflow:"hidden"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                <thead>
                  <tr style={{background:"rgba(255,255,255,0.02)"}}>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Export ID</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Requested</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Status</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Formats</th>
                    <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Size</th>
                    <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {forensicExports.map(e=>{
                    const statusColor = e.status==="complete"?C.a:e.status==="failed"?C.d:e.status==="in_progress"?C.i:C.w;
                    const inFlight = forensicDeleteInFlight[e.id];
                    return (
                      <tr key={e.id} style={{borderBottom:`1px solid ${C.b}`}}>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{e.id}</M>
                          {e.rationale&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>{e.rationale}</M>)}
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <M style={{color:C.tm}}>{e.requested_at||"—"}</M>
                          <M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>by: {e.requested_by_user_id}</M>
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <Badge color={statusColor}>{e.status}</Badge>
                          {e.error_message&&(<M style={{color:C.d,display:"block",fontSize:10,marginTop:4,maxWidth:200,wordBreak:"break-word"}}>{e.error_message}</M>)}
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <M style={{color:C.tm,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{e.output_formats||"—"}</M>
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top",textAlign:"right"}}>
                          <M style={{color:C.tm}}>{e.size_bytes?e.size_bytes.toLocaleString()+" B":"—"}</M>
                          {e.archive_sha256&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2,fontFamily:"'IBM Plex Mono',monospace"}}>{(e.archive_sha256||"").slice(0,12)}…</M>)}
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top",textAlign:"right"}}>
                          <div style={{display:"flex",gap:4,justifyContent:"flex-end",flexWrap:"wrap"}}>
                            {e.status==="complete"&&(<Btn small primary onClick={()=>downloadForensicArchive(e.id)}>Download</Btn>)}
                            {e.status==="complete"&&(<Btn small onClick={()=>viewForensicManifest(e.id)}>Manifest</Btn>)}
                            <button onClick={()=>deleteForensicExport(e.id)} disabled={!!inFlight} style={{padding:"4px 8px",background:"transparent",border:`1px solid ${C.d}`,borderRadius:4,color:C.d,fontSize:10,fontWeight:500,cursor:inFlight?"not-allowed":"pointer",opacity:inFlight?0.6:1}}>{inFlight?"Deleting…":"Delete"}</button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>)}
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
            {gdHealth.metrics&&<div style={{marginTop:16}}>
              <div style={{fontSize:13,fontWeight:600,color:C.t,margin:"4px 0 8px"}}>Subsystem Health</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
                <Card><M style={{color:C.td}}>Fleet</M><div style={{color:C.a,fontWeight:600,fontSize:15}}>{(gdHealth.metrics.fleet?.active??0)+" / "+(gdHealth.metrics.fleet?.total??0)}</div><M style={{color:C.td}}>active MC(s)</M></Card>
                <Card><M style={{color:C.td}}>Signing keys</M><div style={{color:C.i,fontWeight:600,fontSize:15}}>{gdHealth.metrics.signing_keys?.active??0}</div><M style={{color:C.td}}>active{gdHealth.metrics.signing_keys?.pendingApproval?" · "+gdHealth.metrics.signing_keys.pendingApproval+" pending":""}</M></Card>
                <Card><M style={{color:C.td}}>Audit chain</M><div style={{color:gdHealth.metrics.audit_integrity?.intact===false?C.d:C.a,fontWeight:600,fontSize:15}}>{gdHealth.metrics.audit_integrity?.entryCount??0}</div><M style={{color:C.td}}>entries{gdHealth.metrics.audit_integrity?.intact===false?" · BREAK":""}</M></Card>
                <Card><M style={{color:C.td}}>Backup</M><div style={{color:C.t,fontWeight:600,fontSize:15}}>{gdHealth.metrics.backup?.lastStatus||"never"}</div><M style={{color:C.td}}>last status</M></Card>
                <Card><M style={{color:C.td}}>Notifications</M><div style={{color:gdHealth.metrics.notifications?.unacknowledged?C.w:C.t,fontWeight:600,fontSize:15}}>{gdHealth.metrics.notifications?.unacknowledged??0}</div><M style={{color:C.td}}>unacknowledged</M></Card>
                <Card><M style={{color:C.td}}>File integrity</M><div style={{color:C.t,fontWeight:600,fontSize:15}}>{gdHealth.metrics.runtime?.fimFiles??0}</div><M style={{color:C.td}}>files · {gdHealth.metrics.runtime?.dbReadsPerMin??0}/min reads</M></Card>
              </div>
            </div>}
          </div>)}

          {/* ══════════ MONITORING INTEGRATIONS ══════════ */}
          {tab==="monitoring"&&(<GdSelfProtectionConsole/>)}

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

            <div style={{fontSize:13,fontWeight:600,color:C.t,margin:"20px 0 8px"}}>Hardware-Key Sign-In Trust</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Operators sign in with a hardware FIDO2 passkey (a security key with a PIN); there is no password and no external SSO, so the provider settings above do not control sign-in. Manage the attestation roots and model allow-list that decide which hardware keys are accepted at enrollment.</M>
            <GdFidoTrustSection/>
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
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Run a read-only self-integrity check on the Global Dashboard server itself — database and audit-chain integrity, signing-key and encryption-key validity, hardware instance-anchor status, file-integrity, configuration-lock presence, memory, and Node runtime. Each check reports PASS, WARN, or FAIL; the overall result is clean, warnings, or compromised. Results are audit-logged.</M>
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
                <Badge color={compromiseResult.overall==="clean"?C.a:(compromiseResult.overall==="warnings"?C.w:C.d)}>{compromiseResult.overall}</Badge>
              </div>
              {compromiseResult.tests?.map((t,i)=><div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{t.name}</M><M style={{color:t.status==="pass"?C.a:(t.status==="warn"?C.w:C.d),fontWeight:500}}>{t.status?.toUpperCase()}</M></div>{t.detail&&<M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>{t.detail}</M>}</div>)}
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
              if(r&&!r.error){setRegressionResult(r);showGdToast(r.passed+"/"+r.total+" passed"+(r.skipped>0?", "+r.skipped+" skip":""));}
              else showGdToast("Test failed: "+(r?.error||"unknown"));
            }}>{regressionRunning?"Running...":"Run Regression Test"}</Btn>
            {regressionResult&&<Card style={{marginTop:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <M style={{color:C.t,fontWeight:500}}>{regressionResult.timestamp?new Date(regressionResult.timestamp).toLocaleString():""}</M>
                <Badge color={regressionResult.overall==="pass"?C.a:C.d}>{regressionResult.passed}/{regressionResult.total} {regressionResult.overall}{regressionResult.skipped>0?" · "+regressionResult.skipped+" skip":""}</Badge>
              </div>
              {(()=>{const by={};(regressionResult.tests||[]).forEach(t=>{const k=t.category||"other";by[k]=by[k]||{p:0,s:0,n:0,f:false};by[k].n++;if(t.status==="pass")by[k].p++;else if(t.status==="skip")by[k].s++;else by[k].f=true;});const cats=Object.keys(by).sort();return cats.length?(<div style={{display:"flex",flexWrap:"wrap",gap:6,marginBottom:10}}>{cats.map(c=><span key={c} style={{fontSize:11,padding:"3px 8px",borderRadius:6,border:`1px solid ${by[c].f?C.d:C.b}`,color:by[c].f?C.d:C.tm}}>{c} {by[c].p}/{by[c].n}{by[c].s>0?" ·"+by[c].s+" skip":""}</span>)}</div>):null;})()}
              {regressionResult.tests?.map((t,i)=><div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{t.name}</M><M style={{color:t.status==="pass"?C.a:t.status==="skip"?C.i:C.d,fontWeight:500}}>{t.status?.toUpperCase()}</M></div>)}
              <Btn small style={{marginTop:10}} onClick={()=>{const blob=new Blob([JSON.stringify(regressionResult,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="regression-"+Date.now()+".json";a.click();}}>Export Result</Btn>
            </Card>}
          </div>)}

          {/* ══════════ VULNERABILITY SCAN ══════════ */}
          {tab==="vuln_scan"&&(<div>
            <L>Cloud Vulnerability Scan</L>
            <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>Authorize your organization's cloud-posture and IaC scanners to scan this Global Dashboard server. The GD-server does not run scans or store findings — results appear in the scanner's own console. This authorizes scanners (bearer token + source-IP allow-list) and keeps a tamper-evident log of every scan that reaches the GD-server. These authorizations are the GD-server's own, independent of any Management Console.</M>
            <Card style={{background:C.w+"14",border:`1px solid ${C.w}40`}}>
              <M style={{color:C.w,fontWeight:600,letterSpacing:1.2,textTransform:"uppercase",fontSize:10,display:"block",marginBottom:6}}>Application-layer authorization</M>
              <M style={{color:C.t,display:"block",lineHeight:1.6}}>The GD-server authorizes and logs scans that reach it; network-layer blocking of unauthorized scanners remains your firewall / security-group responsibility. Authorized scanner source IPs are exempt from the GD-server's API rate limiting so a sanctioned scan is not throttled — all other defenses stay active.</M>
            </Card>

            {cvError&&<Card style={{background:C.d+"14",border:`1px solid ${C.d}40`}}><M style={{color:C.d}}>Error: {cvError}</M></Card>}

            {cvNewToken&&(<Card style={{background:C.a+"10",border:`1px solid ${C.a}55`}}>
              <M style={{color:C.a,fontWeight:600,display:"block",marginBottom:6}}>Scanner token — shown once</M>
              <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.5}}>Copy this token into your scanner now. It is stored only as a salted hash and cannot be retrieved again. The scanner presents it (Authorization: Bearer ..., or the X-Scan-Token header) when recording a scan via POST /api/cloud-vuln-access.</M>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <code style={{flex:1,fontSize:11,wordBreak:"break-all",background:C.bg,padding:"8px 10px",borderRadius:8,border:`1px solid ${C.b}`,color:C.t,fontFamily:"'IBM Plex Mono',monospace"}}>{cvNewToken}</code>
                <Btn small onClick={()=>{try{if(navigator.clipboard)navigator.clipboard.writeText(cvNewToken);}catch(e){}}}>Copy</Btn>
                <Btn small onClick={()=>setCvNewToken(null)}>Dismiss</Btn>
              </div>
            </Card>)}

            <Card>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                <M style={{color:C.t,fontWeight:600}}>Authorized scanners ({cvList.length})</M>
                <Btn primary small onClick={()=>{setCvNewToken(null);setCvForm({mode:"add",scanner_type:"",display_name:"",allowed_cidrs:"",notes:"",enabled:true});}}>+ Authorize Scanner</Btn>
              </div>
              {cvLoading&&<M style={{color:C.tm}}>Loading...</M>}
              {!cvLoading&&cvList.length===0&&<M style={{color:C.tm,display:"block",padding:"12px 0"}}>No scanners authorized. No external scanner can record a scan of the GD-server until one is added and enabled.</M>}
              {cvList.map(a=>{
                const sc=CLOUD_VULN_SCANNERS.find(s=>s.id===a.scanner_type);
                return(<div key={a.id} style={{padding:"12px 0",borderTop:`1px solid ${C.b}`,display:"flex",alignItems:"center",gap:12,opacity:a.enabled?1:0.55}}>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                      <M style={{color:C.t,fontWeight:600}}>{a.display_name}</M>
                      <Badge color={C.i}>{sc?sc.l:a.scanner_type}</Badge>
                      {!a.enabled&&<Badge color={C.td}>DISABLED</Badge>}
                    </div>
                    <M style={{color:C.tm,display:"block"}}>Allow-list: {(a.allowed_cidrs||[]).join(", ")||"—"}</M>
                    <M style={{color:C.td,display:"block",marginTop:4}}>Last scan: {a.last_scan_at?(a.last_scan_at+(a.last_scan_source_ip?(" from "+a.last_scan_source_ip):"")):"never"}</M>
                    {a.notes&&<M style={{color:C.td,display:"block",marginTop:2}}>{a.notes}</M>}
                  </div>
                  <div style={{display:"flex",gap:6,flexShrink:0}}>
                    <Btn small onClick={async()=>{const r=await api.put("/api/cloud-vuln/authorizations/"+a.id,{enabled:!a.enabled});if(r&&!r.error){showGdToast(a.enabled?"Scanner disabled":"Scanner enabled");reloadCloudVuln();}else setCvError((r&&r.error)||"update failed");}}>{a.enabled?"Disable":"Enable"}</Btn>
                    <Btn small onClick={()=>{setCvNewToken(null);setCvForm({mode:"edit",id:a.id,scanner_type:a.scanner_type,display_name:a.display_name,allowed_cidrs:(a.allowed_cidrs||[]).join(", "),notes:a.notes||"",enabled:a.enabled});}}>Edit</Btn>
                    <Btn small style={{color:C.d,borderColor:C.d+"50"}} onClick={async()=>{if(!window.confirm("Revoke authorization \""+a.display_name+"\"? The scanner's token will stop working."))return;const r=await api.del("/api/cloud-vuln/authorizations/"+a.id);if(r&&!r.error){showGdToast("Authorization revoked");reloadCloudVuln();}else setCvError((r&&r.error)||"revoke failed");}}>Revoke</Btn>
                  </div>
                </div>);
              })}
            </Card>

            <Card>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
                <M style={{color:C.t,fontWeight:600}}>Scan-access log ({cvLogTotal})</M>
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  {cvChain&&<Badge color={cvChain.intact?C.a:C.d}>{cvChain.intact?("CHAIN OK ("+cvChain.count+")"):("CHAIN BROKEN @"+cvChain.brokenAt)}</Badge>}
                  <Btn small onClick={async()=>{const r=await api.get("/api/cloud-vuln/access-log/verify");if(r&&!r.error)setCvChain(r);else setCvError((r&&r.error)||"verify failed");}}>Verify chain</Btn>
                  <Btn small onClick={reloadCloudVuln}>Refresh</Btn>
                </div>
              </div>
              {cvLog.length===0&&<M style={{color:C.tm}}>No scan access recorded yet.</M>}
              {cvLog.map(e=>(<div key={e.id} style={{padding:"8px 0",borderTop:`1px solid ${C.b}`,display:"flex",alignItems:"center",gap:10}}>
                <Badge color={e.outcome==="authorized"?C.a:C.d}>{e.outcome}</Badge>
                <M style={{color:C.t,flex:1,minWidth:0}}>{(e.scanner_type||"unknown")+" · "+e.component+" · "+e.source_ip}</M>
                <M style={{color:C.td,flexShrink:0}}>{e.accessed_at}</M>
              </div>))}
            </Card>

            {cvForm&&(<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setCvForm(null)}>
              <div onClick={e=>e.stopPropagation()} style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:14,padding:28,maxWidth:540,width:"90%",maxHeight:"85vh",overflowY:"auto"}}>
                <L>{cvForm.mode==="add"?"Authorize Scanner":"Edit Authorization"}</L>
                <Sel label="Scanner" value={cvForm.scanner_type} onChange={e=>setCvForm(prev=>({...prev,scanner_type:e.target.value}))} disabled={cvForm.mode==="edit"}>
                  <option value="">Select a scanner...</option>
                  {CLOUD_VULN_SCANNERS.map(s=>(<option key={s.id} value={s.id}>{s.l}</option>))}
                </Sel>
                <Input label="Display name" value={cvForm.display_name} onChange={e=>setCvForm(prev=>({...prev,display_name:e.target.value}))} placeholder="e.g. Prod Prowler (us-east-1)" maxLength={128}/>
                <Input label="Source IP allow-list (comma-separated IPs or CIDRs)" value={cvForm.allowed_cidrs} onChange={e=>setCvForm(prev=>({...prev,allowed_cidrs:e.target.value}))} placeholder="e.g. 10.0.0.0/24, 203.0.113.7" maxLength={512}/>
                <M style={{color:C.td,display:"block",marginBottom:14}}>Scope: Global Dashboard server</M>
                <Input label="Notes (optional)" value={cvForm.notes} onChange={e=>setCvForm(prev=>({...prev,notes:e.target.value}))} maxLength={1000}/>
                {cvForm.mode==="edit"&&(<label style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer",marginBottom:8}}><input type="checkbox" checked={cvForm.enabled} onChange={e=>setCvForm(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/><M style={{color:C.t}}>Enabled</M></label>)}
                <div style={{display:"flex",gap:8,marginTop:16,justifyContent:"flex-end"}}>
                  <Btn onClick={()=>setCvForm(null)}>Cancel</Btn>
                  <Btn primary onClick={async()=>{
                    const cidrs=cvForm.allowed_cidrs.split(",").map(x=>x.trim()).filter(Boolean);
                    if(!cvForm.scanner_type){setCvError("Scanner is required");return;}
                    if(!cvForm.display_name.trim()){setCvError("Display name is required");return;}
                    if(cidrs.length===0){setCvError("At least one source IP / CIDR is required");return;}
                    if(cvForm.mode==="add"){
                      const r=await api.post("/api/cloud-vuln/authorizations",{scanner_type:cvForm.scanner_type,display_name:cvForm.display_name.trim(),allowed_cidrs:cidrs,scope_components:["gd_server"],notes:cvForm.notes||null});
                      if(r&&!r.error&&r.token){showGdToast("Scanner authorized");setCvForm(null);setCvError(null);setCvNewToken(r.token);reloadCloudVuln();}
                      else setCvError((r&&r.error)||"create failed");
                    }else{
                      const r=await api.put("/api/cloud-vuln/authorizations/"+cvForm.id,{display_name:cvForm.display_name.trim(),allowed_cidrs:cidrs,scope_components:["gd_server"],notes:cvForm.notes||null,enabled:cvForm.enabled});
                      if(r&&!r.error){showGdToast("Authorization updated");setCvForm(null);setCvError(null);reloadCloudVuln();}
                      else setCvError((r&&r.error)||"save failed");
                    }
                  }}>{cvForm.mode==="add"?"Authorize":"Save Changes"}</Btn>
                </div>
              </div>
            </div>)}
          </div>)}

          {tab==="cloud_iac"&&(<div>
            <L>Cloud Mode (Confidential VM)</L>
            <Card style={{borderColor:C.a+"40",marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:8}}>Confidential computing required</div>
              <M style={{color:C.tm,lineHeight:1.7,display:"block"}}>Cloud Mode runs the GD Server on a confidential VM with a vTPM hardware root of trust on AWS, Azure, or GCP. VM memory is encrypted (AMD SEV-SNP or Intel TDX) and confidential computing is attested at boot; the GD refuses to seal cloud mode if it is absent, and refuses spot, autoscaled, or ephemeral-fleet instances. GD_ENCRYPTION_KEY must come from the cloud KMS or Vault -- the JWT-secret fallback is refused in cloud mode.</M>
            </Card>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
              <Sel label="Cloud platform" value={gdCloudModeProvider} onChange={e=>setGdCloudModeProvider(e.target.value)}>
                <option value="">Select platform...</option>
                <option value="aws">AWS (SEV-SNP + NitroTPM)</option>
                <option value="azure">Azure (Confidential VM + Trusted Launch)</option>
                <option value="gcp">GCP (Confidential VM + Shielded VM)</option>
              </Sel>
              <Input label="Stable DNS hostname" value={gdCloudModeDns} onChange={e=>setGdCloudModeDns(e.target.value)} placeholder="gd.example.com" maxLength={253}/>
            </div>
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Deployment guide</div>
              {[
                {s:1,t:"Provision a confidential VM",d:gdCloudModeProvider?("Launch a "+GD_CLOUD_MODE_LABELS[gdCloudModeProvider]+" instance. Use an on-demand instance only; spot, autoscaled, and ephemeral-fleet instances are refused."):"Select a platform above, then launch an on-demand confidential VM. Spot and autoscaled instances are refused."},
                {s:2,t:"Generate and apply IaC",d:"Use Generate Infrastructure as Code below to produce a signed bundle for your platform and format, then apply it."},
                {s:3,t:"Point stable DNS at the instance",d:gdCloudModeDns?("Create an A/AAAA record for "+gdCloudModeDns+". This operator DNS name is the primary certificate SAN; clients reach the GD Server here."):"Create a stable A/AAAA record (operator DNS). It becomes the primary certificate SAN; the instance IP is a secondary SAN."},
                {s:4,t:"Set GD_ENCRYPTION_KEY from cloud KMS",d:"Provide the Tier-1 KEK from the provider KMS or Vault secret store. In cloud mode the GD refuses the JWT-secret fallback and requires GD_ENCRYPTION_KEY."},
                {s:5,t:"Start the GD Server and seal cloud mode",d:"On first boot the server attests confidential computing, refuses to continue if it is absent, and seals cloud mode to the instance. Keep the recovery code for instance loss."},
                {s:6,t:"Clients pin the instance anchor",d:"Clients trust the instance anchor fingerprint, not the leaf certificate, so the server certificate is re-issued automatically when the cloud address changes."},
              ].map(step=>(
                <div key={step.s} style={{display:"flex",gap:12,marginBottom:12}}>
                  <div style={{width:24,height:24,borderRadius:"50%",background:C.ad,border:`1px solid ${C.a}40`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,color:C.a,fontWeight:600,flexShrink:0}}>{step.s}</div>
                  <div><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:2}}>{step.t}</div><M style={{color:C.tm}}>{step.d}</M></div>
                </div>
              ))}
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Generate Infrastructure as Code</div>
              <M style={{color:C.tm,display:"block",marginBottom:12}}>Generate a signed deployment bundle for the GD Server (confidential-VM image, port 4001, GD_ENCRYPTION_KEY + GD_JWT_SECRET from the cloud secret store). The server packages IaC files, an SPDX-JSON SBOM, and a Sigstore signature into a tar.gz.</M>
              <Sel label="Cloud provider" value={gdIacProvider} onChange={e=>{setGdIacProvider(e.target.value);setGdIacTool("");setGdIacResult(null);}}>
                <option value="">Select...</option>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
              </Sel>
              {gdIacProvider&&<Sel label="IaC format" value={gdIacTool} onChange={e=>{setGdIacTool(e.target.value);setGdIacResult(null);}}>
                <option value="">Select format...</option>
                {GD_IAC_TOOLS_BY_PROVIDER[gdIacProvider].map(t=><option key={t} value={t}>{t}</option>)}
              </Sel>}
              {gdIacResult&&gdIacResult.ok&&<Card style={{marginTop:8,padding:10,borderColor:C.a+"30"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.a,marginBottom:6}}>Bundle generated</div>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>Package ID: <span style={{fontFamily:"'IBM Plex Mono',monospace",color:C.t}}>{gdIacResult.data.id}</span></M>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>Size: {(gdIacResult.data.size_bytes/1024).toFixed(1)} KB</M>
                <Btn small primary style={{marginTop:8}} onClick={()=>{window.open(gdServerUrl+"/api/cloud/packages/"+gdIacResult.data.id+"/download","_blank");}}>Download bundle.tar.gz</Btn>
                <Btn small style={{marginTop:8,marginLeft:6}} onClick={()=>{window.open(gdServerUrl+"/api/cloud/packages/"+gdIacResult.data.id+"/public-key","_blank");}}>View public key</Btn>
              </Card>}
              {gdIacResult&&!gdIacResult.ok&&<Card style={{marginTop:8,padding:10,borderColor:C.d+"40"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.d,marginBottom:4}}>Generation failed</div>
                <M style={{color:C.tm,lineHeight:1.6,display:"block"}}>{gdIacResult.message}</M>
                {gdIacResult.code==="SYFT_NOT_INSTALLED"&&<M style={{color:C.td,display:"block",marginTop:6,fontSize:10}}>Install Syft on the GD host: <code style={{background:C.s,padding:"2px 4px",borderRadius:3}}>curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0</code></M>}
                {gdIacResult.code==="COSIGN_NOT_INSTALLED"&&<M style={{color:C.td,display:"block",marginTop:6,fontSize:10}}>Install Cosign on the GD host: <code style={{background:C.s,padding:"2px 4px",borderRadius:3}}>curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign</code></M>}
              </Card>}
              <Btn primary disabled={!gdIacProvider||!gdIacTool||gdIacBusy} style={{marginTop:10}} onClick={async()=>{
                setGdIacBusy(true);setGdIacResult(null);
                const r=await api.post("/api/cloud/package",{provider:gdIacProvider,iac_tool:gdIacTool});
                if(r.error){
                  setGdIacResult({ok:false,message:r.message||r.error,code:r.code});
                }else{
                  setGdIacResult({ok:true,data:r});
                  setGdAudit(a=>[{ts:new Date().toISOString(),event:"CLOUD_PACKAGE_GENERATED",detail:gdIacProvider+"/"+gdIacTool+" id="+r.id},...a]);
                }
                setGdIacBusy(false);
              }}>{gdIacBusy?"Generating bundle...":"Generate IaC Config"}</Btn>
              <Card style={{padding:10,marginTop:10}}><M style={{color:C.td,lineHeight:1.7,display:"block"}}>The bundle contains IaC files for the chosen (provider, format), an SPDX-JSON SBOM (Syft), a Sigstore signature (Cosign via the server-managed signing key), and a deployment README. Verify offline with <code style={{background:C.s,padding:"2px 4px",borderRadius:3}}>cosign verify-blob --key public-key.pem --signature bundle.tar.gz.sig bundle.tar.gz</code> before applying.</M></Card>
            </Card>
            <Card>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>CI/CD Pipeline</div>
              <Sel label="CI/CD platform" value={gdCicdPlatform} onChange={e=>{setGdCicdPlatform(e.target.value);setGdCicdResult(null);}}>
                <option value="github-actions">GitHub Actions</option>
                <option value="gitlab-ci">GitLab CI</option>
                <option value="jenkins">Jenkins</option>
                <option value="circleci">CircleCI</option>
              </Sel>
              <Sel label="Purpose" value={gdCicdPurpose} onChange={e=>{setGdCicdPurpose(e.target.value);setGdCicdResult(null);}}>
                <option value="custom-build">Custom build (org-tailored)</option>
                <option value="upstream-contribution">Upstream contribution (public repo)</option>
              </Sel>
              {gdCicdResult&&gdCicdResult.ok&&<Card style={{marginTop:8,padding:10,borderColor:C.a+"30"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.a,marginBottom:6}}>Pipeline config generated</div>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>Config ID: <span style={{fontFamily:"'IBM Plex Mono',monospace",color:C.t}}>{gdCicdResult.data.id}</span></M>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>Pipeline path: <code style={{background:C.s,padding:"2px 4px",borderRadius:3,fontSize:9}}>{gdCicdResult.data.pipeline_relative_path}</code></M>
                <Btn small primary style={{marginTop:8}} onClick={()=>{window.open(gdServerUrl+"/api/cicd/configs/"+gdCicdResult.data.id+"/download","_blank");}}>Download pipeline file</Btn>
              </Card>}
              {gdCicdResult&&!gdCicdResult.ok&&<Card style={{marginTop:8,padding:10,borderColor:C.d+"40"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.d,marginBottom:4}}>Generation failed</div>
                <M style={{color:C.tm,lineHeight:1.6,display:"block"}}>{gdCicdResult.message}</M>
              </Card>}
              <Btn primary disabled={gdCicdBusy} style={{marginTop:10}} onClick={async()=>{
                setGdCicdBusy(true);setGdCicdResult(null);
                const r=await api.post("/api/cicd/generate",{platform:gdCicdPlatform,purpose:gdCicdPurpose});
                if(r.error){
                  setGdCicdResult({ok:false,message:r.message||r.error});
                }else{
                  setGdCicdResult({ok:true,data:r});
                  setGdAudit(a=>[{ts:new Date().toISOString(),event:"CICD_CONFIG_GENERATED",detail:gdCicdPlatform+"/"+gdCicdPurpose+" id="+r.id},...a]);
                }
                setGdCicdBusy(false);
              }}>{gdCicdBusy?"Generating pipeline...":"Generate Pipeline Config"}</Btn>
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
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Create Backup</div>
              <M style={{color:C.tm,display:"block",marginBottom:10}}>Encrypted v2 backups are WAL-tracked and chain-attested. Incremental and differential capture deltas against the last full and escalate to a full automatically when no baseline exists. Full-suite captures complete state (database, configs, version manifest).</M>
              <div style={{display:"grid",gridTemplateColumns:"1fr auto",gap:10,alignItems:"end"}}>
                <Sel label="Strategy" value={gdBackupStrategy} onChange={e=>setGdBackupStrategy(e.target.value)}>
                  <option value="v2">Full — encrypted (v2)</option>
                  <option value="incremental">Incremental</option>
                  <option value="differential">Differential</option>
                  <option value="snapshot">Snapshot</option>
                  <option value="full-suite">Full-suite — complete state</option>
                </Sel>
                <Btn primary disabled={gdBackupBusy} onClick={async()=>{
                  setGdBackupBusy(true);setGdBackupResult(null);
                  const r=await api.post("/api/backup",{strategy:gdBackupStrategy});
                  if(r.error){
                    setGdBackupResult({ok:false,message:r.message||r.error});
                  }else{
                    setGdBackupResult({ok:true,data:r});
                    setGdAudit(a=>[{ts:new Date().toISOString(),event:"BACKUP_CREATED",detail:"id="+(r.id||"?")+" strategy="+(r.actual_strategy||gdBackupStrategy)+(r.escalated?" (escalated: "+r.escalation_reason+")":"")},...a]);
                    api.get('/api/backup').then(l=>{if(l&&!l.error)setGdBackups(l.backups||[]);});
                  }
                  setGdBackupBusy(false);
                }}>{gdBackupBusy?"Creating backup...":"Create backup"}</Btn>
              </div>
              {gdBackupResult&&gdBackupResult.ok&&<Card style={{marginTop:10,padding:10,borderColor:C.a+"30"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.a,marginBottom:6}}>Backup created{gdBackupResult.data.escalated?" (escalated to full)":""}</div>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>ID: <span style={{fontFamily:"'IBM Plex Mono',monospace",color:C.t}}>{gdBackupResult.data.id}</span></M>
                <M style={{color:C.tm,display:"block",marginBottom:2}}>Strategy: {gdBackupResult.data.actual_strategy||gdBackupResult.data.type||"—"}{gdBackupResult.data.format_version?" · format v"+gdBackupResult.data.format_version:""}</M>
                {gdBackupResult.data.size_bytes!=null&&<M style={{color:C.tm,display:"block",marginBottom:2}}>Size: {(gdBackupResult.data.size_bytes/1024/1024).toFixed(2)} MB</M>}
                {gdBackupResult.data.wal_end_position&&<M style={{color:C.td,display:"block",fontSize:9}}>WAL position: {gdBackupResult.data.wal_end_position}{gdBackupResult.data.page_count!=null?" · "+gdBackupResult.data.page_count+" pages":""}</M>}
                {gdBackupResult.data.manifest_sha256&&<M style={{color:C.td,display:"block",fontSize:9}}>Manifest SHA-256: {(gdBackupResult.data.manifest_sha256||"").slice(0,32)}...</M>}
                {gdBackupResult.data.escalation_reason&&<M style={{color:C.w,display:"block",fontSize:9,marginTop:2}}>Escalation reason: {gdBackupResult.data.escalation_reason}</M>}
              </Card>}
              {gdBackupResult&&!gdBackupResult.ok&&<Card style={{marginTop:10,padding:10,borderColor:C.d+"40"}}>
                <div style={{fontSize:11,fontWeight:500,color:C.d,marginBottom:4}}>Backup failed</div>
                <M style={{color:C.tm,lineHeight:1.6,display:"block"}}>{gdBackupResult.message}</M>
              </Card>}
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>Backup attestation chain</div>
                <Btn small disabled={gdChainBusy} onClick={verifyGdChain}>{gdChainBusy?"Verifying...":"Verify chain"}</Btn>
              </div>
              {!gdChain?<M style={{color:C.td,fontStyle:"italic"}}>Loading chain state...</M>:(
                <M style={{color:C.tm,display:"block"}}>{gdChain.totalEntries} entr{gdChain.totalEntries===1?"y":"ies"}{gdChain.head?" · head "+gdChain.head.eventType+" ("+String(gdChain.head.id).slice(0,8)+")":" · no entries yet"}</M>
              )}
              {gdChainVerify&&(<div style={{marginTop:8,padding:"8px 10px",background:C.s,borderRadius:4,borderLeft:`2px solid ${gdChainVerify.ok?C.a:C.d}`}}>
                {gdChainVerify.ok
                  ? <M style={{color:C.a}}>Chain intact — {gdChainVerify.entriesVerified} entries verified.</M>
                  : <M style={{color:C.d}}>Chain broken{gdChainVerify.brokenAtId?" at "+String(gdChainVerify.brokenAtId).slice(0,8):""}: {gdChainVerify.reason||gdChainVerify.detail||"verification failed"}</M>}
              </div>)}
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Recent backups</div>
              {gdBackups.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No backups recorded yet.</M>:gdBackups.slice(0,12).map(b=>{
                const v=gdVerifyResults[b.id];
                return <div key={b.id} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 78px 84px 116px 62px",gap:8,alignItems:"center"}}>
                    <M style={{color:C.t,fontSize:10}}>{b.type}{b.format_version===2?" · v2":""}</M>
                    <M style={{color:C.tm,fontSize:10}}>{b.size_bytes!=null?(b.size_bytes/1024/1024).toFixed(1)+" MB":"—"}</M>
                    <Badge color={b.status==="verified"||b.status==="completed"?C.a:b.status==="failed"?C.d:C.w}>{b.status}</Badge>
                    <M style={{color:C.td,fontSize:9}}>{b.created_at?new Date(String(b.created_at).replace(" ","T")+"Z").toLocaleString():"—"}</M>
                    <Btn small disabled={gdVerifyingId===b.id} onClick={()=>verifyGdBackup(b.id)}>{gdVerifyingId===b.id?"...":"Verify"}</Btn>
                  </div>
                  {v&&(<div style={{marginTop:6,padding:"6px 8px",background:C.s,borderRadius:4,borderLeft:`2px solid ${v.status==="verified"?C.a:v.status==="tampered"?C.d:C.w}`}}>
                    <Badge color={v.status==="verified"?C.a:v.status==="tampered"?C.d:v.status==="missing"?C.w:C.td}>{v.status}</Badge>
                    {v.checks&&<M style={{color:C.tm,display:"block",marginTop:4,fontSize:9}}>manifest {v.checks.manifestHash&&v.checks.manifestHash.matches?"ok":"MISMATCH"} · signature {v.checks.signature&&v.checks.signature.valid?"valid":"INVALID"} · archive {v.checks.archiveHash&&v.checks.archiveHash.matches?"ok":"MISMATCH"} · key {v.checks.wrappedKeyHash&&v.checks.wrappedKeyHash.matches?"ok":"MISMATCH"}</M>}
                    {v.format_version===1&&<M style={{color:C.tm,display:"block",marginTop:4,fontSize:9}}>stored {(v.storedHash||"").slice(0,12)} vs current {(v.currentHash||"").slice(0,12)} — {v.matches?"match":"MISMATCH"}</M>}
                    {v.message&&<M style={{color:C.td,display:"block",marginTop:4,fontSize:9}}>{v.message}</M>}
                  </div>)}
                </div>;
              })}
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
          {tab==="restore"&&(<div>
            <L>Restore & Settings Revert</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Restore the GD Server database from an external backup source, with manifest-signature verification and two-person approval.</M>
            <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><div style={{fontSize:13,fontWeight:600,color:C.d}}>External Restore</div><Btn small onClick={async()=>{const r=await api.get("/api/external-restore/sources");if(r.error){addA("ER_LIST_FAIL",r.error);}else{setErSources(r.sources||[]);}}}>Refresh Sources</Btn></div>
              <Sel label="Source" value={erSelSrc} onChange={e=>{setErSelSrc(e.target.value);setErBackups([]);setErPreview(null);setErApproval(null);}}><option value="">Select source...</option>{erSources.map(s=>(<option key={s.id} value={s.id}>{s.name} ({s.source_type}){s.enabled?"":" [disabled]"}</option>))}</Sel>
              <div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}><Btn small disabled={!erSelSrc} onClick={async()=>{const r=await api.post("/api/external-restore/sources/"+erSelSrc+"/test");if(r.error){addA("ER_TEST_FAIL",r.error||"failed");}else{addA("ER_TEST","OK - "+r.backupCount+" backups");}}}>Test Connection</Btn><Btn small disabled={!erSelSrc} onClick={async()=>{const r=await api.get("/api/external-restore/sources/"+erSelSrc+"/browse");if(r.error){addA("ER_BROWSE_FAIL",r.error||"failed");}else{setErBackups(r.backups||[]);setErPreview(null);setErApproval(null);}}}>Browse Backups</Btn></div>
              {erBackups.length>0&&(<div style={{marginTop:12,maxHeight:240,overflowY:"auto",border:`1px solid ${C.b}`,borderRadius:6}}><div style={{fontSize:11,color:C.tm,padding:"6px 10px",background:"rgba(0,0,0,0.15)"}}>Backups (newest first) - click to preview</div>{erBackups.map(b=>(<div key={b.id} style={{padding:"8px 10px",borderTop:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center",cursor:"pointer",background:erPreview&&erPreview.externalBackupId===b.id?"rgba(110,231,183,0.1)":"transparent"}} onClick={async()=>{const r=await api.post("/api/external-restore/sources/"+erSelSrc+"/preview/"+encodeURIComponent(b.id));if(r.error){addA("ER_PREVIEW_FAIL",r.error||"failed");}else{setErPreview(r);setErApproval(null);}}}><div><M style={{color:C.t}}>{b.id}</M><br/><M style={{color:C.td,fontSize:11}}>{b.modifiedAt} - {(b.sizeBytes/1024/1024).toFixed(1)} MB</M></div></div>))}</div>)}
              {erPreview&&(<Card style={{marginTop:12,padding:12,background:"rgba(0,0,0,0.2)"}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Preview - {erPreview.externalBackupId}</div>
                <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}><Badge color={erPreview.manifestSigOk?C.a:C.d}>Sig: {erPreview.manifestSigOk?"VERIFIED":(erPreview.signingKeyKnown?"FAILED":"UNKNOWN KEY")}</Badge><Badge color={erPreview.structure&&erPreview.structure.ok?C.a:C.d}>Files: {erPreview.structure?erPreview.structure.present.length:0}/4</Badge><Badge color={C.tm}>Key fp: {(erPreview.signingKeyFingerprint||"").slice(0,12)}...</Badge></div>
                {!erPreview.signingKeyKnown&&(<M style={{color:C.d,display:"block",marginBottom:8}}>! Signing key fingerprint {(erPreview.signingKeyFingerprint||"").slice(0,16)}... is not registered (or has been revoked). For cross-deployment restore, register the originating deployment's public key in the Backup Signing Keys section before restore can proceed.</M>)}
                {erPreview.signingKeyKnown&&!erPreview.manifestSigOk&&(<M style={{color:C.d,display:"block",marginBottom:8}}>! Manifest signature verification FAILED. Backup may be tampered or corrupted. Restore is blocked.</M>)}
                <Input label="Reason for restore (recorded in chain audit)" value={erReason} onChange={e=>setErReason(e.target.value)} placeholder="e.g. recovering from ransomware incident on prod-east"/>
                <Btn danger disabled={!erPreview.manifestSigOk||!erPreview.structure||!erPreview.structure.ok} style={{marginTop:8}} onClick={async()=>{if(window.confirm("Request a restore from this external backup? A second admin must approve via TOTP at the Restore Approvals queue before the restore can execute.")){const r=await api.post("/api/external-restore/sources/"+erSelSrc+"/restore-request/"+encodeURIComponent(erPreview.externalBackupId),{request_reason:erReason||null});if(r.error){addA("ER_REQUEST_FAIL",r.error||"failed");}else{setErApproval(r);addA("ER_REQUEST","approval "+r.approval_id+" - "+r.status);}}}}>Request Restore (Two-Person Approval)</Btn>
              </Card>)}
              {erApproval&&(<Card style={{marginTop:12,padding:12,background:"rgba(0,0,0,0.2)",borderColor:C.w+"40"}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Pending Approval - {erApproval.approval_id.slice(0,12)}...</div>
                <M style={{color:C.tm,display:"block",marginBottom:4}}>Status: <Badge color={erApproval.status==="approved"?C.a:erApproval.status==="pending"?C.w:C.d}>{erApproval.status.toUpperCase()}</Badge></M>
                <M style={{color:C.tm,display:"block",marginBottom:4,fontSize:11}}>Mode: {erApproval.approval_mode_at_creation} - Window: {erApproval.approval_window_hours}h - Expires: {erApproval.expires_at}</M>
                <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:11}}>{erApproval.next_step}</M>
                {erApproval.status==="approved"&&(<Btn danger onClick={async()=>{if(window.confirm("EXECUTE EXTERNAL RESTORE NOW?\n\nThis will replace the live database with the bytes from the external backup. A pre-restore snapshot of the current state will be saved next to the DB file. The operation is recorded in the chain audit trail as RESTORE_REQUEST + RESTORE_COMPLETE.\n\nThis action cannot be undone except by manual recovery from the pre-restore snapshot.")){const r=await api.post("/api/external-restore/restore-execute/"+erApproval.approval_id);if(r.error){addA("ER_EXECUTE_FAIL",r.error||"failed");}else{addA("ER_EXECUTED","Restored "+(r.restored_db_size_bytes/1024/1024).toFixed(1)+" MB - pre-restore snapshot at "+r.pre_restore_snapshot_path);setErApproval(null);setErPreview(null);setErBackups([]);setErSelSrc("");}}}}>EXECUTE RESTORE</Btn>)}
                <Btn small style={{marginTop:8,marginLeft:erApproval.status==="approved"?8:0}} onClick={()=>setErApproval(null)}>Dismiss</Btn>
              </Card>)}
            </Card>
            <Card style={{marginBottom:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>Database Backups (this instance)</div><Btn small onClick={async()=>{const r=await api.get("/api/restore/points");if(r.error){addA("RP_LIST_FAIL",r.error);}else{setRestorePoints(r.backups||[]);setRpPreview(null);}}}>Refresh</Btn></div>
              <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:11,lineHeight:1.5}}>Restore points created by this GD Server. Click one to preview its type, integrity, and approval requirement. Executing a restore requires a hardware-key step-up (added next).</M>
              {restorePoints.length===0&&(<M style={{color:C.td,display:"block",padding:"8px 0"}}>No restore points loaded. Click Refresh.</M>)}
              {restorePoints.map(b=>(
                <div key={b.id} style={{padding:"10px 12px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center",cursor:"pointer",background:rpPreview&&rpPreview.id===b.id?"rgba(110,231,183,0.08)":"transparent"}} onClick={async()=>{const r=await api.get("/api/restore/preview/"+b.id);if(r.error){addA("RP_PREVIEW_FAIL",r.error);}else{setRpPreview(r);}}}>
                  <div style={{flex:1,minWidth:0}}><M style={{color:C.t}}>{b.createdAt}</M><br/><M style={{color:C.td,fontSize:11}}>{b.type} - v{b.format_version} - {b.sizeMB!=null?b.sizeMB+" MB":"size n/a"} - {b.hash||"no hash"}</M></div>
                  <Badge color={b.status==="verified"?C.a:C.w}>{(b.status||"unknown").toUpperCase()}</Badge>
                </div>
              ))}
              {rpPreview&&(<Card style={{marginTop:12,padding:12,background:"rgba(0,0,0,0.2)"}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Preview - {rpPreview.id}</div>
                <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}><Badge color={C.tm}>Type: {rpPreview.type} (v{rpPreview.format_version})</Badge>{rpPreview.format_version===2?(<Badge color={rpPreview.allPresent?C.a:C.d}>Files: {rpPreview.allPresent?"all present":"MISSING"}</Badge>):(<Badge color={rpPreview.fileExists?C.a:C.d}>File: {rpPreview.fileExists?"present":"MISSING"}</Badge>)}{rpPreview.approval&&rpPreview.approval.required&&(<Badge color={C.w}>Approval: {rpPreview.approval.mode}</Badge>)}</div>
                <M style={{color:C.tm,display:"block",marginBottom:4,fontSize:11}}>{rpPreview.sizeMB!=null?rpPreview.sizeMB+" MB - ":""}{rpPreview.createdAt}</M>
                <M style={{color:C.td,display:"block",marginBottom:4,fontSize:10,fontFamily:"monospace",wordBreak:"break-all"}}>{rpPreview.format_version===2?("manifest "+(rpPreview.manifestSha256||"").slice(0,32)+"..."):("hash "+(rpPreview.hash||"").slice(0,32)+"...")}</M>
                {rpPreview.manifestParseError&&(<M style={{color:C.d,display:"block",marginBottom:4,fontSize:11}}>! Manifest parse error: {rpPreview.manifestParseError}</M>)}
                {rpPreview.warning&&(<M style={{color:C.w,display:"block",marginTop:6,fontSize:11,lineHeight:1.5}}>{rpPreview.warning}</M>)}
                <Btn danger style={{marginTop:10}} onClick={async()=>{const hash8=((rpPreview.hash||rpPreview.manifestSha256)||"").slice(0,8);const isChain=rpPreview.type==="incremental"||rpPreview.type==="differential";const path=isChain?("/api/restore/execute-chain/"+rpPreview.id):("/api/restore/execute/"+rpPreview.id);if(!window.confirm("EXECUTE RESTORE from "+rpPreview.id+"?\n\n"+(isChain?"This restores the full backup chain up to this point. ":"")+"This replaces the live database and is IRREVERSIBLE. A pre-restore snapshot is saved automatically."+(rpPreview.format_version===2?" Restart the GD Server afterward.":"")+"\n\nYou will be prompted to confirm with your hardware key.")){return;}const r=await stepUp(path,{confirmHash:hash8});if(r.error){addA("RP_EXECUTE_FAIL",r.error);}else{addA("RP_EXECUTED",(isChain?"chain-restored ":"restored ")+rpPreview.id+(r.pre_restore_snapshot_path?(" - snapshot "+r.pre_restore_snapshot_path):""));setRpPreview(null);setRestorePoints([]);}}}>Execute Restore (Hardware-Key Step-Up)</Btn>
              </Card>)}
            </Card>
            <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><div style={{fontSize:13,fontWeight:600,color:C.d}}>Backup Signing Keys</div><div style={{display:"flex",gap:6}}><Btn small onClick={async()=>{const r=await api.get("/api/backup/signing-keys");if(r.error){addA("BSK_LIST_FAIL",r.error);}else{setBskKeys(r.keys||[]);}}}>Refresh</Btn><Btn small onClick={async()=>{if(!window.confirm("Rotate the local backup signing key? New backups will be signed by a fresh keypair; existing backups remain verifiable by the rotated-out key.")){return;}const r=await api.post("/api/backup/signing-keys/rotate");if(r.error){addA("BSK_ROTATE_FAIL",r.error);}else{addA("BSK_ROTATED","new id="+((r.key&&r.key.id)||"?"));const rr=await api.get("/api/backup/signing-keys");if(!rr.error)setBskKeys(rr.keys||[]);}}}>Rotate Local Key</Btn></div></div>
              <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:11,lineHeight:1.5}}>The local-generated key signs new backups created here. External-registered keys are foreign deployments' public keys, registered so backups signed by those deployments can be verified for cross-deployment restore. Confirm a foreign key's fingerprint out-of-band before registering it.</M>
              {bskKeys.length>0&&(<div style={{maxHeight:280,overflowY:"auto",border:`1px solid ${C.b}`,borderRadius:6,marginBottom:10}}>{bskKeys.map((k,i)=>(<div key={k.id} style={{padding:"10px 12px",borderTop:i===0?"none":`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}><div style={{flex:1,minWidth:0}}><div style={{display:"flex",gap:6,marginBottom:4,flexWrap:"wrap"}}><Badge color={k.keyOrigin==="local-generated"?C.d:C.p}>{k.keyOrigin==="local-generated"?"LOCAL":"EXTERNAL"}</Badge>{k.isActive&&(<Badge color={C.a}>ACTIVE</Badge>)}{k.rotatedOutAt&&(<Badge color={C.d}>{k.keyOrigin==="local-generated"?"ROTATED OUT":"REVOKED"}</Badge>)}</div><M style={{color:C.t,fontSize:11,fontFamily:"monospace",wordBreak:"break-all"}}>fp {k.publicKeyFingerprint||"(none)"}</M>{k.keyLabel&&(<M style={{color:C.tm,display:"block",fontSize:11,marginTop:2}}>{k.keyLabel}</M>)}<M style={{color:C.td,display:"block",fontSize:11,marginTop:2}}>id {k.id} - {k.backupsSignedCount||0} backups signed - created {k.createdAt}{k.registeredByUserId?" - registered by "+k.registeredByUserId:""}</M></div></div>))}</div>)}
              {!bskShowAdd&&(<Btn small onClick={()=>{setBskShowAdd(true);setBskPasteText("");setBskLabel("");}}>Register Foreign Public Key</Btn>)}
              {bskShowAdd&&(<Card style={{marginTop:8,padding:12,background:"rgba(0,0,0,0.2)"}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Register Foreign Deployment Public Key</div>
                <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:11,lineHeight:1.5}}>Paste the originating deployment's PEM-encoded public key. Only register a key whose fingerprint you have verified through a separate trusted channel; the server computes and records the fingerprint on registration.</M>
                <textarea value={bskPasteText} onChange={e=>setBskPasteText(e.target.value)} placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"} style={{width:"100%",minHeight:120,padding:8,background:"rgba(0,0,0,0.3)",color:C.t,border:`1px solid ${C.b}`,borderRadius:4,fontFamily:"monospace",fontSize:11,marginBottom:8,resize:"vertical",boxSizing:"border-box"}}/>
                <Input label="Label (optional)" value={bskLabel} onChange={e=>setBskLabel(e.target.value)} placeholder="e.g. prod-east deployment, key from 2026-04-15"/>
                <div style={{display:"flex",gap:6,marginTop:8}}>
                  <Btn small primary disabled={!bskPasteText.trim()} onClick={async()=>{if(!window.confirm("Register this foreign public key? Only proceed if you have confirmed its fingerprint out-of-band. Backups signed by this key will then be accepted for cross-deployment restore here.")){return;}const r=await api.post("/api/backup/signing-keys/register-external",{publicKeyPem:bskPasteText,keyLabel:bskLabel||null});if(r.error){addA("BSK_REGISTER_FAIL",r.error);window.alert("Registration failed: "+r.error);}else{addA("BSK_REGISTERED","id="+((r.key&&r.key.id)||"?")+" fp="+(((r.key&&r.key.publicKeyFingerprint)||"")).slice(0,16));setBskShowAdd(false);setBskPasteText("");setBskLabel("");const rr=await api.get("/api/backup/signing-keys");if(!rr.error)setBskKeys(rr.keys||[]);}}}>Confirm and Register</Btn>
                  <Btn small onClick={()=>{setBskShowAdd(false);setBskPasteText("");setBskLabel("");}}>Cancel</Btn>
                </div>
              </Card>)}
            </Card>
            <Card style={{marginBottom:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Configuration Snapshots</div>
                <div style={{display:"flex",gap:6}}>
                  <Btn small onClick={loadConfigBaseline}>Refresh</Btn>
                  <Btn small primary disabled={cbBusy} onClick={async()=>{const name=window.prompt("Name this configuration snapshot:");if(name===null)return;setCbBusy(true);const r=await api.post("/api/config-baseline",{name:name||null});setCbBusy(false);if(r.error){addA("CB_SAVE_FAIL",r.error);}else{addA("CB_SAVED","id="+((r.id||(r.snapshot&&r.snapshot.id))||"?"));loadConfigBaseline();}}}>Save Current</Btn>
                  <Btn small disabled={cbBusy} onClick={async()=>{const bundle=window.prompt("Paste the exported golden-baseline bundle (JSON):");if(bundle===null||!bundle.trim())return;let parsed;try{parsed=JSON.parse(bundle);}catch(e){window.alert("Not valid JSON.");return;}if(!window.confirm("Import this golden baseline? You will be prompted for a hardware-key step-up. Importing records the snapshot; use Revert on it to apply.")){return;}setCbBusy(true);const r=await stepUp("/api/config-baseline/import",{bundle:parsed});setCbBusy(false);if(r.error){addA("CB_IMPORT_FAIL",r.error);window.alert("Import failed: "+r.error);}else{addA("CB_IMPORTED","id="+((r.id||(r.snapshot&&r.snapshot.id))||"?"));loadConfigBaseline();}}}>Import Baseline</Btn>
                </div>
              </div>
              {cbRetention!=null&&(<M style={{color:C.td,display:"block",fontSize:11,marginBottom:8}}>Keeping up to {cbRetention} snapshots; saving past the cap prunes the oldest manual snapshot.</M>)}
              {configSnapshots.length===0&&(<M style={{color:C.td,display:"block",padding:"8px 0"}}>No snapshots yet. Save the current configuration to create one.</M>)}
              {configSnapshots.map(s=>(
                <div key={s.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
                  <div style={{flex:1,minWidth:0}}>
                    <M style={{color:C.t}}>{s.name||"(unnamed)"}</M>
                    {s.origin&&s.origin!=="manual"&&(<span style={{marginLeft:6}}><Badge color={C.w}>{(s.origin||"").toUpperCase()}</Badge></span>)}
                    <br/><M style={{color:C.td,fontSize:11}}>{s.created_at} - v{s.app_version||"?"} - {(s.sha256||"").slice(0,12)}...</M>
                  </div>
                  <div style={{display:"flex",gap:6,flexShrink:0}}>
                    <Btn small onClick={async()=>{const r=await api.get("/api/config-baseline/"+s.id+"/diff");if(r.error){addA("CB_DIFF_FAIL",r.error);}else{setCbDiff({snapshot:s,diff:r.diff});}}}>Change Report</Btn>
                    <Btn small onClick={()=>{window.open(gdServerUrl+"/api/config-baseline/"+s.id+"/export","_blank");}}>Export</Btn>
                    <Btn small disabled={cbBusy} onClick={async()=>{if(!window.confirm("Revert live configuration to \""+(s.name||s.id)+"\"? This replaces current config keys with the snapshot. You will be prompted for a hardware-key step-up.")){return;}setCbBusy(true);const r=await stepUp("/api/config-baseline/"+s.id+"/revert",{});setCbBusy(false);if(r.error){addA("CB_REVERT_FAIL",r.error);window.alert("Revert failed: "+r.error);}else{addA("CB_REVERTED","id="+s.id);loadConfigBaseline();}}}>Revert</Btn>
                    <Btn small danger disabled={cbBusy} onClick={async()=>{if(!window.confirm("Delete snapshot \""+(s.name||s.id)+"\"?")){return;}const r=await api.del("/api/config-baseline/"+s.id);if(r.error){addA("CB_DELETE_FAIL",r.error);}else{addA("CB_DELETED","id="+s.id);loadConfigBaseline();}}}>Delete</Btn>
                  </div>
                </div>
              ))}
            </Card>
            {cbDiff&&(<Card style={{marginBottom:16,borderColor:C.i+"40"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Change Report: current vs "{cbDiff.snapshot.name||cbDiff.snapshot.id}"</div>
                <Btn small onClick={()=>setCbDiff(null)}>Close</Btn>
              </div>
              {cbDiff.diff&&(cbDiff.diff.changed||[]).length===0&&(cbDiff.diff.added||[]).length===0&&(cbDiff.diff.removed||[]).length===0&&(<M style={{color:C.a,display:"block"}}>No differences. The current configuration matches this snapshot.</M>)}
              {cbDiff.diff&&(cbDiff.diff.changed||[]).map((d,i)=>(<div key={"c"+i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.w,fontFamily:"monospace",fontSize:11}}>changed {d.path}</M><br/><M style={{color:C.td,fontSize:11}}>now {String(d.current)} -- baseline {String(d.baseline)}</M></div>))}
              {cbDiff.diff&&(cbDiff.diff.added||[]).map((d,i)=>(<div key={"a"+i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a,fontFamily:"monospace",fontSize:11}}>added {d.path}</M><br/><M style={{color:C.td,fontSize:11}}>baseline {String(d.baseline)}</M></div>))}
              {cbDiff.diff&&(cbDiff.diff.removed||[]).map((d,i)=>(<div key={"r"+i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.d,fontFamily:"monospace",fontSize:11}}>removed {d.path}</M><br/><M style={{color:C.td,fontSize:11}}>now {String(d.current)}</M></div>))}
            </Card>)}
          </div>)}

          {tab==="data_sov"&&(<div>
            <L>Data Sovereignty &amp; Geo-Fencing</L>
            <M style={{color:C.tm,display:"block",marginBottom:16}}>Where this Global Dashboard's own backups and archives are permitted to reside, and where the managed console fleet sits. Enforcement applies to the GD's routed storage destinations; fleet residency is recorded and surfaced for review, never used to block a management console. Sourced from <code>/api/data-residency/posture</code>.</M>
            {dataSovCfg&&(<Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:12}}>Configure residency policy</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                <Sel label="Enforcement" value={dataSovCfg.enabled?"on":"off"} onChange={e=>setDataSovCfg({...dataSovCfg,enabled:e.target.value==="on"})}>
                  <option value="off">Off — record only</option>
                  <option value="on">On — enforce policy</option>
                </Sel>
                <Sel label="Declared primary residency" value={(dataSovCfg.primaryResidency&&dataSovCfg.primaryResidency.country)||""} onChange={e=>setDataSovCfg({...dataSovCfg,primaryResidency:{...(dataSovCfg.primaryResidency||{}),country:e.target.value||null}})}>
                  <option value="">Not set</option>
                  {[["US","United States"],["CA","Canada"],["GB","United Kingdom"],["DE","Germany"],["FR","France"],["CH","Switzerland"],["SE","Sweden"],["IE","Ireland"],["IL","Israel"],["AE","United Arab Emirates"],["IN","India"],["SG","Singapore"],["JP","Japan"],["KR","South Korea"],["AU","Australia"],["ZA","South Africa"],["BR","Brazil"]].map(o=><option key={o[0]} value={o[0]}>{o[1]} ({o[0]})</option>)}
                </Sel>
              </div>
              <div style={{fontSize:11,color:C.tm,margin:"2px 0 10px"}}>Per-category rules. Permitted regions are comma-separated ISO country codes or blocs (e.g. US, EU, UK, EEA). Enforce blocks a non-compliant destination; warn records it.</div>
              {["backup","audit_log","forensic_export","snapshot","cef_archive"].map(cat=>{
                const sc=(dataSovCfg.categories&&dataSovCfg.categories[cat])||{mode:"warn",permittedRegions:[]};
                return <div key={cat} style={{display:"grid",gridTemplateColumns:"150px 110px 1fr",gap:10,alignItems:"center",marginBottom:8}}>
                  <M style={{color:C.tm}}>{cat}</M>
                  <select value={sc.mode||"warn"} onChange={e=>setDataSovCat(cat,"mode",e.target.value)} style={{padding:8,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11}}>
                    <option value="warn">warn</option><option value="enforce">enforce</option>
                  </select>
                  <input value={(sc.permittedRegions||[]).join(", ")} onChange={e=>setDataSovCat(cat,"permittedRegions",e.target.value.split(",").map(s=>s.trim()).filter(Boolean))} placeholder="US, EU" style={{padding:8,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11}}/>
                </div>;
              })}
              <div style={{display:"flex",gap:12,alignItems:"center",marginTop:12}}>
                <Btn primary disabled={dataSovSaving} onClick={saveDataSovCfg}>{dataSovSaving?"Saving...":"Save policy"}</Btn>
                {dataSovMsg&&<M style={{color:dataSovMsg.ok?C.a:C.d}}>{dataSovMsg.text}</M>}
              </div>
            </Card>)}
            {!dataSov?<M style={{color:C.tm}}>Loading residency posture...</M>:(<div>
              <Card>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                  <div style={{fontSize:13,fontWeight:600,color:C.t}}>Residency policy</div>
                  <Badge color={dataSov.enabled?C.a:C.td}>{dataSov.enabled?"ENFORCED":"OFF"}</Badge>
                </div>
                <M style={{color:C.tm,display:"block"}}>Declared primary residency: <span style={{color:C.t}}>{dataSov.primaryResidency.declared.country||"not set"}</span>{dataSov.primaryResidency.declared.region?" · "+dataSov.primaryResidency.declared.region:""}{dataSov.primaryResidency.declared.providerDomicile?" · provider "+dataSov.primaryResidency.declared.providerDomicile:""}</M>
              </Card>

              <div style={{fontSize:13,fontWeight:600,color:C.t,margin:"18px 0 8px"}}>Routed storage destinations</div>
              {(!dataSov.destinations||dataSov.destinations.length===0)?<M style={{color:C.td,fontStyle:"italic"}}>No storage destinations configured yet.</M>:dataSov.destinations.map(d=>(
                <Card key={d.ref} style={{padding:"12px 16px"}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <div><span style={{color:C.t,fontSize:12,fontWeight:600}}>{d.name}</span> <M style={{color:C.td}}>({d.adapter})</M></div>
                    <Badge color={d.blocked?C.d:d.compliant?C.a:C.w}>{d.blocked?"BLOCKED":d.compliant?"COMPLIANT":"REVIEW"}</Badge>
                  </div>
                  <M style={{color:C.tm,display:"block",marginTop:4}}>Jurisdiction: {d.jurisdiction||"undeclared"}{d.providerDomicile?" · provider "+d.providerDomicile:""}{d.reason?" — "+d.reason:""}</M>
                </Card>
              ))}

              <div style={{fontSize:13,fontWeight:600,color:C.t,margin:"18px 0 8px"}}>Console fleet residency</div>
              <M style={{color:C.td,display:"block",marginBottom:10}}>{dataSov.fleet.total} active console(s) · {dataSov.fleet.crossBorder} with a cross-border flow to this GD. Recorded and surfaced; never blocks a management console.</M>
              {dataSov.fleet.consoles.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No active management consoles.</M>:dataSov.fleet.consoles.map(c=>(
                <Card key={c.id} style={{padding:"10px 16px",marginBottom:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <div><span style={{color:C.t,fontSize:12}}>{c.name}</span> <M style={{color:C.td}}> · {c.region}</M></div>
                    <Badge color={c.crossBorder?C.w:C.a}>{c.crossBorder?"CROSS-BORDER":"IN-REGION"}</Badge>
                  </div>
                  <M style={{color:C.tm,display:"block",marginTop:3}}>Jurisdiction: {c.country||"undeclared"} · framework: {c.regulatoryFramework}</M>
                </Card>
              ))}

              <div style={{fontSize:13,fontWeight:600,color:C.t,margin:"18px 0 8px"}}>Cross-border transfer register</div>
              <Card style={{padding:"12px 16px"}}>
                <M style={{color:C.tm}}>{dataSov.register.transfers} transfer(s) recorded · {dataSov.register.documented} documented · {dataSov.register.blocked} blocked by policy.</M>
              </Card>
            </div>)}
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

          {/* ══════════ COMPLIANCE POSTURE (PR4 C2: selector + fetch; C3-C4 add report rendering) ══════════ */}
          {tab==="compliance_posture"&&(<div>
            <L>Compliance Posture</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>The Global Dashboard's own compliance posture across 16 frameworks. Each framework returns technical-control verification (automated) plus enumerated customer-managed responsibilities (operator-attested). Reports here describe THIS GD instance — not aggregated cross-region results. See Cross-Region Compliance for the matrix view of all connected MCs.</M>
            <Card>
              <Sel label="Framework" value={postureFramework} onChange={e=>setPostureFramework(e.target.value)} disabled={postureLoading}>
                <option value="">Select a framework...</option>
                {COMPLIANCE_FRAMEWORKS.map(f=><option key={f.id} value={f.id}>{f.label}</option>)}
              </Sel>
              <Btn primary disabled={postureLoading||!postureFramework} onClick={async()=>{
                setPostureLoading(true);
                setPostureError(null);
                setPostureReport(null);
                const r = await api.get("/api/compliance/report/"+encodeURIComponent(postureFramework));
                setPostureLoading(false);
                if (r && r.error) {
                  setPostureError(typeof r.error === "string" ? r.error : "Failed to generate report");
                  return;
                }
                setPostureReport(r);
                showGdToast("Report generated for "+postureFramework);
              }}>{postureLoading?"Generating...":"Generate Report"}</Btn>
            </Card>
            {postureError&&<Card style={{borderColor:C.d+"40"}}><M style={{color:C.d}}>{postureError}</M></Card>}
            {postureLoading&&<Card><M style={{color:C.tm,fontStyle:"italic"}}>Loading {postureFramework} compliance report...</M></Card>}
            {postureReport&&!postureLoading&&(<>
              {/* Framework header */}
              <Card style={{marginBottom:12}}>
                <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:6,fontFamily:"'Fraunces',serif"}}>{postureReport.framework}</div>
                {postureReport.authority&&<M style={{color:C.tm,display:"block",marginBottom:4}}>{postureReport.authority}</M>}
                {postureReport.citation&&<M style={{color:C.td,display:"block",marginBottom:6,fontSize:10}}>{postureReport.citation}</M>}
                <M style={{color:C.td,display:"block",fontSize:10}}>Generated {postureReport.generatedAt?new Date(postureReport.generatedAt).toLocaleString():"—"} · GD v{postureReport.appVersion||"—"}</M>
                {postureReport.note&&<M style={{color:C.i,display:"block",marginTop:8,fontSize:10,fontStyle:"italic"}}>{postureReport.note}</M>}
                <div style={{display:"flex",gap:8,marginTop:12}}>
                  <Btn small primary onClick={async()=>{
                    const ok=await api.download("/api/compliance/report/"+encodeURIComponent(postureFramework)+"?format=pdf","firealive-gd-compliance-"+postureFramework+"-"+new Date().toISOString().slice(0,10)+".pdf");
                    showGdToast(ok?"Signed PDF downloaded":"PDF download failed");
                  }}>Download PDF</Btn>
                  <Btn small onClick={async()=>{
                    const ok=await api.download("/api/compliance/report/"+encodeURIComponent(postureFramework)+"?format=docx","firealive-gd-compliance-"+postureFramework+"-"+new Date().toISOString().slice(0,10)+".docx");
                    showGdToast(ok?"Signed DOCX downloaded":"DOCX download failed");
                  }}>Download DOCX</Btn>
                </div>
              </Card>

              {/* Summary: 4-up verified counts + customerResponsibility total */}
              <Card style={{marginBottom:12}}>
                <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:10}}>Summary</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:12}}>
                  {[
                    {l:"Total",v:postureReport.summary?.total??0,c:C.t},
                    {l:"Pass",v:postureReport.summary?.passed??0,c:C.a},
                    {l:"Warn",v:postureReport.summary?.warnings??0,c:C.w},
                    {l:"Fail",v:postureReport.summary?.failed??0,c:C.d},
                  ].map(m=><div key={m.l} style={{textAlign:"center",padding:"8px 0",background:"rgba(0,0,0,0.15)",borderRadius:6}}><div style={{fontSize:18,fontWeight:600,color:m.c,fontFamily:"'IBM Plex Mono',monospace"}}>{m.v}</div><M style={{color:C.td}}>{m.l}</M></div>)}
                </div>
                <M style={{color:C.tm,display:"block"}}>Verified controls (automated): <span style={{color:C.t}}>{postureReport.summary?.verified?.total??0}</span></M>
                <M style={{color:C.tm,display:"block",marginTop:4}}>Customer responsibilities (operator-attested): <span style={{color:C.t}}>{postureReport.summary?.customerResponsibility?.total??0}</span></M>
                {postureReport.summary?.customerResponsibility?.byCategory&&Object.keys(postureReport.summary.customerResponsibility.byCategory).length>0&&<div style={{marginTop:8,paddingTop:8,borderTop:`1px solid ${C.b}`,display:"flex",flexWrap:"wrap",gap:6}}>
                  {Object.entries(postureReport.summary.customerResponsibility.byCategory).map(([cat,count])=><Badge key={cat} color={C.p}>{cat}: {count}</Badge>)}
                </div>}
              </Card>

              {/* verifiedControls list */}
              <Card>
                <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:10}}>Verified Controls ({postureReport.verifiedControls?.length||0})</div>
                {(!postureReport.verifiedControls||postureReport.verifiedControls.length===0)&&<M style={{color:C.td,fontStyle:"italic"}}>No verified controls in this framework.</M>}
                {postureReport.verifiedControls&&postureReport.verifiedControls.map((ctrl,i)=>{
                  const statusColor = ctrl.status==="pass"?C.a:ctrl.status==="warning"?C.w:C.d;
                  const statusLabel = ctrl.status==="pass"?"PASS":ctrl.status==="warning"?"WARN":ctrl.status==="fail"?"FAIL":ctrl.status==="error"?"ERROR":(ctrl.status||"?").toUpperCase();
                  return <div key={ctrl.controlId||i} style={{padding:"10px 0",borderBottom:i<postureReport.verifiedControls.length-1?`1px solid ${C.b}`:"none"}}>
                    <div style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:6}}>
                      <Badge color={statusColor}>{statusLabel}</Badge>
                      <div style={{flex:1,minWidth:0}}>
                        <M style={{color:C.t,fontWeight:500,display:"block"}}>{ctrl.controlId} — {ctrl.controlName}</M>
                      </div>
                    </div>
                    {ctrl.mapping&&<M style={{color:C.tm,display:"block",marginBottom:4,fontSize:10,lineHeight:1.5}}>Mapping: {ctrl.mapping}</M>}
                    {ctrl.detail&&<M style={{color:ctrl.status==="pass"?C.tm:C.t,display:"block",marginBottom:4,fontSize:10,lineHeight:1.5}}>Detail: {ctrl.detail}</M>}
                    {ctrl.remediation&&<div style={{marginTop:6,padding:"8px 10px",background:"rgba(245,158,11,0.06)",borderLeft:`2px solid ${C.w}`,borderRadius:4}}>
                      <M style={{color:C.w,fontWeight:500,display:"block",marginBottom:4,fontSize:10}}>Remediation: {ctrl.remediation.summary}</M>
                      {ctrl.remediation.steps&&ctrl.remediation.steps.length>0&&<ol style={{margin:"4px 0 0 16px",padding:0}}>{ctrl.remediation.steps.map((s,j)=><li key={j} style={{fontSize:10,color:C.tm,fontFamily:"'IBM Plex Mono',monospace",lineHeight:1.5,marginBottom:2}}>{s}</li>)}</ol>}
                      {ctrl.remediation.uiPath&&<M style={{color:C.i,display:"block",marginTop:4,fontSize:9}}>UI: {ctrl.remediation.uiPath}</M>}
                    </div>}
                  </div>;
                })}
              </Card>

              {/* customerResponsibility list */}
              <Card>
                <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:6}}>Customer Responsibility ({postureReport.customerResponsibility?.length||0})</div>
                <M style={{color:C.tm,display:"block",marginBottom:12,fontSize:10,lineHeight:1.5}}>Operator-attested duties — controls the platform cannot verify on your behalf. Enumerated here so an auditor or CISO can see the complete framework surface in one report. The CISO and operations leads should track these against internal policy + evidence binders.</M>
                {(!postureReport.customerResponsibility||postureReport.customerResponsibility.length===0)&&<M style={{color:C.td,fontStyle:"italic"}}>No customer-responsibility items in this framework.</M>}
                {postureReport.customerResponsibility&&postureReport.customerResponsibility.map((item,i)=><div key={item.id||i} style={{padding:"10px 0",borderBottom:i<postureReport.customerResponsibility.length-1?`1px solid ${C.b}`:"none"}}>
                  <div style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:6}}>
                    <Badge color={C.p}>{item.category||"—"}</Badge>
                    <div style={{flex:1,minWidth:0}}>
                      <M style={{color:C.t,fontWeight:500,display:"block"}}>{item.id} — {item.name}</M>
                    </div>
                  </div>
                  {item.detail&&<M style={{color:C.tm,display:"block",fontSize:10,lineHeight:1.5}}>{item.detail}</M>}
                </div>)}
              </Card>
            </>)}
            {!postureFramework&&!postureLoading&&!postureError&&!postureReport&&<Card>
              <M style={{color:C.td,fontStyle:"italic"}}>Select a framework above and click Generate Report to see this GD's compliance posture.</M>
            </Card>}
          </div>)}

          {/* ══════════ CROSS-REGION COMPLIANCE (PR4 C5: rollup matrix; C6-C10 add filters + drilldown + mailbox UI) ══════════ */}
          {tab==="compliance_xregion"&&(<div>
            <L>Cross-Region Compliance</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Aggregated compliance posture across every connected Regional MC. CISOs can review the framework x MC matrix, drill into a specific MC's last-pushed summary, request a fresh full report via the mailbox pattern, and inspect per-control detail when fulfilled. MCs push compliance summaries on their configured cadence (default 24h); full reports arrive on the next MC tick after a CISO request.</M>
            {/* Top-of-tab pending banner (PR4 C10) — visible regardless of matrix state. */}
            {submittedRequests.length>0&&<Card style={{marginBottom:12,borderColor:C.i+"40"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:12,fontWeight:500,color:C.i}}>{submittedRequests.length} full-report request{submittedRequests.length===1?"":"s"} pending fulfillment</div>
                <Btn small disabled={rollupLoading} onClick={()=>{
                  setRollupLoading(true);
                  setRollupError(null);
                  api.get('/api/compliance/rollup').then(r=>{
                    if (r && !r.error && Array.isArray(r.rollups)) setRollupData(r.rollups);
                    else setRollupError(r?.error || 'Failed to load cross-region rollup');
                  }).finally(()=>setRollupLoading(false));
                }}>{rollupLoading?"Refreshing...":"Refresh matrix"}</Btn>
              </div>
              {submittedRequests.map((req,i)=>{
                const f = COMPLIANCE_FRAMEWORKS.find(x=>x.id===req.framework);
                return <div key={req.requestId} style={{padding:"6px 0",borderBottom:i<submittedRequests.length-1?`1px solid ${C.b}`:"none",display:"flex",alignItems:"center",gap:8}}>
                  <div style={{flex:1,minWidth:0}}>
                    <M style={{color:C.t,fontWeight:500,display:"block",fontSize:11}}>#{req.requestId} · {req.mc_id} / {f?f.label:req.framework}</M>
                    <M style={{color:C.td,display:"block",fontSize:9}}>submitted {req.requested_at?new Date(req.requested_at).toLocaleString():"just now"}</M>
                  </div>
                  <Btn small onClick={()=>setSubmittedRequests(prev=>prev.filter(r=>r.requestId!==req.requestId))}>Dismiss</Btn>
                </div>;
              })}
              <M style={{color:C.td,display:"block",marginTop:8,fontSize:9,fontStyle:"italic"}}>Dismissing clears the local tracker only — the request still exists on the GD-side mailbox and the MC will fulfill on its next compliance tick.</M>
            </Card>}
            {rollupError&&<Card style={{borderColor:C.d+"40"}}><M style={{color:C.d}}>{rollupError}</M></Card>}
            {rollupLoading&&<Card><M style={{color:C.tm,fontStyle:"italic"}}>Loading cross-region rollup...</M></Card>}
            {rollupData&&!rollupLoading&&rollupData.length===0&&<Card>
              <M style={{color:C.td,fontStyle:"italic"}}>No compliance data yet. Active MCs push compliance summaries on their configured cadence (default 24h); once the first push lands, this matrix will populate. Verify MC connections in the MC Connections tab.</M>
            </Card>}
            {rollupData&&!rollupLoading&&rollupData.length>0&&(()=>{
              // Distinct MC + region option sets, derived from the unfiltered
              // rollupData so dropdown options stay stable across filter changes.
              const seenMcs = new Map();
              const seenRegions = new Set();
              rollupData.forEach(c=>{
                if (c.mc_id && !seenMcs.has(c.mc_id)) seenMcs.set(c.mc_id, c.mc_name||c.mc_id);
                if (c.region) seenRegions.add(c.region);
              });
              const mcOptions = [...seenMcs.entries()].sort((a,b)=>a[0].localeCompare(b[0]));
              const regionOptions = [...seenRegions].sort();
              const filterActive = !!(rollupFilterFramework||rollupFilterMcId||rollupFilterRegion);

              // Apply filters client-side. Empty filter string = no filter.
              const filtered = rollupData.filter(c=>{
                if (rollupFilterFramework && c.framework !== rollupFilterFramework) return false;
                if (rollupFilterMcId && c.mc_id !== rollupFilterMcId) return false;
                if (rollupFilterRegion && c.region !== rollupFilterRegion) return false;
                return true;
              });

              // Group filtered cells by framework, preserving server-side order.
              const grouped = {};
              const order = [];
              filtered.forEach(c=>{
                if (!grouped[c.framework]) { grouped[c.framework] = []; order.push(c.framework); }
                grouped[c.framework].push(c);
              });
              const frameworkLabel = (id) => {
                const f = COMPLIANCE_FRAMEWORKS.find(x=>x.id===id);
                return f ? f.label : id;
              };
              return <>
                {/* Filter controls */}
                <Card style={{marginBottom:12}}>
                  <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:10}}>Filters</div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr",gap:0}}>
                    <Sel label="Framework" value={rollupFilterFramework} onChange={e=>setRollupFilterFramework(e.target.value)}>
                      <option value="">All frameworks</option>
                      {COMPLIANCE_FRAMEWORKS.map(f=><option key={f.id} value={f.id}>{f.label}</option>)}
                    </Sel>
                    <Sel label="MC" value={rollupFilterMcId} onChange={e=>setRollupFilterMcId(e.target.value)}>
                      <option value="">All MCs</option>
                      {mcOptions.map(([id,name])=><option key={id} value={id}>{name} ({id})</option>)}
                    </Sel>
                    <Sel label="Region" value={rollupFilterRegion} onChange={e=>setRollupFilterRegion(e.target.value)}>
                      <option value="">All regions</option>
                      {regionOptions.map(r=><option key={r} value={r}>{r}</option>)}
                    </Sel>
                  </div>
                  {filterActive&&<Btn small onClick={()=>{setRollupFilterFramework("");setRollupFilterMcId("");setRollupFilterRegion("");}}>Clear filters</Btn>}
                </Card>
                <Card style={{marginBottom:12,padding:"10px 14px"}}>
                  <M style={{color:C.tm}}>{filtered.length} of {rollupData.length} rollup cell{rollupData.length===1?"":"s"} {filterActive?"shown after filter ":""}across {order.length} framework{order.length===1?"":"s"}.</M>
                </Card>
                {filtered.length===0&&<Card>
                  <M style={{color:C.td,fontStyle:"italic"}}>No cells match the active filter. Clear the filter to see all rollup data.</M>
                </Card>}
                {order.map(fw=><Card key={fw} style={{marginBottom:10}}>
                  <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:10}}>{frameworkLabel(fw)} <span style={{color:C.td,fontWeight:400}}>({grouped[fw].length} MC{grouped[fw].length===1?"":"s"})</span></div>
                  {grouped[fw].map((cell,i)=>{
                    const ratio = cell.total>0 ? cell.passed/cell.total : 0;
                    const statColor = ratio>=0.9?C.a:ratio>=0.7?C.w:C.d;
                    const isOpen = selectedCell && selectedCell.mc_id===cell.mc_id && selectedCell.framework===cell.framework;
                    const isPending = submittedRequests.some(r=>r.mc_id===cell.mc_id&&r.framework===cell.framework);
                    return <div key={cell.mc_id}>
                      <div onClick={()=>{setSelectedReportId(null);setSelectedCell(isOpen?null:{mc_id:cell.mc_id,framework:cell.framework});}} style={{borderBottom:!isOpen&&i<grouped[fw].length-1?`1px solid ${C.b}`:"none",display:"flex",alignItems:"center",gap:10,cursor:"pointer",background:isOpen?"rgba(110,231,183,0.04)":"transparent",margin:isOpen?"0 -10px":"0",padding:isOpen?"8px 10px":"8px 0",borderRadius:isOpen?6:0}}>
                        <div style={{flex:1,minWidth:0}}>
                          <M style={{color:C.t,fontWeight:500,display:"block"}}>{cell.mc_name||cell.mc_id}</M>
                          <M style={{color:C.td,display:"block",fontSize:10}}>{cell.mc_id} · {cell.region||"—"}</M>
                        </div>
                        <div style={{textAlign:"right",minWidth:90}}>
                          <M style={{color:statColor,fontWeight:600,fontSize:13,fontFamily:"'IBM Plex Mono',monospace"}}>{cell.passed}/{cell.total}</M>
                          <M style={{color:C.td,display:"block",fontSize:9}}>{cell.last_push_at?new Date(cell.last_push_at).toLocaleString():"never"}</M>
                        </div>
                        {isPending&&<Badge color={C.i}>PENDING</Badge>}
                        {cell.has_drilldown&&<Badge color={C.i}>FULL</Badge>}
                        <M style={{color:C.td,fontSize:14,marginLeft:4}}>{isOpen?"▾":"▸"}</M>
                      </div>
                      {isOpen&&<div style={{padding:"10px 10px 4px",margin:"0 -10px 8px",background:"rgba(0,0,0,0.15)",borderLeft:`2px solid ${C.a}`,borderRadius:"0 6px 6px 0"}}>
                        <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:10}}>Full reports for {cell.mc_name||cell.mc_id} / {frameworkLabel(cell.framework)}</M>
                        {reportsLoading&&<M style={{color:C.tm,fontStyle:"italic",display:"block"}}>Loading full-report history...</M>}
                        {reportsError&&<M style={{color:C.d,display:"block"}}>{reportsError}</M>}
                        {reportsList&&!reportsLoading&&reportsList.length===0&&<M style={{color:C.td,fontStyle:"italic",display:"block"}}>No full reports yet for this MC + framework.</M>}
                        {reportsList&&!reportsLoading&&reportsList.length>0&&<div>
                          {reportsList.map((rep,j)=>{
                            const expired = rep.expires_at && new Date(rep.expires_at) < new Date();
                            const repOpen = selectedReportId === rep.id;
                            return <div key={rep.id}>
                              <div onClick={()=>setSelectedReportId(repOpen?null:rep.id)} style={{padding:"6px 0",borderBottom:!repOpen&&j<reportsList.length-1?`1px solid ${C.b}`:"none",display:"flex",alignItems:"center",gap:8,cursor:"pointer",background:repOpen?"rgba(96,165,250,0.06)":"transparent",margin:repOpen?"0 -10px":"0",borderRadius:repOpen?4:0}}>
                                <div style={{flex:1,minWidth:0,padding:repOpen?"0 10px":"0"}}>
                                  <M style={{color:C.t,fontWeight:500,display:"block",fontSize:11}}>#{rep.id} · {new Date(rep.received_at).toLocaleString()}</M>
                                  <M style={{color:C.td,display:"block",fontSize:9}}>fp: {rep.signature_fingerprint?String(rep.signature_fingerprint).slice(0,16)+"…":"—"} · {rep.bytes?Math.round(rep.bytes/1024)+" KB":"—"} · expires {rep.expires_at?new Date(rep.expires_at).toLocaleDateString():"—"}</M>
                                </div>
                                {expired&&<Badge color={C.w}>EXPIRED</Badge>}
                                <M style={{color:C.td,fontSize:12,marginRight:repOpen?10:0}}>{repOpen?"▾":"▸"}</M>
                              </div>
                              {repOpen&&<div style={{padding:"10px 12px",margin:"0 -10px 8px",background:"rgba(0,0,0,0.25)",borderLeft:`2px solid ${C.i}`,borderRadius:"0 4px 4px 0"}}>
                                {reportDetailLoading&&<M style={{color:C.tm,fontStyle:"italic",display:"block"}}>Loading report body...</M>}
                                {reportDetailError&&<M style={{color:C.d,display:"block"}}>{reportDetailError}</M>}
                                {reportDetail&&!reportDetailLoading&&(()=>{
                                  const body = reportDetail.data || {};
                                  const sum = body.summary || {};
                                  const vc = Array.isArray(body.verifiedControls) ? body.verifiedControls : [];
                                  const cr = Array.isArray(body.customerResponsibility) ? body.customerResponsibility : [];
                                  return <div>
                                    <M style={{color:C.t,fontWeight:600,display:"block",marginBottom:4,fontSize:11}}>{body.framework||frameworkLabel(reportDetail.framework)}</M>
                                    {body.authority&&<M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>{body.authority}</M>}
                                    {body.citation&&<M style={{color:C.td,display:"block",fontSize:9,marginBottom:6}}>{body.citation}</M>}
                                    <M style={{color:C.td,display:"block",fontSize:9,marginBottom:8,fontFamily:"'IBM Plex Mono',monospace"}}>generated: {body.generatedAt?new Date(body.generatedAt).toLocaleString():"—"} · MC app: {body.appVersion||"—"} · fp: {reportDetail.signature_fingerprint||"—"}</M>
                                    <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6,marginBottom:10}}>
                                      {[
                                        {l:"Total",v:sum.total??0,c:C.t},
                                        {l:"Pass",v:sum.passed??0,c:C.a},
                                        {l:"Warn",v:sum.warnings??0,c:C.w},
                                        {l:"Fail",v:sum.failed??0,c:C.d},
                                      ].map(m=><div key={m.l} style={{textAlign:"center",padding:"6px 0",background:"rgba(0,0,0,0.3)",borderRadius:4}}><div style={{fontSize:14,fontWeight:600,color:m.c,fontFamily:"'IBM Plex Mono',monospace"}}>{m.v}</div><M style={{color:C.td,fontSize:9}}>{m.l}</M></div>)}
                                    </div>
                                    {vc.length>0&&<div style={{marginBottom:10}}>
                                      <M style={{color:C.tm,display:"block",marginBottom:6,fontSize:10,fontWeight:500}}>Verified Controls ({vc.length})</M>
                                      {vc.map((ctrl,k)=>{
                                        const sc = ctrl.status==="pass"?C.a:ctrl.status==="warning"?C.w:C.d;
                                        const sl = ctrl.status==="pass"?"PASS":ctrl.status==="warning"?"WARN":ctrl.status==="fail"?"FAIL":ctrl.status==="error"?"ERROR":(ctrl.status||"?").toUpperCase();
                                        return <div key={ctrl.controlId||k} style={{padding:"6px 0",borderBottom:k<vc.length-1?`1px solid ${C.b}`:"none"}}>
                                          <div style={{display:"flex",alignItems:"flex-start",gap:6,marginBottom:3}}>
                                            <Badge color={sc}>{sl}</Badge>
                                            <M style={{color:C.t,fontWeight:500,flex:1,minWidth:0,fontSize:10}}>{ctrl.controlId} — {ctrl.controlName}</M>
                                          </div>
                                          {ctrl.detail&&<M style={{color:ctrl.status==="pass"?C.tm:C.t,display:"block",fontSize:9,lineHeight:1.5}}>{ctrl.detail}</M>}
                                        </div>;
                                      })}
                                    </div>}
                                    {cr.length>0&&<div>
                                      <M style={{color:C.tm,display:"block",marginBottom:6,fontSize:10,fontWeight:500}}>Customer Responsibility ({cr.length})</M>
                                      {cr.map((item,k)=><div key={item.id||k} style={{padding:"6px 0",borderBottom:k<cr.length-1?`1px solid ${C.b}`:"none"}}>
                                        <div style={{display:"flex",alignItems:"flex-start",gap:6,marginBottom:3}}>
                                          <Badge color={C.p}>{item.category||"—"}</Badge>
                                          <M style={{color:C.t,fontWeight:500,flex:1,minWidth:0,fontSize:10}}>{item.id} — {item.name}</M>
                                        </div>
                                        {item.detail&&<M style={{color:C.tm,display:"block",fontSize:9,lineHeight:1.5}}>{item.detail}</M>}
                                      </div>)}
                                    </div>}
                                  </div>;
                                })()}
                              </div>}
                            </div>;
                          })}
                        </div>}
                        {/* Request Full Report — mailbox-pattern POST per PR3 C33. */}
                        {(()=>{
                          const cellKey = cell.mc_id+"::"+cell.framework;
                          const pending = submittedRequests.find(r=>r.mc_id===cell.mc_id&&r.framework===cell.framework);
                          if (pending) {
                            return <div style={{marginTop:8,padding:"8px 10px",background:"rgba(96,165,250,0.06)",borderLeft:`2px solid ${C.i}`,borderRadius:4}}>
                              <M style={{color:C.i,fontWeight:500,display:"block",fontSize:10}}>Request pending fulfillment</M>
                              <M style={{color:C.tm,display:"block",fontSize:9,marginTop:2}}>request #{pending.requestId} submitted {pending.requested_at?new Date(pending.requested_at).toLocaleString():"just now"}. MC observes pending on its next compliance tick (cadence configured per MC; default 24h). Fulfillment will appear in the reports list above on next refresh.</M>
                            </div>;
                          }
                          return <div style={{marginTop:8,paddingTop:8,borderTop:`1px solid ${C.b}`}}>
                            {submitFullReportError&&<M style={{color:C.d,display:"block",marginBottom:6,fontSize:10}}>{submitFullReportError}</M>}
                            <Btn small primary disabled={submittingFullReport} onClick={async(e)=>{
                              e.stopPropagation();
                              setSubmittingFullReport(true);
                              setSubmitFullReportError(null);
                              const r = await api.post("/api/mc/"+encodeURIComponent(cell.mc_id)+"/full-report-requests",{framework:cell.framework});
                              setSubmittingFullReport(false);
                              if (r && !r.error && r.success && r.requestId) {
                                setSubmittedRequests(prev=>[...prev,{mc_id:cell.mc_id,framework:cell.framework,requestId:r.requestId,requested_at:r.requested_at}]);
                                showGdToast("Full report requested for "+(cell.mc_name||cell.mc_id)+" / "+frameworkLabel(cell.framework));
                              } else {
                                setSubmitFullReportError(r?.error||"Failed to submit full-report request");
                              }
                            }}>{submittingFullReport?"Requesting...":"Request Full Report"}</Btn>
                            <M style={{color:C.td,display:"block",marginTop:4,fontSize:9}}>Writes a pending row to the MC's mailbox. The MC will fulfill on its next compliance tick.</M>
                          </div>;
                        })()}
                      </div>}
                    </div>;
                  })}
                </Card>)}
              </>;
            })()}
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

          {/* ══════════ HELPER RECOGNITION (R3h) ══════════ */}
          {tab==="helper_recognition"&&(<div>
            <L>Helper Recognition</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Cross-region Helper Pay leaderboard. Active MCs push their top opted-in helpers on a configurable cadence (default 15 min); this surface displays the matrix. Only analysts who have explicitly opted in via their AC appear here, and only their pseudonyms cross the wire — real names, user IDs, and earning details stay on the MC. Click a card to drill into that MC's full leaderboard with signature provenance.</M>
            {/* DRILLDOWN MODE — visible when hrDrilldownMcId is set */}
            {hrDrilldownMcId ? (<>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
                <Btn small onClick={()=>{setHrDrilldownMcId(null);setHrDrilldownData(null);setHrDrilldownError(null);}}>{"<-"} Back to matrix</Btn>
                {hrDrilldownData&&<M style={{color:C.t,fontWeight:500}}>{hrDrilldownData.mc_name} <span style={{color:C.td,fontWeight:400}}>· {hrDrilldownData.region||"region-unknown"}</span></M>}
              </div>
              {hrDrilldownLoading&&<Card><M style={{color:C.tm,fontStyle:"italic"}}>Loading per-MC leaderboard...</M></Card>}
              {hrDrilldownError&&<Card style={{borderColor:C.d+"40"}}><M style={{color:C.d}}>{hrDrilldownError}</M></Card>}
              {hrDrilldownData&&!hrDrilldownLoading&&hrDrilldownData.entries.length===0&&(
                <Card><M style={{color:C.td,fontStyle:"italic"}}>This MC has not pushed any leaderboard entries yet, or all helpers on this MC have opted out of leaderboard visibility.</M></Card>
              )}
              {hrDrilldownData&&!hrDrilldownLoading&&hrDrilldownData.entries.length>0&&(
                <Card>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                    <div style={{fontSize:12,fontWeight:500,color:C.t}}>{hrDrilldownData.entry_count} helper{hrDrilldownData.entry_count===1?"":"s"} on the leaderboard</div>
                    <div style={{fontSize:9,color:C.td,fontFamily:"'IBM Plex Mono',monospace"}}>last push: {hrDrilldownData.entries[0]?.pushed_at||"—"}</div>
                  </div>
                  <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>
                    {hrDrilldownData.entries.map((e,i)=>(
                      <div key={i} style={{padding:"10px 14px",borderBottom:i<hrDrilldownData.entries.length-1?`1px solid ${C.b}`:"none",display:"flex",justifyContent:"space-between",alignItems:"center",gap:12}}>
                        <div style={{flex:1,minWidth:0}}>
                          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:2}}>
                            <div style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:C.b,color:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>#{i+1}</div>
                            <M style={{color:C.t,fontWeight:500}}>{e.analyst_pseudonym}</M>
                          </div>
                          <M style={{color:C.td}}>{e.sessions_count} session{e.sessions_count===1?"":"s"} · avg {e.avg_rating!=null?e.avg_rating:"—"}/5</M>
                        </div>
                        <div style={{textAlign:"right",flexShrink:0}}>
                          <div style={{fontSize:18,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace"}}>{e.points}</div>
                          <div style={{fontSize:8,color:C.td,fontFamily:"'IBM Plex Mono',monospace",marginTop:2}} title={"signature_fingerprint: "+e.signature_fingerprint}>{(e.signature_fingerprint||"").slice(0,12)}...</div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <M style={{color:C.td,display:"block",marginTop:10,fontSize:9,fontStyle:"italic"}}>Each row carries the signing fingerprint of the MC push that delivered it (truncated to 12 chars; hover for full value). Used for forensic correlation between this surface and the GD-side audit log.</M>
                </Card>
              )}
            </>) : (<>
              {/* MATRIX MODE — default */}
              {hrMatrixLoading&&<Card><M style={{color:C.tm,fontStyle:"italic"}}>Loading Helper Recognition matrix...</M></Card>}
              {hrMatrixError&&<Card style={{borderColor:C.d+"40"}}><M style={{color:C.d}}>{hrMatrixError}</M></Card>}
              {hrMatrix&&!hrMatrixLoading&&hrMatrix.length===0&&(
                <Card><M style={{color:C.td,fontStyle:"italic"}}>No active MCs are pushing leaderboard data yet. The MC→GD leaderboard push tick fires on a configurable cadence (default 15 min); once the first push from any active MC arrives, this matrix will populate. Verify MC connections in the MC Connections tab.</M></Card>
              )}
              {hrMatrix&&!hrMatrixLoading&&hrMatrix.length>0&&(
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(320px, 1fr))",gap:12}}>
                  {hrMatrix.map(m=>(
                    <Card key={m.mc_id} style={{cursor:"pointer"}} onClick={()=>setHrDrilldownMcId(m.mc_id)}>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
                        <div>
                          <M style={{color:C.t,fontWeight:500,display:"block"}}>{m.mc_name}</M>
                          <M style={{color:C.td}}>{m.region||"region-unknown"}</M>
                        </div>
                        <div style={{fontSize:9,color:C.td,fontFamily:"'IBM Plex Mono',monospace",textAlign:"right"}}>{m.entries.length} entr{m.entries.length===1?"y":"ies"}</div>
                      </div>
                      {m.entries.length===0 ? (
                        <M style={{color:C.td,fontStyle:"italic",fontSize:11}}>No opted-in helpers on this MC.</M>
                      ) : (
                        <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:8,overflow:"hidden",marginBottom:6}}>
                          {m.entries.slice(0,5).map((e,i)=>(
                            <div key={i} style={{padding:"6px 10px",borderBottom:i<Math.min(4,m.entries.length-1)?`1px solid ${C.b}`:"none",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                              <div style={{display:"flex",alignItems:"center",gap:6,minWidth:0,flex:1}}>
                                <div style={{fontSize:8,color:C.td,fontFamily:"'IBM Plex Mono',monospace"}}>#{i+1}</div>
                                <M style={{color:C.t,fontSize:11}}>{e.analyst_pseudonym}</M>
                              </div>
                              <div style={{fontSize:13,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace"}}>{e.points}</div>
                            </div>
                          ))}
                          {m.entries.length>5&&(
                            <div style={{padding:"4px 10px",borderTop:`1px solid ${C.b}`,textAlign:"center"}}>
                              <M style={{color:C.td,fontSize:9,fontStyle:"italic"}}>+{m.entries.length-5} more...</M>
                            </div>
                          )}
                        </div>
                      )}
                      <div style={{fontSize:8,color:C.td,fontFamily:"'IBM Plex Mono',monospace"}}>last push: {m.last_pushed_at||"never"}</div>
                    </Card>
                  ))}
                </div>
              )}
            </>)}
          </div>)}

          {/* ══════════ TROUBLESHOOTER ══════════ */}
          {tab==="troubleshooter"&&(<div>
            <L>Troubleshooter</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Run a comprehensive, read-only diagnostic of the Global Dashboard: management-console connectivity and sync, regional and compliance rollup freshness, backups, and dashboard core health. The dashboard runs no model, so this returns structured checks only.</M>
            <Card>
              <Input label="Describe the issue (optional)" value={troubleQuery} onChange={e=>setTroubleQuery(e.target.value)} placeholder="e.g., MC not syncing, reports not generating" disabled={troubleRunning}/>
              <Btn primary disabled={troubleRunning} onClick={async()=>{
                setTroubleRunning(true);setTroubleResult(null);
                const r=await api.post("/api/troubleshoot",{query:troubleQuery});
                setTroubleRunning(false);
                if(r&&!r.error&&Array.isArray(r.findings)){setTroubleResult(r);}
                else{setTroubleResult(null);showGdToast("Troubleshoot failed: "+(r?.error||"unknown"));}
              }}>{troubleRunning?"Diagnosing...":"Run diagnostics"}</Btn>
            </Card>
            {troubleResult&&Array.isArray(troubleResult.findings)&&(<div>
              <Card style={{marginTop:16}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Findings</div>
                {troubleResult.findings.map((f,i)=>(
                  <div key={i} style={{padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                      <Badge color={f.status==="pass"?C.a:f.status==="fail"?C.d:C.w}>{f.status}</Badge>
                      <M style={{color:C.t,fontWeight:500}}>{f.label}</M>
                    </div>
                    <M style={{color:C.tm,display:"block",lineHeight:1.6}}>{f.detail}</M>
                    {f.fix&&<M style={{color:C.tm,display:"block",marginTop:4,lineHeight:1.6}}>Fix: {f.fix}</M>}
                  </div>
                ))}
              </Card>
              {troubleResult.baseline&&troubleResult.baseline.length>0&&<Card style={{marginTop:16}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Dashboard baseline</div>
                {troubleResult.baseline.map((f,i)=>(
                  <div key={i} style={{padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                      <Badge color={f.status==="pass"?C.a:f.status==="fail"?C.d:C.w}>{f.status}</Badge>
                      <M style={{color:C.t,fontWeight:500}}>{f.label}</M>
                    </div>
                    <M style={{color:C.tm,display:"block",lineHeight:1.6}}>{f.detail}</M>
                    {f.fix&&<M style={{color:C.tm,display:"block",marginTop:4,lineHeight:1.6}}>Fix: {f.fix}</M>}
                  </div>
                ))}
              </Card>}
            </div>)}
          </div>)}

          {/* ══════════ APP UPDATES ══════════ */}
          {tab==="app_updates"&&(<div>
            <L>App Updates</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>The Global Dashboard checks this project's GitHub Releases for a newer stable release and notifies you here. It never downloads or installs an update — download it from GitHub, test it, then apply it on your own change-management schedule.</M>
            {configLocked&&<Card style={{borderColor:C.d+"40",marginBottom:12,padding:10}}><M style={{color:C.d}}>LOCK Configurations locked. Unlock with MFA to make changes.</M></Card>}
            <Card style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <M style={{color:C.a,fontWeight:500}}>Current version: v{gdVersion||"…"}</M>
                <Btn small primary onClick={gdCheckUpdate} disabled={updCheck==="checking"}>{updCheck==="checking"?"Checking…":"Check now"}</Btn>
              </div>
              {updStatus&&updStatus.lastCheckedAt&&(
                <M style={{color:C.td,display:"block",marginBottom:8}}>Last checked: {new Date(String(updStatus.lastCheckedAt).replace(" ","T")+"Z").toLocaleString()} · {updStatus.lastResult==="available"?"update available":updStatus.lastResult==="source_unreachable"?"source unreachable":"up to date"}</M>
              )}
              {updCheck&&updCheck!=="checking"&&(
                updCheck.error?
                  <M style={{color:C.w,display:"block"}}>{updCheck.error}</M>:
                updCheck.result==="available"?
                  <M style={{color:C.i,display:"block"}}>Update available: {updCheck.latestVersion}{updCheck.releaseUrl&&<> · <a href={updCheck.releaseUrl} target="_blank" rel="noopener noreferrer" style={{color:C.i}}>release notes</a></>}</M>:
                updCheck.result==="source_unreachable"?
                  <M style={{color:C.w,display:"block"}}>Could not reach the update source (GitHub). Version status unchanged; try again later.</M>:
                  <M style={{color:C.a,display:"block"}}>Running the latest stable release.</M>
              )}
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Automatic Update Checks</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Opt-in. When enabled, the dashboard checks GitHub Releases on the schedule below (UTC) and shows a banner when a newer version exists. Off by default — leave it off for air-gapped deployments and check manually. This check is the only outbound call and sends no data.</M>
              <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",marginBottom:8}}><input type="checkbox" checked={updCfg.enabled} disabled={configLocked} onChange={e=>setUpdCfg(pr=>({...pr,enabled:e.target.checked}))}/><M style={{color:C.t}}>Enable automatic update checks</M></label>
              <Sel label="Frequency" value={updCfg.frequency} disabled={configLocked} onChange={e=>setUpdCfg(pr=>({...pr,frequency:e.target.value}))}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></Sel>
              {updCfg.frequency==="weekly"?
                <Sel label="Day of week" value={String(updCfg.dayOfWeek)} disabled={configLocked} onChange={e=>setUpdCfg(pr=>({...pr,dayOfWeek:Number(e.target.value)}))}><option value="0">Sunday</option><option value="1">Monday</option><option value="2">Tuesday</option><option value="3">Wednesday</option><option value="4">Thursday</option><option value="5">Friday</option><option value="6">Saturday</option></Sel>:
               updCfg.frequency==="monthly"?
                <Sel label="Day of month" value={String(updCfg.dayOfMonth)} disabled={configLocked} onChange={e=>setUpdCfg(pr=>({...pr,dayOfMonth:Number(e.target.value)}))}>{Array.from({length:28},(_,i)=>i+1).map(d=><option key={d} value={String(d)}>{d}</option>)}</Sel>:
                null}
              <Input label="Time (UTC)" type="time" value={updCfg.timeUtc} disabled={configLocked} onChange={e=>setUpdCfg(pr=>({...pr,timeUtc:e.target.value}))}/>
              <Btn primary disabled={configLocked||updSaving} onClick={gdSaveUpdCfg}>{updSaving?"Saving…":"Save schedule"}</Btn>
            </Card>
          </div>)}

        </div>
      </div>
      <div style={{padding:"14px 24px",borderTop:`1px solid ${C.b}`,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",display:"flex",justifyContent:"space-between"}}><span>GLOBAL DASHBOARD · READ-ONLY · v{gdVersion||"…"}</span><span>{regions.length} regions · {totalAnalysts} analysts</span></div>
    </div>
  );
}

// Canonical React 18 mount (PR H): explicit, single, defensive root.
// No reliance on a runtime transpiler's implicit auto-render.
const _rootEl = document.getElementById("root");
if (!_rootEl) {
  const _err = document.createElement("div");
  _err.textContent = "Fatal: #root element not found. FireAlive cannot start.";
  _err.style.cssText = "font-family:monospace;color:#EF4444;padding:24px;font-size:14px";
  document.body.appendChild(_err);
} else {
  createRoot(_rootEl).render(<GlobalDashboard />);
}

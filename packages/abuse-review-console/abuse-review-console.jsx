// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE ABUSE REVIEW CONSOLE — Independent reviewer desktop application
//
// The sole client for the abuse_reviewer role. Talks to the MAIN FireAlive server
// (like the Analyst Client), authenticates a reviewer, and REJECTS every other
// role at sign-in. Flagged abuse content is sealed to the org abuse-review public
// key; only this console (holding the private key, main-process only) can open it.
// Case list, case detail (client-side decrypt via abuse:open), resolution, and
// patterns land in later commits (F7+); this commit is the shell + login.
// ═══════════════════════════════════════════════════════════════════════════════
import { useState, useEffect } from "react";
// FIREALIVE — SOC Analyst Wellbeing Platform
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. Source: https://github.com/petermancina/firealive
// ═══════════════════════════════════════════════════════════════════════════════

// ── Design tokens (shared FireAlive palette, identical to the other apps) ─────
const C = {
  bg:"#080C14",s:"rgba(255,255,255,0.02)",sh:"rgba(255,255,255,0.04)",
  b:"rgba(255,255,255,0.06)",ba:"rgba(255,255,255,0.14)",
  t:"#C8D6E5",tm:"#3A5068",td:"#1E3040",
  a:"#6EE7B7",ad:"rgba(110,231,183,0.1)",
  w:"#FBBF24",wd:"rgba(251,191,36,0.1)",
  d:"#EF4444",dd:"rgba(239,68,68,0.1)",
  i:"#60A5FA",id:"rgba(96,165,250,0.1)",
  p:"#A78BFA",pd:"rgba(167,139,250,0.1)",
};
const MONO = "'IBM Plex Mono',monospace";
const SERIF = "'Fraunces',serif";

// Self-contained: NO external font @import (CDN fonts are blocked by this app's
// CSP, and the app vendors its libs locally). The brand font-families fall back
// to system serif/monospace until fonts are vendored suite-wide (PR H).
const CSS = `*{box-sizing:border-box;margin:0;padding:0;}button,select,input,textarea{font-family:inherit;}
body{background:${C.bg};}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:3px}`;

// ── API client (main FireAlive server) ────────────────────────────────────────
const API_BASE = window.FIREALIVE_SERVER || 'http://localhost:3000';
const api = {
  _token: null,
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  async post(path, data) { try { const r = await fetch(API_BASE + path, { method: 'POST', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
  async get(path) { try { const r = await fetch(API_BASE + path, { headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
  setToken(t) { this._token = t; },
};

// The only role permitted to sign in here. Mirrors the server-side REVIEWER_ROLE.
const REVIEWER_ROLE = "abuse_reviewer";

// ── Shared atoms ──────────────────────────────────────────────────────────────
function Field({ label, ...p }) {
  return (
    <label style={{display:"block",marginBottom:14}}>
      <span style={{display:"block",fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>{label}</span>
      <input {...p} style={{width:"100%",padding:"11px 13px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:14,fontFamily:MONO,outline:"none"}} />
    </label>
  );
}

// ── Login: credentials -> optional MFA -> reviewer-only role gate ─────────────
function Login({ onAuthed }) {
  const [stage, setStage] = useState("creds");          // creds | mfa
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaSessionToken, setMfaSessionToken] = useState(null);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [enrollData, setEnrollData] = useState(null);      // {secret_base32, otpauth_url, qr_png_data_url}
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [pendingAuth, setPendingAuth] = useState(null);    // enroll-confirm result, held until codes saved

  // The reviewer-only role gate. Returns false (and resets to creds) for any
  // non-reviewer; no token is ever kept for a rejected account.
  function gateOk(r) {
    if (!r || !r.user || !r.accessToken) { setBusy(false); setError("Unexpected server response."); return false; }
    if (r.user.role !== REVIEWER_ROLE) {
      api.setToken(null);
      setBusy(false);
      setStage("creds");
      setCode("");
      setError(`This console is for designated abuse reviewers only. The account "${r.user.name}" has the role "${r.user.role}", which cannot sign in here.`);
      return false;
    }
    return true;
  }
  function finalize(r) {
    if (!gateOk(r)) return;
    api.setToken(r.accessToken);
    onAuthed(r.user);
  }

  async function submitCreds() {
    if (!username.trim() || !password) { setError("Enter your username and password."); return; }
    setError(""); setBusy(true);
    const r = await api.post("/api/auth/login", { username: username.trim(), password });
    if (r && r.error) { setBusy(false); setError("Sign-in failed. Check your credentials."); return; }
    if (r && r.mfa_required && r.mfa_session_token) { setBusy(false); setMfaSessionToken(r.mfa_session_token); setStage("mfa"); setCode(""); return; }
    if (r && r.mfa_enrollment_required && r.mfa_session_token) { setMfaSessionToken(r.mfa_session_token); await startEnroll(r.mfa_session_token); return; }
    if (r && r.accessToken && r.user) { finalize(r); return; }
    setBusy(false); setError("Unexpected login response.");
  }

  async function submitMfa() {
    const c = code.trim();
    if (!useRecovery && c.length < 6) { setError("Enter your 6-digit code."); return; }
    if (useRecovery && !c) { setError("Enter a recovery code."); return; }
    setError(""); setBusy(true);
    const body = useRecovery
      ? { mfa_session_token: mfaSessionToken, recovery_code: c }
      : { mfa_session_token: mfaSessionToken, totp_code: c };
    const r = await api.post("/api/auth/login-mfa", body);
    if (r && r.error) { setBusy(false); setError("Verification failed. Try again."); return; }
    if (r && r.accessToken && r.user) { finalize(r); return; }
    setBusy(false); setError("Unexpected verification response.");
  }

  // ── MFA enrollment (a freshly designated reviewer's first sign-in) ──────────
  async function startEnroll(token) {
    setError(""); setBusy(true);
    const r = await api.post("/api/auth/login-enroll-start", { mfa_session_token: token || mfaSessionToken });
    setBusy(false);
    if (!r || r.error || !r.secret_base32) { setStage("creds"); setError("Could not start enrollment. Sign in again to retry."); return; }
    setEnrollData(r); setCode(""); setStage("enroll");
  }

  async function confirmEnroll() {
    const c = code.trim();
    if (c.length !== 6) { setError("Enter the 6-digit code from your authenticator app."); return; }
    setError(""); setBusy(true);
    const r = await api.post("/api/auth/login-enroll-confirm", { mfa_session_token: mfaSessionToken, totp_code: c });
    if (r && r.error) { setBusy(false); setError("Enrollment confirmation failed. Check the code and try again."); return; }
    if (!r || !Array.isArray(r.recovery_codes)) { setBusy(false); setError("Enrollment response was incomplete."); return; }
    if (!gateOk(r)) return;                       // reviewer-only gate, before codes are shown
    setRecoveryCodes(r.recovery_codes); setPendingAuth(r); setBusy(false); setStage("recovery");
  }

  function acknowledgeCodes() {
    if (!pendingAuth) return;                      // already role-gated in confirmEnroll
    api.setToken(pendingAuth.accessToken);
    onAuthed(pendingAuth.user);
  }

  const btn = { width:"100%",padding:12,background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:13,fontWeight:600,fontFamily:MONO };

  return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",background:C.bg,padding:24}}>
      <div style={{width:384,animation:"fadeIn .4s ease"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:24,fontWeight:600,color:C.t,fontFamily:SERIF}}>FireAlive</div>
          <div style={{fontSize:11,color:C.tm,fontFamily:MONO,marginTop:6,letterSpacing:2}}>ABUSE REVIEW CONSOLE</div>
          <div style={{fontSize:10,color:C.td,fontFamily:MONO,marginTop:10,lineHeight:1.5}}>Independent review authority. Reviewer accounts only.</div>
        </div>
        {stage === "creds" && (
          <div>
            <Field label="Username" value={username} onChange={e=>setUsername(e.target.value)} autoFocus onKeyDown={e=>{ if(e.key==="Enter") submitCreds(); }} />
            <Field label="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} onKeyDown={e=>{ if(e.key==="Enter") submitCreds(); }} />
            <button onClick={submitCreds} disabled={busy} style={{...btn,cursor:busy?"default":"pointer",opacity:busy?0.6:1}}>{busy?"Signing in…":"Sign in"}</button>
          </div>
        )}
        {stage === "mfa" && (
          <div>
            <div style={{fontSize:12,color:C.tm,fontFamily:MONO,marginBottom:14,lineHeight:1.6}}>{useRecovery?"Enter one of your recovery codes.":"Enter the 6-digit code from your authenticator app."}</div>
            <Field label={useRecovery?"Recovery code":"Authentication code"} value={code} onChange={e=>setCode(e.target.value)} autoFocus onKeyDown={e=>{ if(e.key==="Enter") submitMfa(); }} />
            <button onClick={submitMfa} disabled={busy} style={{...btn,cursor:busy?"default":"pointer",opacity:busy?0.6:1}}>{busy?"Verifying…":"Verify"}</button>
            <button onClick={()=>{ setUseRecovery(!useRecovery); setCode(""); setError(""); }} style={{width:"100%",marginTop:10,padding:8,background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO,textDecoration:"underline"}}>{useRecovery?"Use authenticator code instead":"Use a recovery code instead"}</button>
          </div>
        )}
        {stage === "enroll" && enrollData && (
          <div>
            <div style={{fontSize:12,color:C.tm,fontFamily:MONO,marginBottom:14,lineHeight:1.6}}>Scan this with your authenticator app, then enter the first 6-digit code to finish enrollment. You'll get one-time recovery codes next.</div>
            <div style={{textAlign:"center",marginBottom:14}}>
              {enrollData.qr_png_data_url
                ? <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:180,height:180,borderRadius:8,background:"#fff",padding:8}} />
                : <div style={{fontSize:11,color:C.tm,fontFamily:MONO}}>QR unavailable -- use the secret below.</div>}
            </div>
            <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:8,padding:12,marginBottom:14}}>
              <span style={{fontSize:9,letterSpacing:1,textTransform:"uppercase",color:C.tm,fontFamily:MONO}}>Secret</span>
              <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:MONO,userSelect:"all",marginTop:4}}>{enrollData.secret_base32}</code>
            </div>
            <Field label="Authentication code" value={code} onChange={e=>setCode(e.target.value)} autoFocus onKeyDown={e=>{ if(e.key==="Enter") confirmEnroll(); }} />
            <button onClick={confirmEnroll} disabled={busy} style={{...btn,cursor:busy?"default":"pointer",opacity:busy?0.6:1}}>{busy?"Confirming…":"Confirm enrollment"}</button>
          </div>
        )}
        {stage === "recovery" && recoveryCodes && (
          <div>
            <div style={{fontSize:12,color:C.w,fontFamily:MONO,marginBottom:12,lineHeight:1.6}}>Save these recovery codes somewhere safe. Each works once if you lose your authenticator. They won't be shown again.</div>
            <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:8,padding:14,marginBottom:14,fontFamily:MONO,fontSize:13,color:C.t,lineHeight:1.9,userSelect:"all"}}>
              {recoveryCodes.map((rc,i)=><div key={i}>{rc}</div>)}
            </div>
            <button onClick={acknowledgeCodes} style={{...btn,cursor:"pointer"}}>I've saved my recovery codes</button>
          </div>
        )}
        {error && <div style={{marginTop:16,padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12,fontFamily:MONO,lineHeight:1.5}}>{error}</div>}
      </div>
    </div>
  );
}

// ── Console shell (case list / detail / resolve / patterns land here in F7+) ──
function Shell({ user, onSignOut }) {
  return (
    <div style={{minHeight:"100vh",background:C.bg,color:C.t,fontFamily:MONO,animation:"fadeIn .4s ease"}}>
      <header style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"16px 24px",borderBottom:`1px solid ${C.b}`}}>
        <div>
          <span style={{fontSize:16,fontWeight:600,fontFamily:SERIF,color:C.t}}>FireAlive</span>
          <span style={{fontSize:11,color:C.tm,marginLeft:10,letterSpacing:1.5}}>ABUSE REVIEW CONSOLE</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <span style={{fontSize:11,color:C.tm}}>{user.name} · reviewer</span>
          <button onClick={onSignOut} style={{padding:"6px 12px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>Sign out</button>
        </div>
      </header>
      <main style={{padding:24,maxWidth:1100,margin:"0 auto"}}>
        <div style={{color:C.tm,fontSize:13,lineHeight:1.7}}>Signed in as an independent abuse reviewer. The case list and review tools load here.</div>
      </main>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);
  function signOut() { api.setToken(null); setUser(null); }
  return (
    <div>
      <style>{CSS}</style>
      {user ? <Shell user={user} onSignOut={signOut} /> : <Login onAuthed={setUser} />}
    </div>
  );
}

// Explicit React 18 mount. ReactDOM is provided globally by the vendored UMD
// build loaded in index.html.
ReactDOM.createRoot(document.getElementById("root")).render(<App />);

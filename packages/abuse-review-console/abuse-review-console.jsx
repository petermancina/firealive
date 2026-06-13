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
import { createRoot } from "react-dom/client";
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
const DET_OPTIONS = [["substantiated", "Substantiated"], ["not_substantiated", "Not substantiated"], ["inconclusive", "Inconclusive"]];
const DET_LABELS = { substantiated: "Substantiated", not_substantiated: "Not substantiated", inconclusive: "Inconclusive" };
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
function Login({ onAuthed, locked }) {
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
        {locked && <div style={{marginBottom:16,padding:10,background:C.wd,border:`1px solid ${C.w}40`,borderRadius:8,color:C.w,fontSize:11,textAlign:"center",fontFamily:MONO}}>Locked due to inactivity. Sign in to continue.</div>}
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

// ── Console shell + case list ─────────────────────────────────────────────────
function Badge({ children, color }) {
  return <span style={{fontSize:9,padding:"2px 8px",borderRadius:10,background:color+"22",color,fontFamily:MONO,fontWeight:600,letterSpacing:0.5}}>{children}</span>;
}

// A party as revealed by the server: leads/admins by real name, analysts only by
// pseudonym. `label` is the resolved display string either way.
function Party({ p }) {
  if (!p) return <span style={{color:C.tm}}>unknown</span>;
  const roleC = (p.role === "lead" || p.role === "admin") ? C.i : C.p;
  return (
    <span style={{display:"inline-flex",alignItems:"center",gap:5}}>
      <span style={{color:C.t}}>{p.label}</span>
      <Badge color={roleC}>{p.role || "—"}</Badge>
    </span>
  );
}

// Friendly labels for the three reviewable target types. Falls back to the raw
// value so an unrecognized type still renders something rather than blank.
const TYPE_LABELS = { lead_chat: "Lead chat", peer_session: "Peer chat", board_post: "Board post" };
function typeLabelFor(t) { return TYPE_LABELS[t] || t; }

function CaseRow({ c, onClick }) {
  const tierC = c.tier >= 3 ? C.d : c.tier === 2 ? C.w : C.i;
  const typeLabel = typeLabelFor(c.targetType);
  return (
    <div onClick={onClick} title="Open case" style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,padding:"14px 16px",marginBottom:10,animation:"fadeIn .3s ease",cursor:"pointer"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <Badge color={tierC}>TIER {c.tier}</Badge>
          <span style={{fontSize:12,color:C.t}}>{typeLabel}</span>
        </div>
        <Badge color={c.resolved ? C.tm : C.a}>{c.resolved ? "RESOLVED" : "OPEN"}</Badge>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.tm,flexWrap:"wrap"}}>
        <Party p={c.flagger} /><span style={{color:C.td}}>reported</span><Party p={c.accused} />
      </div>
      <div style={{fontSize:10,color:C.td,marginTop:8}}>{new Date(c.createdAt).toLocaleString()}{c.resolved && c.resolvedAt ? ` · resolved ${new Date(c.resolvedAt).toLocaleString()}` : ""}</div>
    </div>
  );
}

// ── Case detail: fetch metadata + opaque sealed envelopes, decrypt locally ────
// ============================================================================
// SECURITY INVARIANT (regression lock): decrypted abuse evidence is rendered as
// INERT PLAIN TEXT and must stay that way. The reporter note and the flagged
// content can contain attacker-influenced bytes. (The note is sanitized on the
// input side before sealing; the flagged content is authentic and unsanitized
// by design.) Both are shown only as React text children -- {text} in
// SealedPanel, {m.content} for context items, {c.resolutionNote} -- inside
// whiteSpace:"pre-wrap" containers, so React escapes them and no markup runs.
// DO NOT render any decrypted value via dangerouslySetInnerHTML, a markdown or
// HTML renderer, or by injecting it into a URL, script, or style sink: that
// would turn sealed evidence into a code-execution vector in this console. This
// is the render-side half of the flag-note hardening; the input-side half lives
// in packages/shared/note-sanitizer.js.
// ============================================================================
// The server hands back the note/content as opaque base64 it cannot read; this
// view opens them with the device's reviewer private key via the main process
// (abuse:open). Plaintext exists only transiently in this renderer, to display.
function SealedPanel({ label, state, text }) {
  return (
    <div style={{marginBottom:16}}>
      <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>{label}</div>
      <div style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,padding:14,fontSize:13,color:C.t,lineHeight:1.6,whiteSpace:"pre-wrap",wordBreak:"break-word",minHeight:44}}>
        {state === "loading" && <span style={{color:C.tm}}>Decrypting…</span>}
        {state === "empty" && <span style={{color:C.td}}>(none)</span>}
        {state === "ok" && text}
      </div>
    </div>
  );
}

function CaseDetail({ caseId, onBack, onResolved }) {
  const [data, setData] = useState(null);          // null = loading
  const [error, setError] = useState("");
  const [note, setNote] = useState({ state: "loading", text: "" });
  const [content, setContent] = useState({ state: "loading", text: "" });
  const [context, setContext] = useState({ state: "empty", items: null });  // board thread context (parsed JSON)
  const [decryptError, setDecryptError] = useState("");
  const [resolveNote, setResolveNote] = useState("");
  const [resolveDet, setResolveDet] = useState("");  // structured verdict: substantiated | not_substantiated | inconclusive
  const [resolving, setResolving] = useState(false);
  const [resolveError, setResolveError] = useState("");
  const [exportReq, setExportReq] = useState(null);   // current legal-hold export request for this case, or null
  const [exportReason, setExportReason] = useState("");
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState("");
  const [cisoPin, setCisoPin] = useState(null);        // {pinned, fingerprint, noDesktop?} | null until checked
  const [cisoPem, setCisoPem] = useState("");
  const [cisoFp, setCisoFp] = useState("");
  const [pinBusy, setPinBusy] = useState(false);
  const [pinError, setPinError] = useState("");
  const [produceBusy, setProduceBusy] = useState(false);
  const [produceError, setProduceError] = useState("");

  async function openOne(sealedB64, set) {
    if (!sealedB64) { set({ state: "empty", text: "" }); return; }
    try {
      const res = await window.firealive.invoke("abuse:open", sealedB64);
      set({ state: "ok", text: res && res.plaintext != null ? res.plaintext : "" });
    } catch (e) { set({ state: "empty", text: "" }); setDecryptError("Some content could not be decrypted with this device's reviewer key."); }
  }

  // Board cases may carry a sealed thread-context box: a JSON array of
  // { label, content, flagged }. Decrypt locally, then parse; on a parse failure
  // fall back to showing the raw decrypted text so evidence is never silently
  // dropped.
  async function openContext(sealedB64) {
    if (!sealedB64) { setContext({ state: "empty", items: null }); return; }
    try {
      const res = await window.firealive.invoke("abuse:open", sealedB64);
      const txt = res && res.plaintext != null ? res.plaintext : "";
      let items = null;
      try { const parsed = JSON.parse(txt); if (Array.isArray(parsed)) items = parsed; } catch (_) {}
      if (!items) items = [{ label: "", content: txt, flagged: false }];
      setContext({ state: "ok", items });
    } catch (e) { setContext({ state: "empty", items: null }); setDecryptError("Some content could not be decrypted with this device's reviewer key."); }
  }

  useEffect(() => {
    let alive = true;
    (async () => {
      setError(""); setData(null); setDecryptError("");
      setNote({ state: "loading", text: "" }); setContent({ state: "loading", text: "" }); setContext({ state: "empty", items: null });
      const r = await api.get(`/api/abuse-review/cases/${caseId}`);
      if (!alive) return;
      if (!r || r.error || !r.case) { setError("Could not load this case."); return; }
      setData(r.case);
      if (!window.firealive || !window.firealive.invoke) {
        setDecryptError("Run the desktop app to decrypt sealed content.");
        setNote({ state: "empty", text: "" }); setContent({ state: "empty", text: "" }); setContext({ state: "empty", items: null });
        return;
      }
      openOne(r.case.sealedContent, setContent);
      openOne(r.case.sealedNote, setNote);
      openContext(r.case.sealedContext);
    })();
    return () => { alive = false; };
  }, [caseId]);

  // Load any existing legal-hold export request for this case so its status shows.
  useEffect(() => {
    let alive = true;
    (async () => {
      const r = await api.get('/api/abuse-vault-export/requests');
      if (!alive || !r || r.error || !Array.isArray(r.requests)) return;
      const mine = r.requests.filter(x => x.flagId === caseId);
      setExportReq(mine.length ? mine[0] : null);
    })();
    return () => { alive = false; };
  }, [caseId]);

  // While a request is pending, poll for the CISO's decision (pulled from the GD).
  useEffect(() => {
    if (!exportReq || exportReq.status !== 'pending') return undefined;
    const t = setInterval(async () => {
      const r = await api.get('/api/abuse-vault-export/requests/' + exportReq.id);
      if (r && !r.error && r.id) setExportReq(r);
    }, 20000);
    return () => clearInterval(t);
  }, [exportReq && exportReq.id, exportReq && exportReq.status]);

  // When an approved export is in hand, check whether this device has the CISO
  // approval key pinned -- required to verify the token before producing.
  useEffect(() => {
    if (!exportReq || exportReq.status !== 'approved') return;
    if (!window.firealive || !window.firealive.invoke) { setCisoPin({ pinned: false, noDesktop: true }); return; }
    window.firealive.invoke('abuse:cisoKeyStatus').then(st => setCisoPin(st || { pinned: false })).catch(() => setCisoPin({ pinned: false }));
  }, [exportReq && exportReq.id, exportReq && exportReq.status]);

  async function resolve() {
    setResolveError(""); setResolving(true);
    const r = await api.post(`/api/abuse-review/cases/${caseId}/resolve`, { note: resolveNote, determination: resolveDet });
    setResolving(false);
    if (!r || r.error) { setResolveError(r && r.error === "case already resolved" ? "This case was already resolved." : "Could not resolve the case."); return; }
    setData(d => ({ ...d, resolved: true, resolvedAt: new Date().toISOString(), resolutionNote: resolveNote, determination: resolveDet }));
    if (onResolved) onResolved();
  }

  async function requestExport() {
    setExportError(""); setExportBusy(true);
    const r = await api.post('/api/abuse-vault-export/' + caseId + '/request', { reason: exportReason });
    setExportBusy(false);
    if (!r || r.error) { setExportError(r && r.error ? r.error : "Could not create the request."); return; }
    setExportReq(r); setExportReason("");
  }
  async function refreshExport() {
    if (!exportReq) return;
    const r = await api.get('/api/abuse-vault-export/requests/' + exportReq.id);
    if (r && !r.error && r.id) setExportReq(r);
  }

  async function pinCisoKey() {
    setPinError(""); setPinBusy(true);
    try {
      const r = await window.firealive.invoke('abuse:pinCisoKey', { publicKeyPem: cisoPem, expectedFingerprint: cisoFp });
      setCisoPin({ pinned: true, fingerprint: r.fingerprint }); setCisoPem(""); setCisoFp("");
    } catch (e) { setPinError((e && e.message) ? e.message : "Could not pin the key."); }
    setPinBusy(false);
  }

  async function produceExport() {
    setProduceError(""); setProduceBusy(true);
    try {
      const ap = exportReq.approval;
      if (!ap || !ap.signature) { setProduceError("No signed approval is present yet."); setProduceBusy(false); return; }
      // Authoritative gate: verify the CISO token against THIS device's pinned key.
      const v = await window.firealive.invoke('abuse:verifyExportToken', {
        payloadCanonical: ap.payloadCanonical, signature: ap.signature, keyFingerprint: ap.keyFingerprint,
        expectRequestId: exportReq.id, expectFlagId: caseId, expectDecision: 'approved',
      });
      if (!v || !v.ok) { setProduceError("Approval did not verify: " + ((v && v.reason) || "unknown") + ". Export refused."); setProduceBusy(false); return; }
      const cf = data || {};
      const caseFile = {
        document: "FireAlive Legal-Hold Case File",
        classification: "RESTRICTED \u2014 Legal/HR",
        generatedAt: new Date().toISOString(),
        caseId: caseId,
        targetType: cf.targetType || null,
        determination: cf.determination || null,
        resolutionNote: cf.resolutionNote || null,
        evidence: {
          content: content.state === "ok" ? content.text : null,
          reporterNote: note.state === "ok" ? note.text : null,
          context: context.state === "ok" ? context.items : null,
        },
        cisoApproval: {
          payloadCanonical: ap.payloadCanonical, signature: ap.signature, keyFingerprint: ap.keyFingerprint,
          verifiedAgainstPinnedKey: true, decidedAt: v.decidedAt || null, nonce: v.nonce || null,
        },
        chainReference: { requestId: exportReq.id, flagId: caseId },
        notice: "Two-person controlled export (reviewer + CISO). Verify cisoApproval.signature against the CISO public key. Software cannot control downstream distribution; this file is for legal/HR use only.",
      };
      const blob = new Blob([JSON.stringify(caseFile, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "legal-hold-case-" + caseId + ".json";
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      const rec = await api.post('/api/abuse-vault-export/requests/' + exportReq.id + '/produced', {});
      if (rec && !rec.error && rec.id) { setExportReq(rec); }
      else { setProduceError("File produced, but recording it failed: " + ((rec && rec.error) || "unknown") + "."); }
    } catch (e) { setProduceError((e && e.message) ? e.message : "Production failed."); }
    setProduceBusy(false);
  }

  const back = <button onClick={onBack} style={{padding:"6px 12px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>← Back to cases</button>;

  if (error) return <div>{back}<div style={{marginTop:16,padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12}}>{error}</div></div>;
  if (!data) return <div>{back}<div style={{marginTop:24,color:C.tm,fontSize:12}}>Loading case…</div></div>;

  const c = data;
  const tierC = c.tier >= 3 ? C.d : c.tier === 2 ? C.w : C.i;
  const typeLabel = typeLabelFor(c.targetType);
  return (
    <div style={{animation:"fadeIn .3s ease"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
        {back}
        <Badge color={c.resolved ? C.tm : C.a}>{c.resolved ? "RESOLVED" : "OPEN"}</Badge>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
        <Badge color={tierC}>TIER {c.tier}</Badge>
        <span style={{fontSize:13,color:C.t,fontFamily:SERIF,fontWeight:600}}>{typeLabel}</span>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.tm,flexWrap:"wrap",marginBottom:6}}>
        <Party p={c.flagger} /><span style={{color:C.td}}>reported</span><Party p={c.accused} />
      </div>
      <div style={{fontSize:10,color:C.td,marginBottom:18}}>{new Date(c.createdAt).toLocaleString()}{c.sealedAt ? ` · sealed ${new Date(c.sealedAt).toLocaleString()}` : ""}</div>
      {decryptError && <div style={{marginBottom:14,padding:10,background:C.wd,border:`1px solid ${C.w}40`,borderRadius:8,color:C.w,fontSize:11,lineHeight:1.5}}>{decryptError}</div>}
      <SealedPanel label="Reported content" state={content.state} text={content.text} />
      {context.state !== "empty" && (
        <div style={{marginBottom:16}}>
          <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Thread context</div>
          <div style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,padding:14,minHeight:44}}>
            {context.state === "loading" && <span style={{color:C.tm,fontSize:13}}>Decrypting…</span>}
            {context.state === "ok" && (!context.items || context.items.length === 0) && <span style={{color:C.td,fontSize:13}}>(none)</span>}
            {context.state === "ok" && context.items && context.items.map((m, i) => (
              <div key={i} style={{marginBottom:10,paddingLeft:10,borderLeft:`2px solid ${m.flagged ? C.d : C.b}`}}>
                <div style={{fontSize:11,color:m.flagged ? C.d : C.tm,fontWeight:m.flagged ? 600 : 400,marginBottom:2,fontFamily:MONO}}>{m.label || "\u2014"}{m.flagged ? " \u00b7 reported" : ""}</div>
                <div style={{fontSize:13,color:C.t,lineHeight:1.6,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{m.content}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      <SealedPanel label="Reporter's note" state={note.state} text={note.text} />
      {c.resolved && c.determination && (
        <div style={{marginTop:6}}>
          <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Determination</div>
          <div style={{fontSize:13,color:C.t,fontFamily:MONO}}>{DET_LABELS[c.determination] || c.determination}</div>
        </div>
      )}
      {c.resolved && c.resolutionNote && (
        <div style={{marginTop:6}}>
          <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Resolution note</div>
          <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:8,padding:14,fontSize:13,color:C.t,lineHeight:1.6,whiteSpace:"pre-wrap"}}>{c.resolutionNote}</div>
        </div>
      )}
      {!c.resolved && (
        <div style={{marginTop:8,borderTop:`1px solid ${C.b}`,paddingTop:16}}>
          <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Resolve this case</div>
          <div style={{fontSize:11,color:C.tm,marginBottom:6,fontFamily:MONO}}>Determination (required)</div>
          <div style={{display:"flex",gap:8,marginBottom:10,flexWrap:"wrap"}}>
            {DET_OPTIONS.map(([val,label]) => (
              <button key={val} onClick={()=>setResolveDet(val)} style={{padding:"8px 14px",background:resolveDet===val?C.ad:C.s,border:`1px solid ${resolveDet===val?C.a+"80":C.b}`,borderRadius:8,color:resolveDet===val?C.a:C.t,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:MONO}}>{label}</button>
            ))}
          </div>
          <textarea value={resolveNote} onChange={e=>setResolveNote(e.target.value)} placeholder="Rationale (required)" rows={3} style={{width:"100%",padding:"11px 13px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:13,fontFamily:MONO,outline:"none",resize:"vertical",marginBottom:10}} />
          {resolveError && <div style={{marginBottom:10,padding:10,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,lineHeight:1.5}}>{resolveError}</div>}
          <button onClick={resolve} disabled={resolving || !resolveDet || !resolveNote.trim()} style={{padding:"10px 18px",background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:(resolving||!resolveDet||!resolveNote.trim())?"default":"pointer",fontFamily:MONO,opacity:(resolving||!resolveDet||!resolveNote.trim())?0.6:1}}>{resolving?"Resolving…":"Resolve case"}</button>
        </div>
      )}
      <div style={{marginTop:8,borderTop:`1px solid ${C.b}`,paddingTop:16}}>
        <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Legal-hold export</div>
        {!exportReq && (
          <div>
            <div style={{fontSize:12,color:C.tm,lineHeight:1.6,marginBottom:10}}>A legal-hold export requires a CISO to approve it in the Global Dashboard before the case file can be produced. State the legal basis below.</div>
            <textarea value={exportReason} onChange={e=>setExportReason(e.target.value)} placeholder="Legal basis / rationale (required, min 20 chars)" rows={3} style={{width:"100%",padding:"11px 13px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:13,fontFamily:MONO,outline:"none",resize:"vertical",marginBottom:10}} />
            {exportError && <div style={{marginBottom:10,padding:10,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,lineHeight:1.5}}>{exportError}</div>}
            <button onClick={requestExport} disabled={exportBusy || exportReason.trim().length < 20} style={{padding:"10px 18px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,fontWeight:600,cursor:(exportBusy||exportReason.trim().length<20)?"default":"pointer",fontFamily:MONO,opacity:(exportBusy||exportReason.trim().length<20)?0.6:1}}>{exportBusy?"Requesting\u2026":"Request legal-hold export"}</button>
          </div>
        )}
        {exportReq && (
          <div>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
              <Badge color={exportReq.status==="approved"?C.a:exportReq.status==="denied"?C.d:C.t}>{exportReq.status.toUpperCase()}</Badge>
              {exportReq.status==="pending" && <span style={{fontSize:11,color:C.tm,fontFamily:MONO}}>awaiting CISO approval in the Global Dashboard</span>}
            </div>
            {exportReq.reason && <div style={{fontSize:12,color:C.tm,lineHeight:1.6,marginBottom:6,whiteSpace:"pre-wrap"}}>Basis: {exportReq.reason}</div>}
            {exportReq.status==="denied" && exportReq.denialReason && <div style={{fontSize:12,color:C.d,lineHeight:1.6,marginBottom:6}}>Denied: {exportReq.denialReason}</div>}
            {exportReq.status==="approved" && (
              <div>
                <div style={{fontSize:12,color:C.a,lineHeight:1.6,marginBottom:8}}>Approved by the CISO. Producing assembles the case file on this device after verifying the signed approval; the vault is never modified.</div>
                {cisoPin && cisoPin.noDesktop && <div style={{fontSize:11,color:C.d,marginBottom:8}}>Run the desktop app to verify the approval and produce the file.</div>}
                {cisoPin && !cisoPin.pinned && !cisoPin.noDesktop && (
                  <div style={{marginBottom:10,padding:10,background:C.s,border:`1px solid ${C.b}`,borderRadius:8}}>
                    <div style={{fontSize:11,color:C.tm,marginBottom:6,fontFamily:MONO}}>Pin the CISO approval key (one-time; verify the fingerprint out of band)</div>
                    <textarea value={cisoPem} onChange={e=>setCisoPem(e.target.value)} placeholder="CISO approval public key (PEM)" rows={3} style={{width:"100%",padding:"9px 11px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,fontFamily:MONO,outline:"none",resize:"vertical",marginBottom:6}} />
                    <input value={cisoFp} onChange={e=>setCisoFp(e.target.value)} placeholder="Expected fingerprint (sha256 hex)" style={{width:"100%",padding:"9px 11px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,fontFamily:MONO,outline:"none",marginBottom:6}} />
                    {pinError && <div style={{fontSize:11,color:C.d,marginBottom:6}}>{pinError}</div>}
                    <button onClick={pinCisoKey} disabled={pinBusy || !cisoPem.trim() || !cisoFp.trim()} style={{padding:"8px 14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,cursor:(pinBusy||!cisoPem.trim()||!cisoFp.trim())?"default":"pointer",fontFamily:MONO,opacity:(pinBusy||!cisoPem.trim()||!cisoFp.trim())?0.6:1}}>{pinBusy?"Pinning\u2026":"Pin CISO key"}</button>
                  </div>
                )}
                {cisoPin && cisoPin.pinned && (
                  <div>
                    <div style={{fontSize:10,color:C.tm,marginBottom:8,fontFamily:MONO}}>CISO key pinned: {cisoPin.fingerprint ? cisoPin.fingerprint.slice(0,16)+"\u2026" : ""}</div>
                    <button onClick={produceExport} disabled={produceBusy} style={{padding:"10px 18px",background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:produceBusy?"default":"pointer",fontFamily:MONO,opacity:produceBusy?0.6:1}}>{produceBusy?"Producing\u2026":"Produce case file"}</button>
                  </div>
                )}
                {produceError && <div style={{marginTop:8,padding:10,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,lineHeight:1.5}}>{produceError}</div>}
              </div>
            )}
            {exportReq.status==="consumed" && <div style={{fontSize:12,color:C.tm,lineHeight:1.6,marginBottom:6}}>Case file produced and recorded. The vault record is unchanged and retained.</div>}
            {exportReq.status==="pending" && <button onClick={refreshExport} style={{padding:"8px 14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,cursor:"pointer",fontFamily:MONO}}>Refresh status</button>}
          </div>
        )}
      </div>
    </div>
  );
}

function Tab({ label, active, onClick }) {
  return <button onClick={onClick} style={{padding:"8px 14px",background:"transparent",border:"none",borderBottom:`2px solid ${active?C.a:"transparent"}`,color:active?C.t:C.tm,fontSize:12,fontWeight:active?600:400,cursor:"pointer",fontFamily:MONO}}>{label}</button>;
}

// A behavioral signal from the detector, scoped to cases this reviewer can open.
// flagCount/maxTier reflect ACCESSIBLE cases only -- the server never leaks the
// totals of cases outside this reviewer's scope.
function PatternCard({ p, onOpenCase }) {
  const sev = (p.severity || "").toString();
  const sevC = sev === "high" ? C.d : sev === "medium" ? C.w : C.i;
  const typeLabel = ({ repeat_offender:"Repeat offender", escalation:"Escalation", retaliation:"Retaliation" })[p.patternType] || p.patternType;
  const ids = Array.isArray(p.accessibleFlagIds) ? p.accessibleFlagIds : [];
  return (
    <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,padding:"14px 16px",marginBottom:10,animation:"fadeIn .3s ease"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <Badge color={sevC}>{sev ? sev.toUpperCase() : "SIGNAL"}</Badge>
          <span style={{fontSize:12,color:C.t}}>{typeLabel}</span>
        </div>
        <Badge color={p.acknowledged ? C.tm : C.a}>{p.acknowledged ? "ACKNOWLEDGED" : "NEW"}</Badge>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.tm,flexWrap:"wrap",marginBottom:6}}>
        <Party p={p.subject} />{p.counterpart && <span style={{color:C.td}}>vs</span>}{p.counterpart && <Party p={p.counterpart} />}
      </div>
      <div style={{fontSize:11,color:C.tm,marginBottom:6}}>{p.flagCount} accessible case{p.flagCount === 1 ? "" : "s"} · max tier {p.maxTier || "—"}</div>
      <div style={{fontSize:10,color:C.td,marginBottom:ids.length ? 10 : 0}}>{p.windowStart ? new Date(p.windowStart).toLocaleDateString() : ""}{p.windowEnd ? ` – ${new Date(p.windowEnd).toLocaleDateString()}` : ""}</div>
      {ids.length > 0 && (
        <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
          {ids.map(fid => <button key={fid} onClick={()=>onOpenCase(fid)} style={{padding:"4px 10px",background:C.ad,border:`1px solid ${C.a}40`,borderRadius:8,color:C.a,fontSize:10,cursor:"pointer",fontFamily:MONO}}>Open {String(fid).slice(0,8)}…</button>)}
        </div>
      )}
    </div>
  );
}

// ── First-run key bootstrap (multi-reviewer zero-access) ──────────────────────
// Each reviewer generates their OWN keypair on their OWN device, behind a
// passphrase known only to them. The private key is passphrase-wrapped and then
// sealed with safeStorage in the main process; only this device, with this
// passphrase, can open flags addressed to this reviewer. Adding a reviewer means
// adding another public key to the active recipient set on the server -- it
// does NOT share or copy this key. There is no organisation-wide private key
// to leak.
function KeyBootstrap({ onUnlocked }) {
  const [pass1, setPass1] = useState("");
  const [pass2, setPass2] = useState("");
  const [created, setCreated] = useState(null);  // {algo, publicKeyB64, fingerprint} after generate
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const MIN = 12;

  async function generate() {
    setError("");
    if (pass1.length < MIN) { setError(`Choose a passphrase of at least ${MIN} characters.`); return; }
    if (pass1 !== pass2) { setError("Passphrases do not match."); return; }
    setBusy(true);
    try {
      const r = await window.firealive.invoke("abuse:generateKey", pass1);
      if (!r || !r.publicKeyB64) { setBusy(false); setError("Key generation did not return a public key."); return; }
      // Unlock the new key right away so the reviewer can use the console without re-entering the passphrase.
      await window.firealive.invoke("abuse:unlock", pass1);
      setBusy(false);
      setCreated(r);
    } catch (e) {
      setBusy(false);
      setError("Could not generate the reviewer key on this device. OS secure storage may be unavailable, or a key already exists.");
    }
  }

  if (created) {
    return (
      <div style={{maxWidth:620,animation:"fadeIn .3s ease"}}>
        <div style={{fontSize:15,fontWeight:600,color:C.t,fontFamily:SERIF,marginBottom:8}}>Reviewer key created</div>
        <div style={{fontSize:12,color:C.tm,lineHeight:1.7,marginBottom:14}}>The private key is passphrase-wrapped and sealed on this device; it never leaves. Give the public key and fingerprint below to an administrator -- they add YOUR key to the active recipient set, alongside any other reviewers. Flags are sealed to every active key at once, so any one reviewer opens them with their own private key.</div>
        <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Fingerprint</div>
        <code style={{display:"block",background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,padding:"10px 14px",fontSize:12,color:C.t,fontFamily:MONO,userSelect:"all",marginBottom:14}}>{created.fingerprint}</code>
        <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Public key · {created.algo}</div>
        <code style={{display:"block",background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,padding:14,fontSize:12,color:C.t,wordBreak:"break-all",fontFamily:MONO,userSelect:"all",lineHeight:1.6,marginBottom:16}}>{created.publicKeyB64}</code>
        <button onClick={()=>onUnlocked(created.fingerprint)} style={{padding:"10px 18px",background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:MONO}}>Continue to console</button>
      </div>
    );
  }
  return (
    <div style={{maxWidth:620,animation:"fadeIn .3s ease"}}>
      <div style={{fontSize:15,fontWeight:600,color:C.t,fontFamily:SERIF,marginBottom:8}}>Set up your reviewer key</div>
      <div style={{fontSize:12,color:C.tm,lineHeight:1.7,marginBottom:14}}>This device has no reviewer key yet. Each reviewer generates their own keypair behind a passphrase known only to them; the private key never leaves this device. An administrator then registers your public key, adding it to the active recipient set so reports seal to your key alongside any other reviewers'.</div>
      <div style={{fontSize:12,color:C.tm,lineHeight:1.7,marginBottom:14,padding:11,background:C.id,border:`1px solid ${C.i}30`,borderRadius:8}}>Your passphrase is the second factor protecting your private key at rest. Choose at least {MIN} characters; length matters more than mixed cases or symbols. There is no recovery -- forget it and the key on this device is unrecoverable, but you can be re-issued by generating a fresh key.</div>
      <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Passphrase</div>
      <input type="password" value={pass1} onChange={e=>setPass1(e.target.value)} autoComplete="new-password" style={{width:"100%",padding:"10px 14px",background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:13,fontFamily:MONO,marginBottom:12,boxSizing:"border-box"}} />
      <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Confirm passphrase</div>
      <input type="password" value={pass2} onChange={e=>setPass2(e.target.value)} autoComplete="new-password" style={{width:"100%",padding:"10px 14px",background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:13,fontFamily:MONO,marginBottom:14,boxSizing:"border-box"}} />
      {error && <div style={{marginBottom:14,padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12,lineHeight:1.5}}>{error}</div>}
      <button onClick={generate} disabled={busy} style={{padding:"10px 18px",background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:busy?"default":"pointer",fontFamily:MONO,opacity:busy?0.6:1}}>{busy?"Generating…":"Generate my reviewer key"}</button>
    </div>
  );
}

// ── Per-session unlock ────────────────────────────────────────────────────────
// The reviewer's private key is held in main-process memory only while the
// session is unlocked. The renderer never sees the key -- only the unlock
// confirmation and the resulting fingerprint, used to show which reviewer
// identity is active. Locking clears the key from memory; reopening flags
// then requires another unlock.
function Unlock({ onUnlocked }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    if (!pass) { setError("Enter your passphrase."); return; }
    setBusy(true);
    try {
      const r = await window.firealive.invoke("abuse:unlock", pass);
      setBusy(false);
      if (!r || !r.unlocked) { setError("Unlock failed."); return; }
      onUnlocked(r.fingerprint);
    } catch (e) {
      setBusy(false);
      setError("Incorrect passphrase, or the reviewer key on this device could not be read.");
    }
  }

  return (
    <div style={{maxWidth:520,animation:"fadeIn .3s ease"}}>
      <div style={{fontSize:15,fontWeight:600,color:C.t,fontFamily:SERIF,marginBottom:8}}>Unlock the reviewer key</div>
      <div style={{fontSize:12,color:C.tm,lineHeight:1.7,marginBottom:14}}>Enter your passphrase to hold the private key in memory for this session. Reports remain sealed until the key is unlocked, and locking again clears it.</div>
      <div style={{fontSize:10,letterSpacing:1,textTransform:"uppercase",color:C.tm,marginBottom:6,fontFamily:MONO}}>Passphrase</div>
      <input type="password" value={pass} onChange={e=>setPass(e.target.value)} onKeyDown={e=>{ if(e.key==="Enter") submit(); }} autoComplete="current-password" autoFocus style={{width:"100%",padding:"10px 14px",background:C.bg,border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:13,fontFamily:MONO,marginBottom:14,boxSizing:"border-box"}} />
      {error && <div style={{marginBottom:14,padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12,lineHeight:1.5}}>{error}</div>}
      <button onClick={submit} disabled={busy} style={{padding:"10px 18px",background:C.ad,border:`1px solid ${C.a}50`,borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:busy?"default":"pointer",fontFamily:MONO,opacity:busy?0.6:1}}>{busy?"Unlocking…":"Unlock"}</button>
    </div>
  );
}

function Shell({ user, onSignOut }) {
  const [cases, setCases] = useState(null);   // null = loading
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [tab, setTab] = useState("cases");
  const [patterns, setPatterns] = useState(null);
  const [patternsError, setPatternsError] = useState("");
  const [hasKey, setHasKey] = useState(null);   // null=checking, true=on device, false=needs setup
  const [unlockedFp, setUnlockedFp] = useState(null); // fingerprint of the unlocked key, null = locked

  function handleUnlocked(fp) { setHasKey(true); setUnlockedFp(fp); }
  async function lock() {
    try { await window.firealive.invoke("abuse:lock"); } catch (e) {}
    setUnlockedFp(null);
  }

  async function loadPatterns() {
    setPatternsError(""); setPatterns(null);
    const r = await api.get("/api/abuse-review/patterns");
    if (r && r.error) { setPatternsError("Could not load patterns."); setPatterns([]); return; }
    setPatterns(Array.isArray(r && r.patterns) ? r.patterns : []);
  }

  async function checkKey() {
    if (!window.firealive || !window.firealive.invoke) { setHasKey(true); setUnlockedFp("-"); return; }  // non-desktop: don't block (decrypt is guarded)
    try { const r = await window.firealive.invoke("abuse:hasKey"); setHasKey(!!r); }
    catch (e) { setHasKey(true); setUnlockedFp("-"); }
  }

  async function load() {
    setError(""); setCases(null);
    const r = await api.get("/api/abuse-review/cases");
    if (r && r.error) { setError("Could not load cases. Check your connection to the server."); setCases([]); return; }
    setCases(Array.isArray(r && r.cases) ? r.cases : []);
  }
  useEffect(() => { load(); checkKey(); }, []);

  const openCount = Array.isArray(cases) ? cases.filter(c => !c.resolved).length : 0;

  return (
    <div style={{minHeight:"100vh",background:C.bg,color:C.t,fontFamily:MONO,animation:"fadeIn .4s ease"}}>
      <header style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"16px 24px",borderBottom:`1px solid ${C.b}`}}>
        <div>
          <span style={{fontSize:16,fontWeight:600,fontFamily:SERIF,color:C.t}}>FireAlive</span>
          <span style={{fontSize:11,color:C.tm,marginLeft:10,letterSpacing:1.5}}>ABUSE REVIEW CONSOLE</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <span style={{fontSize:11,color:C.tm}}>{user.name} · reviewer</span>
          {unlockedFp && <span style={{fontSize:10,color:C.tm,fontFamily:MONO,letterSpacing:0.5}} title="Unlocked reviewer fingerprint">· {unlockedFp}</span>}
          {unlockedFp && unlockedFp !== "-" && <button onClick={lock} title="Clear the reviewer key from memory" style={{padding:"6px 12px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>Lock</button>}
          <button onClick={onSignOut} style={{padding:"6px 12px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>Sign out</button>
        </div>
      </header>
      <main style={{padding:24,maxWidth:900,margin:"0 auto"}}>
        <div style={{background:C.id,border:`1px solid ${C.i}30`,borderRadius:8,padding:"10px 14px",marginBottom:18,fontSize:11,color:C.tm,lineHeight:1.6}}>
          <span style={{color:C.i,fontWeight:600}}>Independent review authority.</span> This console is the sole place abuse reports are reviewed. Team leads and admins never review abuse; analysts appear only as pseudonyms; and reported content is decrypted only on this device with the reviewer key, never by the server.
        </div>
        {hasKey === null && <div style={{color:C.tm,fontSize:12,padding:"24px 0"}}>Checking reviewer key…</div>}
        {hasKey === false && <KeyBootstrap onUnlocked={handleUnlocked} />}
        {hasKey === true && !unlockedFp && <Unlock onUnlocked={handleUnlocked} />}
        {hasKey === true && unlockedFp && (selectedId ? (
          <CaseDetail caseId={selectedId} onBack={()=>setSelectedId(null)} onResolved={load} />
        ) : (
          <div>
            <div style={{display:"flex",gap:8,marginBottom:18,borderBottom:`1px solid ${C.b}`}}>
              <Tab label="Cases" active={tab === "cases"} onClick={()=>setTab("cases")} />
              <Tab label="Patterns" active={tab === "patterns"} onClick={()=>{ setTab("patterns"); if (patterns === null) loadPatterns(); }} />
            </div>
            {tab === "cases" && (
              <div>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
                  <div>
                    <div style={{fontSize:15,fontWeight:600,color:C.t,fontFamily:SERIF}}>Cases</div>
                    <div style={{fontSize:11,color:C.tm,marginTop:2}}>{Array.isArray(cases) ? `${cases.length} total · ${openCount} open` : "Loading…"}</div>
                  </div>
                  <button onClick={load} style={{padding:"6px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>Refresh</button>
                </div>
                {cases === null && <div style={{color:C.tm,fontSize:12,padding:"24px 0"}}>Loading cases…</div>}
                {error && <div style={{padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12,lineHeight:1.5}}>{error}</div>}
                {Array.isArray(cases) && cases.length === 0 && !error && (
                  <div style={{textAlign:"center",padding:"48px 0",color:C.tm,fontSize:13,lineHeight:1.7}}>No cases to review.<div style={{fontSize:11,color:C.td,marginTop:6}}>Flagged abuse assigned to you will appear here.</div></div>
                )}
                {Array.isArray(cases) && cases.map(c => <CaseRow key={c.id} c={c} onClick={()=>setSelectedId(c.id)} />)}
              </div>
            )}
            {tab === "patterns" && (
              <div>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
                  <div>
                    <div style={{fontSize:15,fontWeight:600,color:C.t,fontFamily:SERIF}}>Patterns</div>
                    <div style={{fontSize:11,color:C.tm,marginTop:2}}>{Array.isArray(patterns) ? `${patterns.length} signal${patterns.length === 1 ? "" : "s"}` : "Loading…"}</div>
                  </div>
                  <button onClick={loadPatterns} style={{padding:"6px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer",fontFamily:MONO}}>Refresh</button>
                </div>
                {patterns === null && <div style={{color:C.tm,fontSize:12,padding:"24px 0"}}>Loading patterns…</div>}
                {patternsError && <div style={{padding:11,background:C.dd,border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:12,lineHeight:1.5}}>{patternsError}</div>}
                {Array.isArray(patterns) && patterns.length === 0 && !patternsError && (
                  <div style={{textAlign:"center",padding:"48px 0",color:C.tm,fontSize:13,lineHeight:1.7}}>No behavioral patterns.<div style={{fontSize:11,color:C.td,marginTop:6}}>Repeat-offender, escalation, and retaliation signals across your cases appear here.</div></div>
                )}
                {Array.isArray(patterns) && patterns.map(p => <PatternCard key={p.id} p={p} onOpenCase={(fid)=>{ setTab("cases"); setSelectedId(fid); }} />)}
              </div>
            )}
          </div>
        ))}
      </main>
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
  const choose = async (mode) => {
    setErr(""); setBusy(true);
    try {
      const bridge = (typeof window !== "undefined") ? window.firealive : null;
      if (!bridge || typeof bridge.invoke !== "function") { onComplete(); return; }
      const r = await bridge.invoke("deployment:setLocalMode", { mode: mode });
      if (r && r.error) { setErr(r.error); setBusy(false); return; }
      onComplete();
    } catch (e) {
      setErr(e && e.message ? e.message : "could not save selection");
      setBusy(false);
    }
  };
  const card = (mode, title, desc) => (
    <button key={mode} onClick={()=>choose(mode)} disabled={busy} style={{textAlign:"left",padding:"18px 20px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10,color:C.t,cursor:busy?"default":"pointer",opacity:busy?0.6:1,display:"flex",flexDirection:"column",gap:6,maxWidth:420}}>
      <span style={{fontSize:13,fontWeight:600,color:C.t}}>{title}</span>
      <span style={{fontFamily:MONO,color:C.tm,fontSize:10,lineHeight:1.5}}>{desc}</span>
    </button>
  );
  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:18,padding:24}}>
      <div style={{textAlign:"center",display:"flex",flexDirection:"column",gap:8,maxWidth:460}}>
        <span style={{fontFamily:MONO,color:C.a,fontSize:11,letterSpacing:1}}>FIREALIVE SETUP</span>
        <div style={{color:C.t,fontSize:20,fontWeight:600}}>Select deployment mode</div>
        <span style={{fontFamily:MONO,color:C.tm,fontSize:11,lineHeight:1.6}}>Choose how this deployment runs. This sets local virtualization tolerances and is confirmed against the server.</span>
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {card("bare-metal","Bare metal","Dedicated physical hardware. Strictest identity enforcement; no live-migration allowances.")}
        {card("virtualized","Virtualized","Runs in a VM or hypervisor. Allows authorized live migration (vMotion) while still refusing clones.")}
      </div>
      {err && <span style={{fontFamily:MONO,color:C.d,fontSize:10}}>{err}</span>}
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);
  const [locked, setLocked] = useState(false);
  const [deployMode, setDeployMode] = useState(undefined); // undefined = checking
  useEffect(()=>{
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || typeof bridge.invoke !== "function") { setDeployMode({ configured: true, unmanaged: true }); return; }
    bridge.invoke("deployment:getLocalMode")
      .then(d=>setDeployMode(d || { configured: false }))
      .catch(()=>setDeployMode({ configured: true, unmanaged: true }));
  },[]);
  function signOut() { api.setToken(null); setUser(null); setLocked(false); }
  function lock() { api.setToken(null); setUser(null); setLocked(true); }

  // Auto-lock after inactivity. Clears the in-memory session and, by unmounting
  // the views, any decrypted evidence; the reviewer must re-authenticate. The
  // sealed reviewer private key stays on-device throughout.
  const IDLE_MS = 5 * 60 * 1000;
  useEffect(() => {
    if (!user) return;
    let t;
    const reset = () => { clearTimeout(t); t = setTimeout(lock, IDLE_MS); };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    events.forEach(e => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => { clearTimeout(t); events.forEach(e => window.removeEventListener(e, reset)); };
  }, [user]);

  if (deployMode === undefined) return null;
  if (!deployMode.configured) return <DeploymentSetup onComplete={()=>setDeployMode({ configured: true })} />;

  return (
    <div>
      <style>{CSS}</style>
      {user ? <Shell user={user} onSignOut={signOut} /> : <Login onAuthed={(u)=>{ setLocked(false); setUser(u); }} locked={locked} />}
    </div>
  );
}

// Canonical React 18 mount (PR H): explicit, single, defensive root.
// Uses the imported createRoot; no global ReactDOM / vendored UMD.
const _rootEl = document.getElementById("root");
if (!_rootEl) {
  const _err = document.createElement("div");
  _err.textContent = "Fatal: #root element not found. FireAlive cannot start.";
  _err.style.cssText = "font-family:monospace;color:#EF4444;padding:24px;font-size:14px";
  document.body.appendChild(_err);
} else {
  createRoot(_rootEl).render(<App />);
}

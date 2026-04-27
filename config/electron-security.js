// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.58 — Electron Security Configuration
// For AC and MC (Electron desktop apps)
// ═══════════════════════════════════════════════════════════════════════════════

const electronSecurityConfig = {
  // BrowserWindow security options
  webPreferences: {
    nodeIntegration: false,          // CRITICAL: prevents RCE
    contextIsolation: true,          // CRITICAL: isolates renderer from Node
    sandbox: true,                   // CRITICAL: OS-level sandboxing
    webSecurity: true,               // Enforce same-origin
    allowRunningInsecureContent: false,
    enableRemoteModule: false,       // Deprecated and dangerous
    worldSafeExecuteJavaScript: true,
    safeDialogs: true,
    navigateOnDragDrop: false,       // Prevent drag-and-drop navigation
    spellcheck: false,               // Disable to prevent data leak to spell service
  },
  // Content Security Policy for Electron
  contentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://localhost:*; font-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'",
  // Disable navigation to external URLs
  navigationWhitelist: [
    'app://firealive-ac',
    'app://firealive-mc',
  ],
  // Certificate pinning for mTLS connections
  certificatePinning: {
    enabled: true,
    pins: [] // SHA-256 hashes of server certificates, set during deployment
  },
  // Auto-update security
  autoUpdate: {
    requireSignature: true,          // Code signing required
    allowDowngrade: false,           // Anti-rollback (enforced by e-fuse)
    updateUrl: null,                 // Set during deployment, HTTPS only
  },
  // IPC security
  ipc: {
    allowedChannels: [
      'auth:login', 'auth:logout', 'auth:mfa',
      'data:fetch', 'data:save',
      'config:get', 'config:set',
      'peer:connect', 'peer:message',
      'audit:log'
    ]
  },
  // macOS Lockdown Mode compatibility
  lockdownModeCompat: {
    noJIT: true,                     // Disable JIT (required for Lockdown Mode)
    noSharedMemory: false,           // Keep for performance but isolate
    disableWebGL: true,              // Reduce attack surface
  }
};

module.exports = electronSecurityConfig;

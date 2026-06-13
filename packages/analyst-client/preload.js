const { contextBridge, ipcRenderer } = require('electron');
const pkg = require('./package.json');

// Expose only whitelisted IPC channels
const ALLOWED_CHANNELS = [
  'auth:login', 'auth:logout', 'auth:mfa', 'auth:importCaCert', 'auth:caStatus',
  'data:fetch', 'data:save', 'data:signals',
  'peer:connect', 'peer:message', 'peer:disconnect',
  'training:submit', 'assessment:submit',
  'config:get', 'config:set',
  'audit:log', 'audit:export',
  'notify:desktop',
  'e2ee:init', 'e2ee:publishBundle', 'e2ee:replenishPrekeys', 'e2ee:processBundle', 'e2ee:hasSession', 'e2ee:encrypt', 'e2ee:decrypt', 'e2ee:safetyNumber',
  'abuse:seal', 'abuse:hold-for-export', 'abuse:finalize-export', 'abuse:cancel-export',
  'kb:search', 'kb:entry', 'kbChat:ask', 'kbChat:modelStatus', 'kbChat:verifyModel', 'kbChat:provisioningInfo', 'kbChat:modelScanStatus',
  'selfscan:getPublicKey', 'selfscan:run', 'device:signSessionChallenge',
  'burnout:status', 'burnout:enrollKey', 'burnout:unlockKey', 'burnout:decrypt', 'burnout:lock', 'burnout:addHwFactor', 'burnout:removeHwFactor', 'burnout:interpret', 'burnout:interpretOverall',
  // B5d4: per-client recovery + fleet ops
  'clientop:run', 'recovery:wipeLocal', 'burnout:recoverAndRewrap',
  // B5e: AC-side anti-cloning ratchet (present + check server ratchet)
  'anticlone:ratchetState', 'anticlone:recordRatchet',
  // B5e (D25): AC-side server anchor pinning + per-connect verification
  'anticlone:anchorNonce', 'anticlone:verifyAnchor', 'anticlone:pinAnchor', 'anticlone:anchorState',
  // B5e (D9): deployment-mode first-run selection
  'deployment:getLocalMode', 'deployment:setLocalMode',
];

contextBridge.exposeInMainWorld('firealive', {
  send: (channel, data) => {
    if (ALLOWED_CHANNELS.includes(channel)) ipcRenderer.send(channel, data);
  },
  invoke: (channel, data) => {
    if (ALLOWED_CHANNELS.includes(channel)) return ipcRenderer.invoke(channel, data);
    return Promise.reject(new Error('Channel not allowed'));
  },
  on: (channel, callback) => {
    if (ALLOWED_CHANNELS.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => callback(...args));
    }
  },
  version: pkg.version,
  component: 'analyst-client',
});

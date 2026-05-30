const { contextBridge, ipcRenderer } = require('electron');
const pkg = require('./package.json');

// Expose only whitelisted IPC channels
const ALLOWED_CHANNELS = [
  'auth:login', 'auth:logout', 'auth:mfa',
  'data:fetch', 'data:save', 'data:signals',
  'peer:connect', 'peer:message', 'peer:disconnect',
  'training:submit', 'assessment:submit',
  'config:get', 'config:set',
  'audit:log', 'audit:export',
  'notify:desktop',
  'e2ee:init', 'e2ee:publishBundle', 'e2ee:replenishPrekeys', 'e2ee:processBundle', 'e2ee:hasSession', 'e2ee:encrypt', 'e2ee:decrypt', 'e2ee:safetyNumber',
  'abuse:seal', 'abuse:hold-for-export', 'abuse:finalize-export', 'abuse:cancel-export',
  'kb:search', 'kb:entry', 'kbChat:ask', 'kbChat:modelStatus', 'kbChat:verifyModel', 'kbChat:provisioningInfo',
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

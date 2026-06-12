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
  'device:getPublicKey', 'device:signLoginChallenge', 'device:signPopProof',
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
  component: 'global-dashboard',
});

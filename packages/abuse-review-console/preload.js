const { contextBridge, ipcRenderer } = require('electron');
const pkg = require('./package.json');

// Minimal, least-privilege IPC surface. The ARC reaches the server's
// reviewer-only API over HTTP (that needs no IPC); IPC is used ONLY for the
// reviewer-key operations that must stay in the main process: checking for and
// generating the org reviewer keypair, and opening sealed case content with the
// private key. The main-process handlers for these channels land in F5b.
const ALLOWED_CHANNELS = [
  'abuse:hasKey', 'abuse:generateKey', 'abuse:unlock', 'abuse:lock', 'abuse:open', 'abuse:cisoKeyStatus', 'abuse:pinCisoKey', 'abuse:verifyExportToken',
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
  component: 'abuse-review-console',
});

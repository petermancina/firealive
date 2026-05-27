const { app, BrowserWindow, session } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let gdServerProcess = null;

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

function startGdServer() {
  const serverPath = path.join(__dirname, '..', 'global-dashboard-server', 'index.js');
  gdServerProcess = spawn('node', [serverPath], {
    env: { ...process.env, NODE_ENV: 'production', GD_PORT: '4001' },
    stdio: 'pipe'
  });
  gdServerProcess.stdout.on('data', (d) => console.log('[GD-Server]', d.toString()));
  gdServerProcess.stderr.on('data', (d) => console.error('[GD-Server]', d.toString()));
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440, height: 900,
    title: 'FireAlive — Global Dashboard',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"] } });
  });
  win.loadFile('index.html');
}

app.whenReady().then(() => { startGdServer(); setTimeout(createWindow, 2000); });
app.on('window-all-closed', () => { if (gdServerProcess) gdServerProcess.kill(); if (process.platform !== 'darwin') app.quit(); });

const { app, BrowserWindow, session } = require('electron');
const path = require('path');

// The Abuse Review Console talks ONLY to the existing FireAlive server's
// reviewer-only API (/api/abuse-review/*). It runs no server of its own -- the
// evidence vault stays single-source on the main server. Sealed case content is
// opened client-side in this main process; the abuse-seal helper and the
// reviewer-key bootstrap (generate keypair, register the public key, seal the
// private key via safeStorage) are added in F5b.

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1440, height: 900,
    title: 'FireAlive — Abuse Review Console',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"] } });
  });
  win.loadFile('index.html');
}

app.whenReady().then(createWindow);
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

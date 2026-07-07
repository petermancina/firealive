#!/usr/bin/env node
//
// FIREALIVE GLOBAL DASHBOARD -- Recover the hardware-sealed GD Tier-1 KEK on new hardware
//
// The GD analogue of scripts/recover-tier1-kek.js. Run on a REPLACEMENT GD Server
// host after the original TPM / Secure Enclave is lost (decision D26). Takes the
// offline recovery code emitted at GD provisioning plus its passphrase, re-
// establishes the IDENTICAL GD Tier-1 key, re-seals it to this host's hardware
// root of trust, and prints the new value to set as GD_ENCRYPTION_KEY. After that,
// restore the GD Server from a backup: the backup is encrypted under this key,
// which is now re-established, so the restore can decrypt it.
//
// The recovery code is read from FIREALIVE_GD_RECOVERY_CODE if set, otherwise it
// is prompted for (it is protected by the passphrase, so it is shown as typed).
// The passphrase is read from FIREALIVE_GD_RECOVERY_PASSPHRASE if set, otherwise
// it is prompted for without echo. The recovered key never leaves this process and
// is zeroed after use.
//
// The recovered key is identical to the original, so the existing recovery code
// stays valid -- keep it offline. The new wrapper is sealed to THIS hardware (the
// vTPM in Cloud Mode) and will only unseal here.
//
// Run:  node scripts/gd-recover-tier1-kek.js
// Exits 0 on success, non-zero (with a reason) on a wrong passphrase, a corrupt
// recovery code, or when no hardware root of trust is present to re-seal to.
//

const path = require('path');
const readline = require('readline');

const GD_SERVER = path.join(__dirname, '..', 'packages', 'global-dashboard-server');
const gdTier1Kek = require(path.join(GD_SERVER, 'services', 'gd-tier1-kek.js'));

// Prompt for a line WITH echo (the recovery code is passphrase-protected, and
// seeing it as typed avoids paste errors on a long value).
function promptVisible(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(query, (value) => {
      rl.close();
      resolve(value);
    });
  });
}

// Prompt for a line WITHOUT echo (the recovery passphrase).
function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const newline = String.fromCharCode(10);
    let muted = false;
    rl._writeToOutput = function (s) {
      if (!muted) {
        rl.output.write(s);
      }
    };
    rl.question(query, (value) => {
      rl.output.write(newline);
      rl.close();
      resolve(value);
    });
    muted = true;
  });
}

async function getRecoveryCode() {
  const fromEnv = process.env.FIREALIVE_GD_RECOVERY_CODE;
  if (typeof fromEnv === 'string' && fromEnv.trim().length > 0) {
    return fromEnv.trim();
  }
  const code = await promptVisible('Paste the recovery code (begins fa-gd-tier1-recovery:v1:): ');
  return code.trim();
}

async function getPassphrase() {
  const fromEnv = process.env.FIREALIVE_GD_RECOVERY_PASSPHRASE;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    return fromEnv;
  }
  return promptHidden('Recovery passphrase: ');
}

function printInstructions(wrapper) {
  const log = (s) => process.stdout.write((s === undefined ? '' : s) + String.fromCharCode(10));
  log('');
  log('FireAlive Global Dashboard -- GD Tier-1 KEK recovered and re-sealed to this hardware.');
  log('');
  log('1) Set this as GD_ENCRYPTION_KEY in your GD Server environment or secrets manager:');
  log('');
  log('   ' + wrapper);
  log('');
  log('2) Then restore the GD Server from your most recent backup. It is encrypted');
  log('   under this key, which you have now re-established, so the restore can');
  log('   decrypt it.');
  log('');
  log('NOTES');
  log(' - The recovered key is identical to the original, so your existing recovery');
  log('   code stays valid. Keep it stored offline.');
  log(' - The new wrapper is sealed to THIS host hardware (the vTPM in Cloud Mode)');
  log('   and will only unseal here.');
  log('');
}

async function main() {
  let kek = null;
  try {
    const recoveryCode = await getRecoveryCode();
    const passphrase = await getPassphrase();
    try {
      kek = gdTier1Kek.recoverKekFromCode(recoveryCode, passphrase);
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      throw new Error('could not recover the GD Tier-1 KEK: ' + detail);
    }
    let wrapper;
    try {
      wrapper = gdTier1Kek.sealKekToWrapper(kek);
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      throw new Error('recovered the key but could not re-seal it to this hardware: ' + detail);
    }
    printInstructions(wrapper);
    return { wrapper: wrapper };
  } finally {
    if (kek) {
      kek.fill(0);
    }
  }
}

if (require.main === module) {
  main()
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      process.stderr.write('gd-recover-tier1-kek: ' + (err && err.message ? err.message : String(err)) + String.fromCharCode(10));
      process.exit(1);
    });
}

module.exports = { main: main };

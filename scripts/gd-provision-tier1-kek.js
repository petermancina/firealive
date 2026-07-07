#!/usr/bin/env node
//
// FIREALIVE GLOBAL DASHBOARD -- Provision the hardware-sealed GD Tier-1 KEK
//
// The GD analogue of scripts/provision-tier1-kek.js. Run ONCE on the GD Server
// host, on the hardware that will run the Global Dashboard, before first start.
// Generates the GD Tier-1 key-encryption-key (the AES-256-GCM key that protects
// the GD's secrets at rest: every GD signing-key private key, the GD CA key,
// integration credentials), seals it to this host TPM 2.0 / Secure Enclave
// (decision D26), and prints two things:
//
//   1. the value to set as GD_ENCRYPTION_KEY (an opaque hardware-sealed wrapper
//      -- only this hardware can unseal it; a copied disk cannot), and
//   2. a one-time RECOVERY CODE (the same key wrapped under a passphrase you
//      choose) to store OFFLINE. It is the only way to re-establish the key on
//      replacement hardware if the TPM / Secure Enclave is ever lost.
//
// The recovery passphrase is read from FIREALIVE_GD_RECOVERY_PASSPHRASE if set
// (for non-interactive provisioning); otherwise it is prompted for, without echo,
// and confirmed. The raw key never leaves this process and is zeroed after use.
//
// In Cloud Mode the GD seals to the confidential VM's vTPM; run this on the
// confidential VM at provisioning so GD_ENCRYPTION_KEY is sealed to that vTPM
// (this supersedes the former "supply a raw GD_ENCRYPTION_KEY via the cloud
// secret store" posture -- no raw key is ever placed in the environment).
//
// WARNINGS
//   - Keep the recovery code AND back up the GD Server. A backup is encrypted
//     under this key and cannot be restored without it (from this hardware or the
//     recovery code). Neither the backup nor the recovery code alone is enough.
//   - Re-running this generates a NEW key that CANNOT decrypt anything encrypted
//     under the previous one. Only run it for initial setup.
//
// Run:  node scripts/gd-provision-tier1-kek.js
// Exits 0 on success, non-zero (with a reason) if no hardware root of trust is
// present or the inputs are invalid.
//

const path = require('path');
const readline = require('readline');

const GD_SERVER = path.join(__dirname, '..', 'packages', 'global-dashboard-server');
const gdTier1Kek = require(path.join(GD_SERVER, 'services', 'gd-tier1-kek.js'));

const MIN_PASSPHRASE_LENGTH = 12;

// Prompt for a line without echoing keystrokes (recovery passphrase entry).
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

async function getPassphrase() {
  const fromEnv = process.env.FIREALIVE_GD_RECOVERY_PASSPHRASE;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    if (fromEnv.length < MIN_PASSPHRASE_LENGTH) {
      throw new Error('FIREALIVE_GD_RECOVERY_PASSPHRASE must be at least ' + MIN_PASSPHRASE_LENGTH + ' characters');
    }
    return fromEnv;
  }
  const first = await promptHidden('Choose a recovery passphrase (at least ' + MIN_PASSPHRASE_LENGTH + ' characters; store it with the recovery code): ');
  if (first.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error('passphrase must be at least ' + MIN_PASSPHRASE_LENGTH + ' characters');
  }
  const second = await promptHidden('Confirm recovery passphrase: ');
  if (first !== second) {
    throw new Error('passphrases did not match');
  }
  return first;
}

function printInstructions(wrapper, recoveryCode) {
  const log = (s) => process.stdout.write((s === undefined ? '' : s) + String.fromCharCode(10));
  log('');
  log('FireAlive Global Dashboard -- GD Tier-1 KEK provisioned and sealed to this hardware.');
  log('');
  log('1) Set this as GD_ENCRYPTION_KEY in your GD Server environment or secrets manager:');
  log('');
  log('   ' + wrapper);
  log('');
  log('2) Store this RECOVERY CODE offline. It is shown once and is the only way to');
  log('   re-establish the key on new hardware (with your passphrase):');
  log('');
  log('   ' + recoveryCode);
  log('');
  log('IMPORTANT');
  log(' - The key is sealed to THIS GD host TPM / Secure Enclave (the vTPM in Cloud');
  log('   Mode). A copied disk cannot unseal it, so the secrets it protects stay');
  log('   inert off this hardware.');
  log(' - Back up the GD Server regularly AND keep the recovery code. A backup is');
  log('   encrypted under this key; restoring needs the key, from this hardware or');
  log('   the recovery code. Neither alone can recover a failed deployment.');
  log(' - Re-running this script makes a NEW key that cannot decrypt data encrypted');
  log('   under the old one. Only run it for initial setup.');
  log('');
}

async function main() {
  let kek = null;
  try {
    const passphrase = await getPassphrase();
    kek = gdTier1Kek.generateKek();
    let wrapper;
    try {
      wrapper = gdTier1Kek.sealKekToWrapper(kek);
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      throw new Error('cannot seal the GD Tier-1 KEK to hardware: ' + detail);
    }
    const recoveryCode = gdTier1Kek.makeRecoveryCode(kek, passphrase);
    printInstructions(wrapper, recoveryCode);
    return { wrapper: wrapper, recoveryCode: recoveryCode };
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
      process.stderr.write('gd-provision-tier1-kek: ' + (err && err.message ? err.message : String(err)) + String.fromCharCode(10));
      process.exit(1);
    });
}

module.exports = { main: main };

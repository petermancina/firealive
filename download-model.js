#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Local Model Provisioning (VERIFY-ONLY)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// FireAlive NEVER downloads AI model weights. This tool VERIFIES that the
// operator has provisioned the correct, official model files — it makes ZERO
// network calls. There is no URL on the other end for anyone to poison.
//
// The operator obtains the official files through their OWN vetted channel
// (the official publisher's page on Hugging Face or an internal mirror),
// places them in the model directory, and FireAlive verifies each file
// against a SHA-256 that is PINNED IN THIS SOURCE FILE (reviewed, version-
// controlled). A file only loads on an exact hash match; anything else is
// refused. Because the expected hashes live in code — never supplied at runtime
// — an insider cannot drop in a tampered model plus a matching hash.
//
// Updating a model = a reviewed FireAlive code change (bump pinnedCommit + the
// per-file sha256 below), never a runtime input.
//
// Two models are provisioned (both land in the same model directory):
//   • chat      — Phi-4, Q4_K (single GGUF, ~9.05 GB).
//                 Used by the MC lead KB chat via server/services/internal-llm.js.
//   • embedding — Nomic Embed Text v1.5, F16 (~274 MB, 768-dim). Used by
//                 server/services/kb-embeddings.js for KB semantic retrieval.
//
// Usage (no network, ever):
//   node scripts/download-model.js                 — verify chat + embedder
//   node scripts/download-model.js --verify        — same (explicit)
//   node scripts/download-model.js --model chat    — verify just the chat model
//   node scripts/download-model.js --instructions  — print provisioning guide
//
// Programmatic:
//   const prov = require('./scripts/download-model');
//   const r = await prov.verifyModel('embedding');   // { ok, status, files, ... }
//   if (!r.ok) { /* refuse to load; show prov.provisioningInstructions('embedding') */ }
//
// Environment:
//   FIREALIVE_MODEL_PATH — model directory (or a *.gguf path; its dir is used).
//                          Defaults to ~/.firealive/models/.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// ── Pinned model manifest (source of truth) ──────────────────────────────────
// Every expected SHA-256 below was read from the official publisher pages and is
// pinned here. NOTHING here is fetched. To change a model, update pinnedCommit
// and the per-file sha256 in a reviewed commit.

const MODELS = {
  chat: {
    id: 'chat',
    kind: 'chat',
    label: 'Phi-4 Q4_K (Microsoft, 14B, MIT)',
    officialSource: {
      publisher: 'Microsoft',
      huggingFaceRepo: 'microsoft/phi-4-gguf',
      pinnedCommit: '18ece485b98ae22388ffad82ad468cc2d774f6d4',
    },
    // node-llama-cpp loads this single-file GGUF; it is verified before load.
    loadFile: 'phi-4-Q4_K.gguf',
    files: [
      { filename: 'phi-4-Q4_K.gguf', sizeApprox: '9.05 GB',
        sha256: '5652b9be0ea4ae2842130d04fe31bc869fcb99a2b7106c53b4e754a343fd688f' },
    ],
    endpointFloor: '~9.05 GB free disk + ~10-12 GB RAM to run the 14B locally.',
  },
  embedding: {
    id: 'embedding',
    kind: 'embedding',
    label: 'Nomic Embed Text v1.5 F16 (Nomic AI, 768-dim, Apache-2.0)',
    officialSource: {
      publisher: 'Nomic AI',
      huggingFaceRepo: 'nomic-ai/nomic-embed-text-v1.5-GGUF',
      pinnedCommit: '18d1044f4866e224159fce8c6fc5c4f3920176e7',
    },
    // MUST match DEFAULT_EMBED_FILENAME in server/services/kb-embeddings.js and
    // the AC bundled embedder — that's where retrieval looks.
    loadFile: 'nomic-embed-text-v1.5.f16.gguf',
    files: [
      { filename: 'nomic-embed-text-v1.5.f16.gguf', sizeApprox: '274 MB',
        sha256: 'f7af6f66802f4df86eda10fe9bbcfc75c39562bed48ef6ace719a251cf1c2fdb' },
    ],
    endpointFloor: '~274 MB free disk; minimal RAM.',
  },
};

// Compat alias: ai-provider.js (until it moves to verifyModel) reads dl.VARIANTS.
const VARIANTS = MODELS;
const MODEL_IDS = Object.keys(MODELS);

// ── Path resolution (shared with the runtime loaders) ────────────────────────

function resolveModelDir() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath) {
    if (envPath.toLowerCase().endsWith('.gguf')) return path.dirname(envPath);
    return envPath;
  }
  return path.join(os.homedir(), '.firealive', 'models');
}

function modelFiles(id) {
  const m = MODELS[id];
  if (!m) throw new Error('unknown model: ' + id);
  const dir = resolveModelDir();
  return m.files.map(f => ({ ...f, path: path.join(dir, f.filename) }));
}

// Path the loader hands to node-llama-cpp (the model's load file).
function resolveModelPath(id) {
  const m = MODELS[id];
  if (!m) throw new Error('unknown model: ' + id);
  return path.join(resolveModelDir(), m.loadFile);
}

function isModelPresent(id) {
  return modelFiles(id).every(f => fs.existsSync(f.path));
}

function isEmbedderPresent() {
  return isModelPresent('embedding');
}

// ── Verify (the only integrity gate; NO network) ─────────────────────────────
// Streams each file, computes SHA-256, compares to the pinned value.
// status: 'ok' (all present + all match) | 'missing' (≥1 absent) | 'mismatch'.

async function verifyModel(id) {
  const m = MODELS[id];
  if (!m) return { ok: false, status: 'unknown-model', id };

  const files = [];
  let anyMissing = false;
  let anyMismatch = false;

  for (const f of modelFiles(id)) {
    if (!fs.existsSync(f.path)) {
      anyMissing = true;
      files.push({ filename: f.filename, path: f.path, present: false, match: false,
        expected: f.sha256, actual: null });
      continue;
    }
    const actual = await sha256File(f.path);
    const match = actual === f.sha256;
    if (!match) anyMismatch = true;
    files.push({ filename: f.filename, path: f.path, present: true, match,
      expected: f.sha256, actual });
  }

  const status = anyMissing ? 'missing' : (anyMismatch ? 'mismatch' : 'ok');
  return {
    ok: status === 'ok',
    status,
    id,
    kind: m.kind,
    label: m.label,
    loadFile: m.loadFile,
    loadPath: resolveModelPath(id),
    modelDir: resolveModelDir(),
    files,
  };
}

async function verifyAll() {
  const results = {};
  for (const id of MODEL_IDS) results[id] = await verifyModel(id);
  return { ok: MODEL_IDS.every(id => results[id].ok), models: results };
}

// Back-compat name some callers used; now just verifyModel.
function checkModel(id) {
  return verifyModel(id || 'chat');
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// ── Provisioning instructions (operator-facing; no network performed) ────────

function provisioningInstructions(id) {
  const m = MODELS[id];
  if (!m) return 'Unknown model: ' + id;
  const dir = resolveModelDir();
  const lines = [];
  lines.push(`Provision the ${m.kind} model: ${m.label}`);
  lines.push('');
  lines.push('FireAlive does not download models. Obtain the official files through');
  lines.push('your own vetted channel, then place them in the model directory below.');
  lines.push('');
  lines.push('Official first-party source:');
  lines.push(`  • Hugging Face (official publisher): ${m.officialSource.huggingFaceRepo}`);
  lines.push(`    pinned commit: ${m.officialSource.pinnedCommit}`);
  lines.push('');
  lines.push(`Model directory: ${dir}`);
  lines.push(`Endpoint floor: ${m.endpointFloor}`);
  lines.push('');
  lines.push('Place these file(s) and confirm each SHA-256 matches exactly:');
  for (const f of m.files) {
    lines.push(`  ${f.filename}  (${f.sizeApprox})`);
    lines.push(`    sha256: ${f.sha256}`);
  }
  lines.push('');
  lines.push('Then verify:  node scripts/download-model.js --model ' + id);
  return lines.join('\n');
}

// ── CLI (verify-only) ─────────────────────────────────────────────────────────

async function cli() {
  const args = process.argv.slice(2);
  let only = null;
  let mode = 'verify';

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--verify' || a === '--check') mode = 'verify';
    else if (a === '--instructions') mode = 'instructions';
    else if (a === '--model' || a === '--variant') {
      only = args[++i];
      if (!MODELS[only]) {
        console.error(`Unknown model: ${only}`);
        console.error(`Available: ${MODEL_IDS.join(', ')}`);
        process.exit(2);
      }
    } else if (a === '--help' || a === '-h') {
      console.log('FireAlive model provisioning (VERIFY-ONLY — no downloads).');
      console.log('Usage: node scripts/download-model.js [options]');
      console.log('  --verify              verify provisioned model files (default)');
      console.log('  --instructions        print provisioning guide + pinned hashes');
      console.log('  --model <chat|embedding>  act on a single model');
      console.log('  --help                show this message');
      process.exit(0);
    }
  }

  const ids = only ? [only] : MODEL_IDS;

  if (mode === 'instructions') {
    for (const id of ids) {
      console.log(provisioningInstructions(id));
      console.log('');
    }
    process.exit(0);
  }

  let allOk = true;
  for (const id of ids) {
    const r = await verifyModel(id);
    if (r.ok) {
      console.log(`\u2713 ${id} verified (${r.label})`);
      console.log(`  dir: ${r.modelDir}`);
    } else {
      allOk = false;
      console.error(`\u2717 ${id} NOT ready — status: ${r.status}`);
      for (const f of r.files) {
        if (!f.present) console.error(`  missing: ${f.filename}`);
        else if (!f.match) console.error(`  hash mismatch: ${f.filename}\n    expected ${f.expected}\n    actual   ${f.actual}`);
      }
      console.error('');
      console.error(provisioningInstructions(id));
      console.error('');
    }
  }
  process.exit(allOk ? 0 : 1);
}

if (require.main === module) {
  cli();
}

module.exports = {
  MODELS,
  VARIANTS,            // compat alias (= MODELS)
  MODEL_IDS,
  resolveModelDir,
  resolveModelPath,
  modelFiles,
  isModelPresent,
  isEmbedderPresent,
  verifyModel,
  verifyAll,
  checkModel,          // alias -> verifyModel
  provisioningInstructions,
  sha256File,
};

#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Local LLM Model Bootstrap
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Downloads the FireAlive local model files from HuggingFace on first run.
//
// Two kinds of model are provisioned:
//   • chat      — the internal LLM (default: Phi-3-mini-4k-instruct-q4_K_M,
//                 ~2.4GB, MIT licensed; or the smaller Qwen 1.5B fallback).
//   • embedding — the KB retrieval embedder (all-MiniLM-L6-v2 Q8_0, ~25MB,
//                 384-dim, Apache 2.0), used by server/services/kb-embeddings.js
//                 for semantic search over the Research KB (K1).
//
// Both live in the same model directory. The embedder is small enough that the
// default run fetches it alongside the chat model — semantic retrieval needs it
// regardless of which chat variant is chosen.
//
// Usage:
//
//   node scripts/download-model.js                   — download chat default + embedder
//   node scripts/download-model.js --check           — verify chat default + embedder
//   node scripts/download-model.js --variant qwen    — download just the Qwen chat fallback
//   node scripts/download-model.js --variant minilm  — download just the embedder
//   node scripts/download-model.js --force           — re-download even if present
//
// Or programmatically from server code:
//
//   const { downloadDefaultModel, downloadEmbedder, isModelPresent, isEmbedderPresent }
//     = require('./scripts/download-model');
//   if (!isModelPresent())  await downloadDefaultModel({ onProgress: ... });  // chat
//   if (!isEmbedderPresent()) await downloadEmbedder({ onProgress: ... });    // embedder
//
// Environment variables:
//
//   FIREALIVE_MODEL_PATH    — directory or file path; defaults to
//                             ~/.firealive/models/ (both chat + embedder land here)
//   FIREALIVE_MODEL_VARIANT — 'phi3' (default) or 'qwen' (smaller chat fallback)
//
// On success: writes the .gguf model file(s) to disk plus a manifest.json
// recording { kind, label, filename, sizeBytes, sha256, downloadedAt, sourceUrl }
// per file.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const https = require('https');

// ── Model variants ──────────────────────────────────────────────────────────
// Each variant is a fully-specified record so downloads are reproducible
// across hosts and audited against expected hashes. `kind` distinguishes the
// chat LLM ('chat') from the KB retrieval embedder ('embedding'); both land in
// the same model directory.

const VARIANTS = {
  phi3: {
    kind: 'chat',
    label: 'Phi-3-mini-4k-instruct (Microsoft, 3.8B params, MIT licensed)',
    filename: 'phi-3-mini-4k-instruct-q4.gguf',
    sourceUrl: 'https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf',
    sha256: '8a83c7fb9049a9b2e92266fa7ad04933bb53aa1e85136b7b30f1b8000ff2edef',
    sizeBytes: 2393232672,  // ~2.39 GB
  },
  qwen: {
    kind: 'chat',
    label: 'Qwen-2.5-1.5B-instruct (Alibaba, 1.5B params, Apache 2.0 — smaller fallback)',
    filename: 'qwen2.5-1.5b-instruct-q4_k_m.gguf',
    // Hash and exact URL must be verified before enabling this variant in
    // production. The path below is the typical second-state mirror for
    // Qwen GGUF models; users selecting this variant should confirm the
    // hash from the source repo card.
    sourceUrl: 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf',
    sha256: null,  // not pinned — fallback variant, advisory use only
    sizeBytes: null,
  },
  minilm: {
    kind: 'embedding',
    label: 'all-MiniLM-L6-v2 Q8_0 (Second State, 384-dim sentence embeddings, Apache 2.0)',
    // Filename MUST match DEFAULT_EMBED_FILENAME in server/services/kb-embeddings.js
    // (and the AC's bundled embedder) — that's where the retrieval service looks.
    filename: 'all-MiniLM-L6-v2-Q8_0.gguf',
    sourceUrl: 'https://huggingface.co/second-state/All-MiniLM-L6-v2-Embedding-GGUF/resolve/main/all-MiniLM-L6-v2-Q8_0.gguf',
    // Verified against the HuggingFace file page (git-LFS SHA-256), 2026-05.
    sha256: '263215c3cadd6e16740741a7624ab4cbb6c8e777688bd5331ecfbf5681c2f8ed',
    sizeBytes: null,  // ~25 MB (Q8_0); exact byte count not published, so not pinned — integrity is enforced by the SHA-256 above
  },
};

const DEFAULT_VARIANT = 'phi3';
const DEFAULT_EMBEDDER = 'minilm';

// ── Public API ──────────────────────────────────────────────────────────────

function resolveModelDir() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath) {
    if (envPath.endsWith('.gguf')) return path.dirname(envPath);
    return envPath;
  }
  return path.join(os.homedir(), '.firealive', 'models');
}

function resolveModelPath(variantKey) {
  const variant = VARIANTS[variantKey || DEFAULT_VARIANT];
  if (!variant) throw new Error('unknown variant: ' + variantKey);
  return path.join(resolveModelDir(), variant.filename);
}

function isModelPresent(variantKey) {
  const target = resolveModelPath(variantKey || DEFAULT_VARIANT);
  return fs.existsSync(target);
}

async function downloadDefaultModel(options) {
  return downloadModel(DEFAULT_VARIANT, options);
}

// Embedder helpers. Kept separate from downloadDefaultModel so the existing
// chat-model programmatic contract is unchanged: callers that want the
// retrieval embedder ask for it explicitly.

function isEmbedderPresent() {
  return isModelPresent(DEFAULT_EMBEDDER);
}

async function downloadEmbedder(options) {
  return downloadModel(DEFAULT_EMBEDDER, options);
}

async function downloadModel(variantKey, options) {
  options = options || {};
  const variant = VARIANTS[variantKey];
  if (!variant) throw new Error('unknown variant: ' + variantKey);

  const dir = resolveModelDir();
  fs.mkdirSync(dir, { recursive: true });
  const target = path.join(dir, variant.filename);

  // Already present + verified? Skip.
  if (!options.force && fs.existsSync(target)) {
    if (variant.sha256) {
      report(options, 'verifying existing file...');
      const actualHash = await sha256File(target);
      if (actualHash === variant.sha256) {
        report(options, `existing file verified: ${variant.filename}`);
        writeManifest(dir, variant);
        return target;
      }
      report(options, `existing file hash mismatch (got ${actualHash.slice(0, 16)}…); re-downloading`);
      fs.unlinkSync(target);
    } else {
      report(options, `existing file present; skipping (no hash to verify): ${variant.filename}`);
      writeManifest(dir, variant);
      return target;
    }
  }

  report(options, `downloading ${variant.label}`);
  report(options, `from: ${variant.sourceUrl}`);
  report(options, `to:   ${target}`);
  report(options, '');

  await downloadWithProgress(variant.sourceUrl, target, options);

  if (variant.sha256) {
    report(options, '');
    report(options, 'verifying SHA-256...');
    const actualHash = await sha256File(target);
    if (actualHash !== variant.sha256) {
      fs.unlinkSync(target);
      throw new Error(`SHA-256 mismatch: expected ${variant.sha256}, got ${actualHash}; downloaded file deleted`);
    }
    report(options, '✓ SHA-256 verified');
  } else {
    report(options, '⚠ no SHA-256 pinned for this variant; skipping verification');
  }

  writeManifest(dir, variant);
  report(options, '');
  report(options, `✓ model ready at: ${target}`);
  return target;
}

async function checkModel(variantKey) {
  const variant = VARIANTS[variantKey || DEFAULT_VARIANT];
  if (!variant) return { ok: false, error: 'unknown variant' };

  const target = path.join(resolveModelDir(), variant.filename);
  if (!fs.existsSync(target)) {
    return { ok: false, error: 'file not present', path: target };
  }
  const stat = fs.statSync(target);
  if (variant.sha256) {
    const actualHash = await sha256File(target);
    if (actualHash !== variant.sha256) {
      return { ok: false, error: 'SHA-256 mismatch', path: target, expected: variant.sha256, actual: actualHash };
    }
  }
  return {
    ok: true,
    path: target,
    sizeBytes: stat.size,
    sha256: variant.sha256,
    variant: variantKey || DEFAULT_VARIANT,
  };
}

// ── Internal helpers ────────────────────────────────────────────────────────

function downloadWithProgress(url, destPath, options) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const tmpPath = destPath + '.partial';
    const file = fs.createWriteStream(tmpPath);
    let downloadedBytes = 0;
    let totalBytes = 0;
    let lastReportedPct = -1;

    const req = https.get(url, { headers: { 'User-Agent': 'FireAlive-Model-Bootstrap/1.0' } }, (res) => {
      // Follow redirects (HuggingFace serves files via 302 to a CDN)
      if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 303 || res.statusCode === 307 || res.statusCode === 308) {
        if (!res.headers.location) {
          file.close();
          fs.unlinkSync(tmpPath);
          return reject(new Error(`redirect ${res.statusCode} without Location header`));
        }
        file.close();
        return downloadWithProgress(res.headers.location, destPath, options).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        try { fs.unlinkSync(tmpPath); } catch (_) { /* ignore */ }
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }

      totalBytes = parseInt(res.headers['content-length'], 10) || 0;
      res.pipe(file);

      res.on('data', (chunk) => {
        downloadedBytes += chunk.length;
        if (totalBytes > 0) {
          const pct = Math.floor((downloadedBytes / totalBytes) * 100);
          if (pct !== lastReportedPct && pct % 5 === 0) {
            lastReportedPct = pct;
            const mb = (downloadedBytes / (1024 * 1024)).toFixed(1);
            const totalMb = (totalBytes / (1024 * 1024)).toFixed(1);
            const elapsedSec = (Date.now() - startedAt) / 1000;
            const speedMbs = elapsedSec > 0 ? (downloadedBytes / (1024 * 1024) / elapsedSec).toFixed(1) : '?';
            report(options, `  ${pct}% — ${mb} / ${totalMb} MB (${speedMbs} MB/s)`);
            if (options.onProgress) {
              options.onProgress({ downloadedBytes, totalBytes, pct });
            }
          }
        }
      });

      file.on('finish', () => {
        file.close(() => {
          fs.renameSync(tmpPath, destPath);
          resolve();
        });
      });
    });

    req.on('error', (err) => {
      try { file.close(); fs.unlinkSync(tmpPath); } catch (_) { /* ignore */ }
      reject(err);
    });

    file.on('error', (err) => {
      try { fs.unlinkSync(tmpPath); } catch (_) { /* ignore */ }
      reject(err);
    });
  });
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

function writeManifest(dir, variant) {
  const manifestPath = path.join(dir, 'manifest.json');
  let manifest = {};
  if (fs.existsSync(manifestPath)) {
    try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (_) { manifest = {}; }
  }
  manifest[variant.filename] = {
    kind: variant.kind || 'chat',
    label: variant.label,
    sourceUrl: variant.sourceUrl,
    sha256: variant.sha256,
    sizeBytes: variant.sizeBytes,
    downloadedAt: new Date().toISOString(),
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
}

function report(options, msg) {
  if (options.silent) return;
  if (options.onLog) options.onLog(msg);
  else process.stdout.write(msg + '\n');
}

// ── CLI ─────────────────────────────────────────────────────────────────────

async function cli() {
  const args = process.argv.slice(2);
  let variant = DEFAULT_VARIANT;
  let variantExplicit = false;
  let force = false;
  let mode = 'download';

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--check') mode = 'check';
    else if (a === '--force') force = true;
    else if (a === '--variant') {
      variant = args[++i];
      variantExplicit = true;
      if (!VARIANTS[variant]) {
        console.error(`Unknown variant: ${variant}`);
        console.error(`Available: ${Object.keys(VARIANTS).join(', ')}`);
        process.exit(2);
      }
    } else if (a === '--help' || a === '-h') {
      console.log('Usage: node scripts/download-model.js [options]');
      console.log('  --check               verify model files');
      console.log('  --force               re-download even if present');
      console.log('  --variant <name>      pick a single variant (phi3 | qwen | minilm)');
      console.log('  --help                show this message');
      console.log('');
      console.log('With no --variant, the default action provisions the chat default');
      console.log(`(${DEFAULT_VARIANT}) plus the KB retrieval embedder (${DEFAULT_EMBEDDER}).`);
      console.log('');
      console.log('Available variants:');
      for (const [key, v] of Object.entries(VARIANTS)) {
        console.log(`  ${key.padEnd(8)} [${(v.kind || 'chat').padEnd(9)}] ${v.label}`);
      }
      process.exit(0);
    }
  }

  // With an explicit --variant, act on exactly that one. Otherwise act on the
  // chat default AND the embedder — semantic retrieval needs the embedder
  // regardless of the chat model, and it's only ~25 MB.
  const targets = variantExplicit ? [variant] : [DEFAULT_VARIANT, DEFAULT_EMBEDDER];

  try {
    if (mode === 'check') {
      let allOk = true;
      for (const v of targets) {
        const result = await checkModel(v);
        if (result.ok) {
          console.log(`✓ ${v} model verified at ${result.path}`);
          console.log(`  size: ${(result.sizeBytes / (1024 * 1024)).toFixed(1)} MB`);
        } else {
          allOk = false;
          console.error(`✗ ${v} check failed: ${result.error}`);
          if (result.path) console.error(`  path: ${result.path}`);
          if (result.expected) console.error(`  expected SHA-256: ${result.expected}`);
          if (result.actual) console.error(`  actual SHA-256:   ${result.actual}`);
        }
      }
      process.exit(allOk ? 0 : 1);
    } else {
      for (const v of targets) {
        await downloadModel(v, { force });
      }
      process.exit(0);
    }
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  cli();
}

module.exports = {
  VARIANTS,
  DEFAULT_VARIANT,
  DEFAULT_EMBEDDER,
  resolveModelDir,
  resolveModelPath,
  isModelPresent,
  isEmbedderPresent,
  downloadDefaultModel,
  downloadEmbedder,
  downloadModel,
  checkModel,
};

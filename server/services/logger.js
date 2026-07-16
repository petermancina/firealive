// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Logging Service
// ═══════════════════════════════════════════════════════════════════════════════

const winston = require('winston');
const path = require('path');
const pkgVersion = require(path.join(__dirname, '..', '..', 'package.json')).version;
const dataRoot = require('../lib/data-root');

// P1-1: logs live under the canonical data root, not beside the code.
// ensureDir creates 0700 and refuses a group- or world-readable directory --
// operational logs are not public.
const logDir = dataRoot.logsDir();
dataRoot.ensureDir(logDir);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'firealive', version: pkgVersion },
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    ),
  }));
}

module.exports = { logger };

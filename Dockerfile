FROM node:24-alpine AS builder
WORKDIR /app
RUN addgroup -g 1001 firealive && adduser -u 1001 -G firealive -s /bin/sh -D firealive
COPY package.json package-lock.json ./
RUN npm ci --production --workspaces=false && npm cache clean --force
COPY packages/shared/ ./node_modules/@firealive/shared/
COPY server/ ./server/
COPY .env.example .env
RUN find server/ -name "*.js" -exec sha256sum {} \; > /app/integrity-manifest.sha256 \
 && find node_modules/@firealive/shared -name "*.js" -exec sha256sum {} \; >> /app/integrity-manifest.sha256
FROM node:24-alpine
WORKDIR /app
# B5b: the built-in CA issues certificates by shelling out to the openssl CLI.
# Alpine ships libcrypto but not the openssl binary, so install it at runtime.
RUN apk add --no-cache openssl
RUN addgroup -g 1001 firealive && adduser -u 1001 -G firealive -s /bin/sh -D firealive
COPY --from=builder /app /app
RUN chmod -R 550 /app/server && mkdir -p /app/data /app/backups /app/logs && chown -R firealive:firealive /app/data /app/backups /app/logs
ENV NODE_ENV=production FIREALIVE_DB_PATH=/app/data/firealive.db FIREALIVE_LOG_PATH=/app/logs FIREALIVE_BACKUP_PATH=/app/backups
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget --no-verbose --tries=1 --spider http://localhost:3001/api/health || exit 1
EXPOSE 3001
USER firealive
CMD ["sh", "-c", "sha256sum -c /app/integrity-manifest.sha256 2>/dev/null; node server/index.js"]

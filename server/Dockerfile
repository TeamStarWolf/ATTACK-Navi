# Credentials proxy image. Node 24 (Active LTS until 2028-04-30); Node 20 reached
# end-of-life on 2026-04-30 and must not run a service that holds live tokens.
FROM node:24-alpine
WORKDIR /app
# Express hides stack traces and enables its production code paths only when
# NODE_ENV is "production"; the proxy's own JSON error handler relies on it too.
ENV NODE_ENV=production
COPY package*.json ./
# Reproducible install from the lockfile, runtime dependencies only.
RUN npm ci --omit=dev
COPY src/ src/
# The container must listen on its own interface for the published port to work;
# on a non-loopback bind the proxy fails closed until PROXY_AUTH_TOKEN is set.
ENV HOST=0.0.0.0
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
# Drop root: the image's unprivileged "node" user (uid 1000) only needs to read /app.
USER node
CMD ["node", "src/index.js"]

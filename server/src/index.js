// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config({ quiet: true });

const app = express();
const port = Number(process.env.PORT) || 8787;

// Parse allowed origins from env
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : ['http://localhost:4200']; // Safe default — not open to all origins

app.use(cors({
  origin(origin, callback) {
    // CORS is a browser mechanism and cannot authenticate non-browser callers;
    // caller authentication is enforced by requireProxyToken below, not by CORS.
    // A configured-but-empty allowlist FAILS CLOSED (deny) rather than allow-all.
    if (!origin || (allowedOrigins.length > 0 && allowedOrigins.includes(origin))) {
      callback(null, true);
    } else {
      // Carry an HTTP status so the error handler below answers 403 JSON instead of
      // Express's default 500 (which outside NODE_ENV=production includes the stack).
      const denied = new Error('Origin not allowed by proxy CORS policy.');
      denied.status = 403;
      callback(denied);
    }
  },
}));
app.use(express.json({ limit: '5mb' }));

// ── Caller authentication ─────────────────────────────────────────────────────
// The proxy forwards the operator's OpenCTI/MISP credentials upstream, so it must
// not rely on CORS (which cannot restrain non-browser clients) for authorization.
// When PROXY_AUTH_TOKEN is configured, every /api/* route except /api/health
// requires it (Authorization: Bearer <token> or X-Proxy-Key: <token>), checked
// BEFORE any upstream fetch. When it is unset the proxy logs a warning and relies
// on network isolation only (docker-compose binds it to 127.0.0.1) — set the token
// whenever the proxy is reachable beyond localhost.
const proxyAuthToken = (process.env.PROXY_AUTH_TOKEN || '').trim();
if (!proxyAuthToken) {
  console.warn(
    '[attack-nav proxy] PROXY_AUTH_TOKEN is not set — caller authentication is disabled. ' +
    'Rely on localhost-only binding, or set PROXY_AUTH_TOKEN before exposing the proxy.'
  );
}

function requireProxyToken(req, res, next) {
  if (!proxyAuthToken) return next(); // enforce only when configured
  const header = req.headers['authorization'];
  const bearer = typeof header === 'string' && header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : '';
  const provided = bearer || (typeof req.headers['x-proxy-key'] === 'string' ? req.headers['x-proxy-key'].trim() : '');
  if (provided && provided === proxyAuthToken) return next();
  return res.status(401).json({ error: 'Proxy authentication required.' });
}

// ── Validation helpers ──────────────────────────────────────────────────────

/** Validate that a URL string points to the configured upstream host only. */
function validateUpstreamUrl(configuredUrl, requestedPath) {
  let base;
  try {
    base = new URL(configuredUrl);
  } catch {
    return null;
  }
  // Strip trailing slash from base, strip leading slash from path
  const safePath = String(requestedPath || '').replace(/^\/+/, '');
  // Block path traversal
  if (safePath.includes('..') || safePath.includes('//')) {
    return null;
  }
  // Only allow alphanumeric, hyphens, underscores, slashes, dots, and query-safe chars
  if (!/^[\w\-./]*$/.test(safePath)) {
    return null;
  }
  const full = new URL(safePath, base.origin + base.pathname.replace(/\/?$/, '/'));
  // Ensure the resolved URL stays on the same origin
  if (full.origin !== base.origin) {
    return null;
  }
  return full.toString();
}

// ── Health (unauthenticated) ──────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'attack-nav-proxy' });
});

// All remaining /api/* routes require the proxy token (when configured).
app.use('/api', requireProxyToken);

// ── OpenCTI Proxy ────────────────────────────────────────────────────────────

app.post('/api/opencti/graphql', async (req, res) => {
  const url = process.env.OPENCTI_URL;
  const token = process.env.OPENCTI_TOKEN;
  if (!url || !token) {
    return res.status(500).json({ error: 'OpenCTI proxy is not configured.' });
  }

  const targetUrl = validateUpstreamUrl(url, 'graphql');
  if (!targetUrl) {
    return res.status(400).json({ error: 'Invalid upstream URL configuration.' });
  }

  // Sanitize GraphQL query — only allow string query and object variables
  const query = typeof req.body?.query === 'string' ? req.body.query : '';
  const variables = typeof req.body?.variables === 'object' && req.body.variables !== null
    ? req.body.variables
    : {};

  try {
    const upstream = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ query, variables }),
    });

    const contentType = upstream.headers.get('content-type') || 'application/json';
    const text = await upstream.text();
    res.status(upstream.status).type(contentType).send(text);
  } catch (error) {
    res.status(502).json({
      error: error instanceof Error ? error.message : 'OpenCTI proxy request failed.',
    });
  }
});

// ── MISP Proxy (READ-ONLY) ─────────────────────────────────────────────────────
// Deliberately excludes write endpoints (e.g. events/add): the workbench only reads
// threat intel, and forwarding writes with the operator's key is unnecessary risk.

const MISP_ALLOWED_ENDPOINTS = [
  'servers/getVersion',
  'attributes/restSearch',
  'events/restSearch',
  'events/view',
];

const mispProxy = async (req, res) => {
  const url = process.env.MISP_URL;
  const apiKey = process.env.MISP_API_KEY;
  if (!url || !apiKey) {
    return res.status(500).json({ error: 'MISP proxy is not configured.' });
  }

  const endpoint = String(req.params[0] || '').replace(/^\/+/, '');

  // Allowlist check — only permit known, read-only MISP API endpoints
  const isAllowed = MISP_ALLOWED_ENDPOINTS.some((allowed) =>
    endpoint === allowed || endpoint.startsWith(allowed + '/')
  );
  if (!isAllowed) {
    return res.status(403).json({ error: `Endpoint not allowed: ${endpoint}` });
  }

  const targetUrl = validateUpstreamUrl(url, endpoint);
  if (!targetUrl) {
    return res.status(400).json({ error: 'Invalid upstream URL configuration.' });
  }

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers: {
        'Authorization': apiKey,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: req.method === 'GET' ? undefined : JSON.stringify(req.body ?? {}),
    });

    const contentType = upstream.headers.get('content-type') || 'application/json';
    const text = await upstream.text();
    res.status(upstream.status).type(contentType).send(text);
  } catch (error) {
    res.status(502).json({
      error: error instanceof Error ? error.message : 'MISP proxy request failed.',
    });
  }
};

app.get('/api/misp/*', mispProxy);
app.post('/api/misp/*', mispProxy);

// ── Error handler ────────────────────────────────────────────────────────────
// Every error (CORS denial, body-parser 400/413, anything thrown) is answered as
// generic JSON: the status the error carries (or 500) and, for client errors
// only, its message. Never the stack, never file paths or dependency versions —
// Express's default handler prints those whenever NODE_ENV is not "production".
app.use((error, _req, res, _next) => {
  const status = Number(error?.status ?? error?.statusCode) || 500;
  if (status >= 500) console.error('[attack-nav proxy]', error);
  const message = status < 500 && error instanceof Error && error.message
    ? error.message
    : 'Proxy request failed.';
  res.status(status).json({ error: message });
});

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`attack-nav proxy listening on http://localhost:${port}`);
});

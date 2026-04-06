// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 8787;

// Parse allowed origins from env
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : [];

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by proxy CORS policy.'));
    }
  },
}));
app.use(express.json({ limit: '5mb' }));

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

// ── Health ───────────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'attack-nav-proxy' });
});

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

// ── MISP Proxy ───────────────────────────────────────────────────────────────

const MISP_ALLOWED_ENDPOINTS = [
  'servers/getVersion',
  'attributes/restSearch',
  'events/restSearch',
  'events/add',
  'events/view',
];

const mispProxy = async (req, res) => {
  const url = process.env.MISP_URL;
  const apiKey = process.env.MISP_API_KEY;
  if (!url || !apiKey) {
    return res.status(500).json({ error: 'MISP proxy is not configured.' });
  }

  const endpoint = String(req.params[0] || '').replace(/^\/+/, '');

  // Allowlist check — only permit known MISP API endpoints
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

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`attack-nav proxy listening on http://localhost:${port}`);
});

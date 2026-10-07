// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { timingSafeEqual } from 'node:crypto';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import { Kind, parse as parseGraphql } from 'graphql';

dotenv.config({ quiet: true });

const app = express();
const port = Number(process.env.PORT) || 8787;

// ── Bind address ─────────────────────────────────────────────────────────────
// Loopback by default: the proxy forwards the operator's OpenCTI/MISP credentials,
// so it must not be reachable from the network unless the operator opts in with
// HOST (e.g. 0.0.0.0 inside a container) AND configures PROXY_AUTH_TOKEN.
const host = (process.env.HOST || '127.0.0.1').trim();

function isLoopbackHost(value) {
  const h = String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || /^127(\.\d{1,3}){3}$/.test(h) || /^::ffff:127(\.\d{1,3}){3}$/.test(h);
}

const loopbackBind = isLoopbackHost(host);

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
      callback(new Error('Origin not allowed by proxy CORS policy.'));
    }
  },
}));

// Request bodies: the largest legitimate body is the SPA's Export-to-OpenCTI STIX
// bundle (a few hundred KB for the whole Enterprise matrix). 1 MB covers that with
// headroom; raise MAX_BODY_SIZE (e.g. "5mb") only if your bundles are larger.
app.use(express.json({ limit: process.env.MAX_BODY_SIZE || '1mb' }));

// ── Caller authentication ─────────────────────────────────────────────────────
// The proxy forwards the operator's OpenCTI/MISP credentials upstream, so it must
// not rely on CORS (which cannot restrain non-browser clients) for authorization.
// When PROXY_AUTH_TOKEN is configured, every /api/* route except /api/health
// requires it (Authorization: Bearer <token> or X-Proxy-Key: <token>), checked
// BEFORE any upstream fetch. The SPA sends X-Proxy-Key from the "Proxy access
// token" field in Settings > Integrations.
//
// When the token is unset the proxy only serves callers on the loopback bind. On
// a non-loopback HOST (containers, LAN exposure) it FAILS CLOSED: /api/health
// still answers so orchestrators can probe it, every other route returns 503
// until PROXY_AUTH_TOKEN is set.
const proxyAuthToken = (process.env.PROXY_AUTH_TOKEN || '').trim();
const proxyAuthTokenBuffer = Buffer.from(proxyAuthToken, 'utf8');
const unauthenticatedExposure = !proxyAuthToken && !loopbackBind;
if (unauthenticatedExposure) {
  console.error(
    `[attack-nav proxy] HOST=${host} is not a loopback address and PROXY_AUTH_TOKEN is not set. ` +
    'Refusing every /api/* route except /api/health until PROXY_AUTH_TOKEN is configured.'
  );
} else if (!proxyAuthToken) {
  console.warn(
    '[attack-nav proxy] PROXY_AUTH_TOKEN is not set — caller authentication is disabled. ' +
    `Serving loopback only (${host}); set PROXY_AUTH_TOKEN before exposing the proxy.`
  );
}

function tokenMatches(provided) {
  if (!provided) return false;
  const providedBuffer = Buffer.from(provided, 'utf8');
  // timingSafeEqual needs equal lengths; a length mismatch is simply a mismatch.
  if (providedBuffer.length !== proxyAuthTokenBuffer.length) return false;
  return timingSafeEqual(providedBuffer, proxyAuthTokenBuffer);
}

function requireProxyToken(req, res, next) {
  if (unauthenticatedExposure) {
    return res.status(503).json({
      error: 'Proxy is bound to a non-loopback address without PROXY_AUTH_TOKEN; set the token to enable this route.',
    });
  }
  if (!proxyAuthToken) return next(); // enforce only when configured
  const header = req.headers['authorization'];
  const bearer = typeof header === 'string' && header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : '';
  const provided = bearer || (typeof req.headers['x-proxy-key'] === 'string' ? req.headers['x-proxy-key'].trim() : '');
  if (tokenMatches(provided)) return next();
  return res.status(401).json({ error: 'Proxy authentication required.' });
}

// ── Host allowlist (DNS-rebinding defence) ───────────────────────────────────
// A page on an attacker's domain whose DNS is re-pointed at 127.0.0.1 reaches a
// loopback-bound proxy as a same-origin request, so CORS never applies. Only the
// hostnames the proxy is legitimately addressed by are accepted; everything else
// is answered 421 before any upstream call. Ports are ignored on purpose: the
// hostname is what rebinding controls. Add reverse-proxy / container names with
// ALLOWED_HOSTS (comma-separated), e.g. ALLOWED_HOSTS=proxy for docker-compose.
const configuredHosts = (process.env.ALLOWED_HOSTS || '')
  .split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
const allowedHosts = new Set(['localhost', '127.0.0.1', '::1', ...configuredHosts]);
if (!isLoopbackHost(host) && host !== '0.0.0.0' && host !== '::') allowedHosts.add(host.toLowerCase());

function hostnameOf(hostHeader) {
  const raw = String(hostHeader || '').trim().toLowerCase();
  if (!raw) return '';
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    return end === -1 ? '' : raw.slice(1, end);
  }
  const colon = raw.lastIndexOf(':');
  return colon === -1 ? raw : raw.slice(0, colon);
}

function requireAllowedHost(req, res, next) {
  const name = hostnameOf(req.headers.host);
  if (name && allowedHosts.has(name)) return next();
  return res.status(421).json({ error: 'Host header not allowed by proxy.' });
}

// ── Required client header ──────────────────────────────────────────────────
// Every credentialed route demands a custom header so that a browser can never
// reach it with a "simple" request: cross-origin callers are forced through a
// CORS preflight, which the origin allowlist above then decides. The SPA sends
// X-Requested-With: ATTACK-Navi in proxy mode.
const CLIENT_HEADER = 'x-requested-with';

function requireClientHeader(req, res, next) {
  if (typeof req.headers[CLIENT_HEADER] === 'string' && req.headers[CLIENT_HEADER].trim()) return next();
  return res.status(403).json({ error: 'Missing X-Requested-With header.' });
}

// ── Upstream fetch guards ───────────────────────────────────────────────────
// Every upstream call is bounded in time and in response size so a hung or
// oversized OpenCTI/MISP response cannot pin the proxy indefinitely.
const upstreamTimeoutMs = Math.max(1000, Number(process.env.UPSTREAM_TIMEOUT_MS) || 30000);
const upstreamMaxBytes = Math.max(1024, Number(process.env.UPSTREAM_MAX_BYTES) || 10 * 1024 * 1024);

class UpstreamTooLargeError extends Error {
  constructor() {
    super(`Upstream response exceeded ${upstreamMaxBytes} bytes.`);
    this.name = 'UpstreamTooLargeError';
  }
}

/** Read an upstream body, aborting once it passes the byte cap. */
async function readBounded(upstream, controller) {
  if (!upstream.body) return '';
  const chunks = [];
  let received = 0;
  for await (const chunk of upstream.body) {
    received += chunk.byteLength;
    if (received > upstreamMaxBytes) {
      controller.abort();
      throw new UpstreamTooLargeError();
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Fetch an upstream URL with a timeout and a bounded body; relays status/type/body. */
async function relayUpstream(res, targetUrl, init, failureMessage) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), upstreamTimeoutMs);
  try {
    const upstream = await fetch(targetUrl, { ...init, signal: controller.signal });
    const contentType = upstream.headers.get('content-type') || 'application/json';
    const text = await readBounded(upstream, controller);
    res.status(upstream.status).type(contentType).send(text);
  } catch (error) {
    if (error instanceof UpstreamTooLargeError) {
      res.status(502).json({ error: error.message });
    } else if (controller.signal.aborted || error?.name === 'AbortError' || error?.name === 'TimeoutError') {
      res.status(504).json({ error: `Upstream did not respond within ${upstreamTimeoutMs} ms.` });
    } else {
      res.status(502).json({ error: error instanceof Error ? error.message : failureMessage });
    }
  } finally {
    clearTimeout(timer);
  }
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

// ── OpenCTI operation allowlist ─────────────────────────────────────────────
// The proxy forwards GraphQL under the operator's bearer token, so the document
// is parsed and checked BEFORE it is forwarded, by operation type and root field
// — the GraphQL equivalent of MISP_ALLOWED_ENDPOINTS below. Naming alone is not a
// control (any caller can name a document "IndicatorsByTechnique"), so the root
// selection set is what is allowlisted.
//
//   queries        : only the root fields the SPA reads, plus __typename
//   mutations      : refused unless OPENCTI_ALLOW_IMPORT=true, and then only the
//                    SPA's `mutation ImportStix` selecting
//                    stixObjectOrStixRelationshipImport (Export-to-OpenCTI)
//   subscriptions  : always refused
//
// Extend the read allowlist with OPENCTI_ALLOWED_QUERY_FIELDS (comma-separated)
// when you add queries to the SPA; keep OPENCTI_TOKEN a least-privileged user.
const OPENCTI_DEFAULT_QUERY_FIELDS = ['about', 'indicators', 'threatActors'];
const openCtiQueryFields = new Set([
  '__typename',
  ...OPENCTI_DEFAULT_QUERY_FIELDS,
  ...(process.env.OPENCTI_ALLOWED_QUERY_FIELDS || '').split(',').map((f) => f.trim()).filter(Boolean),
]);
const openCtiAllowImport = String(process.env.OPENCTI_ALLOW_IMPORT || '').trim().toLowerCase() === 'true';
const OPENCTI_IMPORT_OPERATION = 'ImportStix';
const OPENCTI_IMPORT_FIELD = 'stixObjectOrStixRelationshipImport';

/**
 * Decide whether a GraphQL document may be forwarded.
 * Returns { ok: true } or { ok: false, status, error }.
 */
function checkOpenCtiDocument(query) {
  if (typeof query !== 'string' || !query.trim()) {
    return { ok: false, status: 400, error: 'GraphQL query must be a non-empty string.' };
  }
  let document;
  try {
    document = parseGraphql(query, { noLocation: true });
  } catch (error) {
    return { ok: false, status: 400, error: `GraphQL syntax error: ${error instanceof Error ? error.message : 'invalid document'}` };
  }
  const operations = document.definitions.filter((d) => d.kind === Kind.OPERATION_DEFINITION);
  if (operations.length === 0) {
    return { ok: false, status: 400, error: 'GraphQL document contains no operation.' };
  }
  for (const op of operations) {
    const name = op.name?.value ?? '';
    const selections = op.selectionSet?.selections ?? [];
    // Root selections must be plain fields: a fragment spread at the root would
    // hide the real root fields from this check.
    if (selections.some((s) => s.kind !== Kind.FIELD)) {
      return { ok: false, status: 403, error: 'Root-level fragments are not allowed through the proxy.' };
    }
    const fields = selections.map((s) => s.name.value);
    if (op.operation === 'subscription') {
      return { ok: false, status: 403, error: 'GraphQL subscriptions are not allowed through the proxy.' };
    }
    if (op.operation === 'mutation') {
      if (!openCtiAllowImport) {
        return { ok: false, status: 403, error: 'GraphQL mutations are disabled (set OPENCTI_ALLOW_IMPORT=true to allow ImportStix).' };
      }
      if (name !== OPENCTI_IMPORT_OPERATION || fields.length === 0 || fields.some((f) => f !== OPENCTI_IMPORT_FIELD)) {
        return { ok: false, status: 403, error: `Only mutation ${OPENCTI_IMPORT_OPERATION} { ${OPENCTI_IMPORT_FIELD} } is allowed through the proxy.` };
      }
      continue;
    }
    const denied = fields.filter((f) => !openCtiQueryFields.has(f));
    if (fields.length === 0 || denied.length > 0) {
      return { ok: false, status: 403, error: `Query root field not allowed: ${denied.join(', ') || '(none)'}` };
    }
  }
  return { ok: true };
}

// ── Health (unauthenticated) ──────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'attack-nav-proxy' });
});

// All remaining /api/* routes: Host allowlist, proxy token (when configured),
// then the custom-header requirement — all before any upstream fetch.
app.use('/api', requireAllowedHost, requireProxyToken, requireClientHeader);

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

  const verdict = checkOpenCtiDocument(query);
  if (!verdict.ok) {
    return res.status(verdict.status).json({ error: verdict.error });
  }

  await relayUpstream(res, targetUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
  }, 'OpenCTI proxy request failed.');
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

  await relayUpstream(res, targetUrl, {
    method: req.method,
    headers: {
      'Authorization': apiKey,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: req.method === 'GET' ? undefined : JSON.stringify(req.body ?? {}),
  }, 'MISP proxy request failed.');
};

app.get('/api/misp/*', mispProxy);
app.post('/api/misp/*', mispProxy);

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(port, host, () => {
  console.log(`attack-nav proxy listening on http://${host.includes(':') ? `[${host}]` : host}:${port}`);
});

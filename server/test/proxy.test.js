// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import proxyaddr from 'proxy-addr';

// The SPA sends this on every proxy-mode request (see opencti.service.ts /
// misp.service.ts); the proxy refuses credentialed routes without it so that a
// cross-origin browser call can never be a preflight-free "simple" request.
const CLIENT_HEADERS = { 'x-requested-with': 'ATTACK-Navi' };
const JSON_HEADERS = { 'content-type': 'application/json', ...CLIENT_HEADERS };

test('dotenv retains parsing and existing-environment precedence', () => {
  const parsed = dotenv.parse('PLAIN=value\nQUOTED="value # kept"\nMULTILINE="one\\ntwo"\n');
  assert.deepEqual(parsed, { PLAIN: 'value', QUOTED: 'value # kept', MULTILINE: 'one\ntwo' });
  const environment = { PLAIN: 'already-set' };
  dotenv.populate(environment, parsed);
  assert.equal(environment.PLAIN, 'already-set');
  assert.equal(environment.QUOTED, 'value # kept');
});

test('proxy address trust does not widen an IPv4-mapped IPv6 subnet', () => {
  const trust = proxyaddr.compile('::ffff:192.0.2.0/120');
  assert.equal(trust('192.0.2.10'), true);
  assert.equal(trust('::ffff:192.0.2.10'), true);
  assert.equal(trust('198.51.100.10'), false);
  assert.equal(trust('::ffff:198.51.100.10'), false);
});

/**
 * fetch() silently drops a caller-supplied Host header, so Host-allowlist cases
 * go through node:http directly. Resolves { status, body }.
 */
function rawRequest(base, path, { method = 'GET', headers = {}, body } = {}) {
  const url = new URL(path, base);
  return new Promise((resolveRequest, rejectRequest) => {
    const req = request({
      host: url.hostname, port: url.port, path: url.pathname, method,
      headers: { ...(body ? { 'content-length': Buffer.byteLength(body) } : {}), ...headers },
    }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolveRequest({ status: res.statusCode, body: data }));
    });
    req.on('error', rejectRequest);
    if (body) req.write(body);
    req.end();
  });
}

/** Reserve an ephemeral loopback port and release it for the proxy to bind. */
async function reservePort() {
  const reservation = createServer();
  await new Promise(resolveListen => reservation.listen(0, '127.0.0.1', resolveListen));
  const port = reservation.address().port;
  await new Promise(resolveClose => reservation.close(resolveClose));
  return port;
}

/**
 * Launch the unmodified proxy entry point in a scratch directory holding the
 * given .env lines, with `extraEnv` in the process environment, and wait for
 * /api/health. Returns { base, port, output() } and registers cleanup on `t`.
 */
async function startProxy(t, envLines, extraEnv = {}, prefix = 'attack-navi-proxy-test-') {
  const temporaryRoot = resolve(tmpdir());
  const directory = await mkdtemp(join(temporaryRoot, prefix));
  let child;
  let output = '';
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    assert(directory.startsWith(temporaryRoot + sep));
    assert(directory.slice(temporaryRoot.length + 1).startsWith(prefix));
    await rm(directory, { recursive: true, force: true });
  });
  const port = await reservePort();
  await writeFile(join(directory, '.env'), envLines.join('\n'));
  child = spawn(process.execPath, [fileURLToPath(new URL('../src/index.js', import.meta.url))], {
    cwd: directory,
    env: {
      PORT: String(port),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...extraEnv,
    },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(500) });
      ready = response.ok;
      await response.arrayBuffer();
      if (ready) break;
    } catch { /* The process may still be starting. */ }
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  assert(ready, `Proxy did not become ready: ${output}`);
  return { base, port, output: () => output };
}

/** A recording upstream that answers every request with { upstream: true }. */
async function startUpstream(t, handler) {
  const requests = [];
  const upstream = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    requests.push({ path: req.url, method: req.method, authorization: req.headers.authorization, body });
    if (handler && handler(req, res, body) === true) return; // handler took over the response
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ upstream: true }));
  });
  t.after(async () => {
    upstream.closeAllConnections();
    if (upstream.listening) await new Promise(resolveClose => upstream.close(resolveClose));
  });
  await new Promise(resolveListen => upstream.listen(0, '127.0.0.1', resolveListen));
  return { requests, url: `http://127.0.0.1:${upstream.address().port}` };
}

test('proxy handles configured requests after dependency updates', { timeout: 30000 }, async t => {
  const { requests, url: upstreamUrl } = await startUpstream(t);
  const { base, port, output } = await startProxy(t, [
    'PORT=1', // The explicit process environment must win over this fixture.
    'ALLOWED_ORIGINS="http://lab.example.test"',
    `OPENCTI_URL=${upstreamUrl}/opencti/`,
    'OPENCTI_TOKEN=synthetic-opencti-token',
    `MISP_URL=${upstreamUrl}/misp/`,
    'MISP_API_KEY=synthetic-misp-key',
  ]);

  await t.test('loads fixture configuration quietly, preserves process PORT and binds loopback by default', async () => {
    const response = await fetch(`${base}/api/health`, { headers: { Origin: 'http://lab.example.test' } });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, service: 'attack-nav-proxy' });
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://lab.example.test');
    assert.match(output(), new RegExp(`http://127\\.0\\.0\\.1:${port}`));
    assert.doesNotMatch(output(), /injected env|injecting env|synthetic-opencti-token|synthetic-misp-key/);
  });

  await t.test('does not grant CORS to a disallowed origin', async () => {
    const response = await fetch(`${base}/api/health`, { headers: { Origin: 'http://unapproved.example.test' } });
    assert.equal(response.status, 500);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    await response.arrayBuffer();
  });

  await t.test('forwards GraphQL body and authorization only to the configured upstream', async () => {
    const body = { query: 'query { __typename }', variables: { sample: 1 } };
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { upstream: true });
    const request = requests.at(-1);
    assert.equal(request.path, '/opencti/graphql');
    assert.equal(request.authorization, 'Bearer synthetic-opencti-token');
    assert.deepEqual(JSON.parse(request.body), body);
  });

  await t.test('forwards the SPA named read queries (about, indicators, threatActors)', async () => {
    const before = requests.length;
    for (const query of [
      '{ about { version title } }',
      'query IndicatorsByTechnique($attackId: String!) { indicators(filters: { key: "indicates", values: [$attackId] }) { edges { node { id name } } } }',
      'query ThreatActorsByTechnique($attackId: String!) { threatActors(filters: { key: "uses", values: [$attackId] }) { edges { node { id name } } } }',
    ]) {
      const response = await fetch(`${base}/api/opencti/graphql`, {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ query, variables: { attackId: 'T1059' } }),
      });
      assert.equal(response.status, 200, query);
      await response.arrayBuffer();
    }
    assert.equal(requests.length, before + 3);
  });

  await t.test('refuses a credentialed route without X-Requested-With before any upstream call', async () => {
    const before = requests.length;
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: '{ about { version } }' }),
    });
    assert.equal(response.status, 403);
    await response.arrayBuffer();
    const simple = await fetch(`${base}/api/misp/servers/getVersion`);
    assert.equal(simple.status, 403);
    await simple.arrayBuffer();
    assert.equal(requests.length, before);
  });

  await t.test('refuses a Host header outside the allowlist (DNS rebinding) before any upstream call', async () => {
    const before = requests.length;
    const response = await rawRequest(base, '/api/misp/servers/getVersion', { headers: { ...CLIENT_HEADERS, host: 'evil.example.test' } });
    assert.equal(response.status, 421);
    assert.match(JSON.parse(response.body).error, /Host header/);
    const health = await rawRequest(base, '/api/health', { headers: { host: 'evil.example.test' } });
    assert.equal(health.status, 200, 'health stays probe-able regardless of Host');
    assert.equal(requests.length, before);
    const loopbackForms = ['localhost:1', '127.0.0.1', '[::1]:8787'];
    for (const host of loopbackForms) {
      const ok = await rawRequest(base, '/api/misp/servers/getVersion', { headers: { ...CLIENT_HEADERS, host } });
      assert.equal(ok.status, 200, host);
    }
    assert.equal(requests.length, before + loopbackForms.length);
  });

  await t.test('rejects mutations, subscriptions, root fragments and unlisted root fields before forwarding', async () => {
    const before = requests.length;
    const refused = [
      ['mutation { __typename }', 403],
      ['mutation ImportStix($stixData: String!) { stixObjectOrStixRelationshipImport(stixData: $stixData) { id } }', 403],
      ['mutation { userEdit(id: "x") { id } }', 403],
      ['subscription { __typename }', 403],
      ['{ users { edges { node { id } } } }', 403],
      ['{ __schema { types { name } } }', 403],
      ['query { ...Hidden } fragment Hidden on Query { users { edges { node { id } } } }', 403],
      ['{ about { version } } mutation { userEdit(id: "x") { id } }', 403],
      ['{ about { version ', 400],
      ['fragment Only on Query { about { version } }', 400],
    ];
    for (const [query, status] of refused) {
      const response = await fetch(`${base}/api/opencti/graphql`, {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ query }),
      });
      assert.equal(response.status, status, query);
      const payload = await response.json();
      assert.equal(typeof payload.error, 'string', query);
    }
    assert.equal(requests.length, before);
  });

  await t.test('retains Express 4 wildcard MISP routing and rejects unlisted endpoints', async () => {
    const response = await fetch(`${base}/api/misp/servers/getVersion`, { headers: CLIENT_HEADERS });
    assert.equal(response.status, 200);
    await response.arrayBuffer();
    assert.equal(requests.at(-1).path, '/misp/servers/getVersion');
    assert.equal(requests.at(-1).authorization, 'synthetic-misp-key');
    const before = requests.length;
    const denied = await fetch(`${base}/api/misp/admin/delete`, { headers: CLIENT_HEADERS });
    assert.equal(denied.status, 403);
    await denied.arrayBuffer();
    assert.equal(requests.length, before);
  });

  await t.test('rejects malformed JSON before forwarding', async () => {
    const before = requests.length;
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: JSON_HEADERS, body: '{',
    });
    assert.equal(response.status, 400);
    await response.arrayBuffer();
    assert.equal(requests.length, before);
  });

  await t.test('rejects a body over the configured limit (default 1mb) before forwarding', async () => {
    const before = requests.length;
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: JSON_HEADERS,
      body: JSON.stringify({ query: '{ about { version } }', variables: { pad: 'x'.repeat(1024 * 1024 + 1) } }),
    });
    assert.equal(response.status, 413);
    await response.arrayBuffer();
    assert.equal(requests.length, before);
  });
});

test('proxy token gate: /api/* requires PROXY_AUTH_TOKEN when configured; health stays exempt', { timeout: 30000 }, async t => {
  const { base } = await startProxy(t, [
    'ALLOWED_ORIGINS="http://localhost:4200"',
    'PROXY_AUTH_TOKEN=synthetic-proxy-secret',
  ], {}, 'attack-navi-proxy-auth-');

  await t.test('health is reachable without the proxy token', async () => {
    const response = await fetch(`${base}/api/health`);
    assert.equal(response.status, 200);
    await response.arrayBuffer();
  });

  await t.test('protected route without the token is rejected 401 before any upstream call', async () => {
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ query: '{ __typename }' }),
    });
    assert.equal(response.status, 401);
    await response.arrayBuffer();
  });

  await t.test('wrong token and same-length wrong token are rejected 401', async () => {
    for (const key of ['nope', 'synthetic-proxy-secreT']) {
      const response = await fetch(`${base}/api/opencti/graphql`, {
        method: 'POST', headers: { ...JSON_HEADERS, 'x-proxy-key': key }, body: JSON.stringify({ query: '{ __typename }' }),
      });
      assert.equal(response.status, 401, key);
      await response.arrayBuffer();
    }
  });

  await t.test('correct Bearer token passes the gate (then 500: upstream not configured)', async () => {
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST',
      headers: { ...JSON_HEADERS, authorization: 'Bearer synthetic-proxy-secret' },
      body: JSON.stringify({ query: '{ __typename }' }),
    });
    assert.equal(response.status, 500);
    await response.arrayBuffer();
  });

  await t.test('correct X-Proxy-Key (the header the SPA sends) passes the gate on both routes', async () => {
    const graphql = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST',
      headers: { ...JSON_HEADERS, 'x-proxy-key': 'synthetic-proxy-secret' },
      body: JSON.stringify({ query: '{ __typename }' }),
    });
    assert.equal(graphql.status, 500); // past the gate: upstream not configured in this fixture
    await graphql.arrayBuffer();
    const misp = await fetch(`${base}/api/misp/servers/getVersion`, {
      headers: { ...CLIENT_HEADERS, 'x-proxy-key': 'synthetic-proxy-secret' },
    });
    assert.equal(misp.status, 500);
    await misp.arrayBuffer();
  });
});

test('OPENCTI_ALLOW_IMPORT=true admits only the SPA ImportStix mutation; ALLOWED_HOSTS admits a reverse-proxy name', { timeout: 30000 }, async t => {
  const { requests, url: upstreamUrl } = await startUpstream(t);
  const { base } = await startProxy(t, [
    `OPENCTI_URL=${upstreamUrl}/opencti/`,
    'OPENCTI_TOKEN=synthetic-opencti-token',
    'OPENCTI_ALLOW_IMPORT=true',
    'ALLOWED_HOSTS=proxy',
  ], {}, 'attack-navi-proxy-import-');

  await t.test('forwards mutation ImportStix { stixObjectOrStixRelationshipImport }', async () => {
    const body = {
      query: 'mutation ImportStix($stixData: String!) { stixObjectOrStixRelationshipImport(stixData: $stixData) { id } }',
      variables: { stixData: '{"type":"bundle"}' },
    };
    const response = await fetch(`${base}/api/opencti/graphql`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });
    assert.equal(response.status, 200);
    await response.arrayBuffer();
    assert.deepEqual(JSON.parse(requests.at(-1).body), body);
  });

  await t.test('still refuses any other mutation shape, even when named ImportStix', async () => {
    const before = requests.length;
    for (const query of [
      'mutation ImportStix { userEdit(id: "x") { id } }',
      'mutation ImportStix($stixData: String!) { stixObjectOrStixRelationshipImport(stixData: $stixData) { id } userEdit(id: "x") { id } }',
      'mutation Renamed($stixData: String!) { stixObjectOrStixRelationshipImport(stixData: $stixData) { id } }',
      'mutation { stixObjectOrStixRelationshipImport(stixData: "x") { id } }',
      'subscription ImportStix { stixObjectOrStixRelationshipImport(stixData: "x") { id } }',
    ]) {
      const response = await fetch(`${base}/api/opencti/graphql`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ query }) });
      assert.equal(response.status, 403, query);
      await response.arrayBuffer();
    }
    assert.equal(requests.length, before);
  });

  await t.test('accepts the Host name listed in ALLOWED_HOSTS (any port) and still refuses others', async () => {
    const body = JSON.stringify({ query: '{ about { version } }' });
    const ok = await rawRequest(base, '/api/opencti/graphql', { method: 'POST', headers: { ...JSON_HEADERS, host: 'proxy:8787' }, body });
    assert.equal(ok.status, 200);
    const denied = await rawRequest(base, '/api/opencti/graphql', { method: 'POST', headers: { ...JSON_HEADERS, host: 'proxy.evil.example' }, body });
    assert.equal(denied.status, 421);
  });
});

test('non-loopback HOST without PROXY_AUTH_TOKEN fails closed: health only', { timeout: 30000 }, async t => {
  const { url: upstreamUrl, requests } = await startUpstream(t);
  const { base, output } = await startProxy(t, [
    `MISP_URL=${upstreamUrl}/misp/`,
    'MISP_API_KEY=synthetic-misp-key',
  ], { HOST: '0.0.0.0' }, 'attack-navi-proxy-exposed-');

  const health = await fetch(`${base}/api/health`);
  assert.equal(health.status, 200);
  await health.arrayBuffer();
  const response = await fetch(`${base}/api/misp/servers/getVersion`, { headers: CLIENT_HEADERS });
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /PROXY_AUTH_TOKEN/);
  assert.equal(requests.length, 0);
  assert.match(output(), /not a loopback address and PROXY_AUTH_TOKEN is not set/);
});

test('upstream guards: timeout -> 504 and oversized body -> 502', { timeout: 30000 }, async t => {
  const { url: upstreamUrl } = await startUpstream(t, (req, res) => {
    if (req.url.endsWith('/servers/getVersion')) return true; // never answer: hang the request
    if (req.url.endsWith('/events/view/1')) {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ pad: 'x'.repeat(4096) }));
      return true;
    }
    return false;
  });
  const { base } = await startProxy(t, [
    `MISP_URL=${upstreamUrl}/misp/`,
    'MISP_API_KEY=synthetic-misp-key',
    'UPSTREAM_TIMEOUT_MS=1000',
    'UPSTREAM_MAX_BYTES=2048',
  ], {}, 'attack-navi-proxy-guards-');

  const started = Date.now();
  const slow = await fetch(`${base}/api/misp/servers/getVersion`, { headers: CLIENT_HEADERS });
  assert.equal(slow.status, 504);
  assert.match((await slow.json()).error, /1000 ms/);
  assert(Date.now() - started < 10000, 'timeout must fire well before the test deadline');

  const big = await fetch(`${base}/api/misp/events/view/1`, { headers: CLIENT_HEADERS });
  assert.equal(big.status, 502);
  assert.match((await big.json()).error, /exceeded 2048 bytes/);
});

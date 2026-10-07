// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

test('dotenv retains parsing and existing-environment precedence', () => {
  const parsed = dotenv.parse('PLAIN=value\nQUOTED="value # kept"\nMULTILINE="one\\ntwo"\n');
  assert.deepEqual(parsed, { PLAIN: 'value', QUOTED: 'value # kept', MULTILINE: 'one\ntwo' });
  const environment = { PLAIN: 'already-set' };
  dotenv.populate(environment, parsed);
  assert.equal(environment.PLAIN, 'already-set');
  assert.equal(environment.QUOTED, 'value # kept');
});

test('proxy handles configured requests after dependency updates', { timeout: 30000 }, async t => {
  const temporaryRoot = resolve(tmpdir());
  const directory = await mkdtemp(join(temporaryRoot, 'attack-navi-proxy-test-'));
  const requests = [];
  let child;
  let output = '';
  const upstream = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    requests.push({ path: req.url, method: req.method, authorization: req.headers.authorization, body });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ upstream: true }));
  });
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    upstream.closeAllConnections();
    if (upstream.listening) await new Promise(resolveClose => upstream.close(resolveClose));
    assert(directory.startsWith(temporaryRoot + sep));
    assert(directory.slice(temporaryRoot.length + 1).startsWith('attack-navi-proxy-test-'));
    await rm(directory, { recursive: true, force: true });
  });
  await new Promise(resolveListen => upstream.listen(0, '127.0.0.1', resolveListen));
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;

  // Reserve an ephemeral port before launching the unmodified server entry point.
  const reservation = createServer();
  await new Promise(resolveListen => reservation.listen(0, '127.0.0.1', resolveListen));
  const port = reservation.address().port;
  await new Promise(resolveClose => reservation.close(resolveClose));
  await writeFile(join(directory, '.env'), [
    'PORT=1', // The explicit process environment must win over this fixture.
    'ALLOWED_ORIGINS="http://lab.example.test"',
    `OPENCTI_URL=${upstreamUrl}/opencti/`,
    'OPENCTI_TOKEN=synthetic-opencti-token',
    `MISP_URL=${upstreamUrl}/misp/`,
    'MISP_API_KEY=synthetic-misp-key',
  ].join('\n'));
  child = spawn(process.execPath, [fileURLToPath(new URL('../src/index.js', import.meta.url))], {
    cwd: directory,
    env: { PORT: String(port), ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) },
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
  assert(ready, 'Proxy did not become ready');

  await t.test('loads fixture configuration quietly and preserves process PORT', async () => {
    const response = await fetch(`${base}/api/health`, { headers: { Origin: 'http://lab.example.test' } });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, service: 'attack-nav-proxy' });
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://lab.example.test');
    assert.match(output, new RegExp(`localhost:${port}`));
    assert.doesNotMatch(output, /injected env|injecting env|synthetic-opencti-token|synthetic-misp-key/);
  });

  await t.test('does not grant CORS to a disallowed origin: 403 JSON, no stack trace', async () => {
    const response = await fetch(`${base}/api/health`, { headers: { Origin: 'http://unapproved.example.test' } });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    assert.match(response.headers.get('content-type'), /application\/json/);
    const text = await response.text();
    assert.deepEqual(JSON.parse(text), { error: 'Origin not allowed by proxy CORS policy.' });
    assert.doesNotMatch(text, /\n\s+at |node_modules|index\.js/);
  });

  await t.test('forwards GraphQL body and authorization only to the configured upstream', async () => {
    const body = { query: 'query { __typename }', variables: { sample: 1 } };
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { upstream: true });
    const request = requests.at(-1);
    assert.equal(request.path, '/opencti/graphql');
    assert.equal(request.authorization, 'Bearer synthetic-opencti-token');
    assert.deepEqual(JSON.parse(request.body), body);
  });

  await t.test('retains Express 4 wildcard MISP routing and rejects unlisted endpoints', async () => {
    const response = await fetch(`${base}/api/misp/servers/getVersion`);
    assert.equal(response.status, 200);
    await response.arrayBuffer();
    assert.equal(requests.at(-1).path, '/misp/servers/getVersion');
    assert.equal(requests.at(-1).authorization, 'synthetic-misp-key');
    const before = requests.length;
    const denied = await fetch(`${base}/api/misp/admin/delete`);
    assert.equal(denied.status, 403);
    await denied.arrayBuffer();
    assert.equal(requests.length, before);
  });

  await t.test('rejects malformed JSON before forwarding, as JSON without a stack trace', async () => {
    const before = requests.length;
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{',
    });
    assert.equal(response.status, 400);
    assert.match(response.headers.get('content-type'), /application\/json/);
    const text = await response.text();
    assert.equal(typeof JSON.parse(text).error, 'string');
    assert.doesNotMatch(text, /\n\s+at |node_modules|<html|<pre>/);
    assert.equal(requests.length, before);
  });
});

test('proxy token gate: /api/* requires PROXY_AUTH_TOKEN when configured; health stays exempt', { timeout: 30000 }, async t => {
  const directory = await mkdtemp(join(resolve(tmpdir()), 'attack-navi-proxy-auth-'));
  let child;
  let output = '';
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    await rm(directory, { recursive: true, force: true });
  });

  const reservation = createServer();
  await new Promise(resolveListen => reservation.listen(0, '127.0.0.1', resolveListen));
  const port = reservation.address().port;
  await new Promise(resolveClose => reservation.close(resolveClose));
  await writeFile(join(directory, '.env'), [
    'ALLOWED_ORIGINS="http://localhost:4200"',
    'PROXY_AUTH_TOKEN=synthetic-proxy-secret',
  ].join('\n'));
  child = spawn(process.execPath, [fileURLToPath(new URL('../src/index.js', import.meta.url))], {
    cwd: directory,
    env: { PORT: String(port), ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) },
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
    } catch { /* still starting */ }
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  assert(ready, 'Proxy did not become ready');

  await t.test('health is reachable without the proxy token', async () => {
    const response = await fetch(`${base}/api/health`);
    assert.equal(response.status, 200);
    await response.arrayBuffer();
  });

  await t.test('protected route without the token is rejected 401 before any upstream call', async () => {
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: '{ __typename }' }),
    });
    assert.equal(response.status, 401);
    await response.arrayBuffer();
  });

  await t.test('correct token passes the gate (then 500: upstream not configured)', async () => {
    const response = await fetch(`${base}/api/opencti/graphql`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer synthetic-proxy-secret' },
      body: JSON.stringify({ query: '{ __typename }' }),
    });
    assert.equal(response.status, 500);
    await response.arrayBuffer();
  });
});

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Lab measurement of the production build (plan epic E0.4).
//
// Builds the production app (or reuses dist/ with --skip-build), serves it on
// 127.0.0.1, and drives the installed Google Chrome through Playwright in two
// profiles, each in its own throwaway user-data directory:
//
//   cold  fresh profile, service workers blocked, HTTP cache disabled (CDP).
//         This is a true first visit.
//   warm  fresh profile, service worker allowed; a priming load (onboarding
//         dismissed, worker installed, IndexedDB filled), then a second load
//         in a new tab is measured. This is the walkthrough's "warm revisit".
//
// Per load it records FCP, DOMContentLoaded, time to the first matrix cell,
// requests by host, decoded bytes, JS heap, and api.github.com calls. On the
// cold page it then records the /matrix tab-stop count and axe counts, and
// attributes api.github.com calls to each of the heatmap lenses (switched
// through the real View menu) and to each routed tab, in a fixed order.
// Bundle sizes come from the build's esbuild stats (browser-stats.json).
//
// Usage:
//   node scripts/measure.mjs                    build, measure, print summary
//   node scripts/measure.mjs --skip-build       reuse dist/ (must be a production build with --stats-json)
//   node scripts/measure.mjs --md docs/MEASUREMENTS.md --out results.json
//
// Options: --runs N (repeat cold and warm boots, report the median; default 1)
//          --window S (boot measurement cap in seconds after navigation; default 120)
//          --no-lenses, --no-routes (skip the attribution passes; --no-routes also skips the sidebar)
//          --chrome <path> (Chrome executable; default: Playwright channel 'chrome')
//          --url <base> (measure a deployed copy instead of the local build, e.g. the
//                        GitHub Pages site; bundle sizes still come from the local dist)
//          --headed
//
// The app fetches live third-party data, so the run needs network access and
// spends unauthenticated api.github.com quota (60 per hour per IP). Requests
// are counted whether or not GitHub answers 200; status codes are recorded.
// Nothing is sent anywhere except the requests the app itself makes.

import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const DIST = join(ROOT, 'dist', 'mitre-mitigation-navigator');
const BROWSER_DIR = join(DIST, 'browser');
const STATS = join(DIST, 'browser-stats.json');
const VIEWPORT = { width: 1280, height: 720 };
const QUIET_MS = 5000;

// ── arguments ────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
};
const known = new Set(['--skip-build', '--no-lenses', '--no-routes', '--headed', '--runs', '--window', '--md', '--out', '--chrome', '--url']);
for (const [i, a] of argv.entries()) {
  if (a.startsWith('--') && !known.has(a)) throw new Error(`Unknown option ${a}`);
  if (!a.startsWith('--') && !['--runs', '--window', '--md', '--out', '--chrome', '--url'].includes(argv[i - 1])) {
    throw new Error(`Unexpected argument ${a}`);
  }
}
const RUNS = Number(opt('--runs', '1'));
const WINDOW_MS = Number(opt('--window', '120')) * 1000;
if (!Number.isInteger(RUNS) || RUNS < 1) throw new Error('--runs must be a positive integer');
if (!(WINDOW_MS >= 10000)) throw new Error('--window must be at least 10 seconds');
const OUT = opt('--out', join(tmpdir(), `navi-measure-${Date.now()}.json`));
const MD = opt('--md', null);
const CHROME = opt('--chrome', process.env['CHROME_PATH'] ?? null);
const REMOTE = opt('--url', null)?.replace(/#.*$/, '').replace(/\/+$/, '') ?? null;

const log = (...a) => console.log(`[measure ${new Date().toISOString().slice(11, 19)}]`, ...a);
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const median = (xs) => {
  const v = xs.filter((x) => typeof x === 'number' && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = Math.floor(v.length / 2);
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
};

// ── 1. build ─────────────────────────────────────────────────────────────────
function build() {
  log('building production app: ng build --stats-json');
  const r = spawnSync('npx', ['ng', 'build', '--stats-json'], { cwd: ROOT, stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) throw new Error(`ng build failed with exit code ${r.status}`);
}
if (!flag('--skip-build') && !REMOTE) build();
for (const f of [join(BROWSER_DIR, 'index.html'), join(BROWSER_DIR, 'ngsw.json'), STATS]) {
  if (!existsSync(f)) throw new Error(`${f} is missing: run without --skip-build (needs a production build with --stats-json)`);
}

// ── 2. bundle sizes from esbuild stats ───────────────────────────────────────
function bundleStats() {
  const stats = JSON.parse(readFileSync(STATS, 'utf8'));
  const outputs = stats.outputs;
  const name = (p) => p.split('/').pop();
  const entries = Object.keys(outputs).filter((k) => outputs[k].entryPoint);
  const initial = new Set();
  const visit = (k) => {
    if (initial.has(k) || !outputs[k]) return;
    initial.add(k);
    for (const imp of outputs[k].imports ?? []) if (imp.kind === 'import-statement') visit(imp.path);
  };
  for (const e of entries) if (/main\.ts$|polyfills|styles/.test(outputs[e].entryPoint)) visit(e);
  const gz = (k) => {
    const f = join(BROWSER_DIR, name(k));
    return existsSync(f) ? gzipSync(readFileSync(f)).length : null;
  };
  const sum = (ks, fn) => ks.reduce((a, k) => a + (fn(k) ?? 0), 0);
  const js = Object.keys(outputs).filter((k) => k.endsWith('.js'));
  const initialList = [...initial];
  const main = js.find((k) => /(^|\/)main-[^/]+\.js$/.test(k));
  let assetsBytes = 0;
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else assetsBytes += statSync(p).size;
    }
  };
  if (existsSync(join(BROWSER_DIR, 'assets'))) walk(join(BROWSER_DIR, 'assets'));
  return {
    mainFile: main ? name(main) : null,
    mainBytes: main ? outputs[main].bytes : null,
    mainGzipBytes: main ? gz(main) : null,
    initialFiles: initialList.map(name),
    initialBytes: sum(initialList, (k) => outputs[k].bytes),
    initialGzipBytes: sum(initialList, gz),
    jsFiles: js.length,
    lazyJsFiles: js.filter((k) => !initial.has(k)).length,
    totalJsBytes: sum(js, (k) => outputs[k].bytes),
    assetsBytes,
  };
}

// ── 3. static server ─────────────────────────────────────────────────────────
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2', '.txt': 'text/plain',
  '.yaml': 'text/yaml', '.yml': 'text/yaml', '.csv': 'text/csv', '.xml': 'application/xml', '.gz': 'application/gzip',
};
const gzCache = new Map();
function startServer() {
  const server = createServer((req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let file = normalize(join(BROWSER_DIR, urlPath === '/' ? 'index.html' : urlPath));
    if (!file.startsWith(BROWSER_DIR + sep) && file !== BROWSER_DIR) { res.writeHead(403).end(); return; }
    if (!existsSync(file) || statSync(file).isDirectory()) { res.writeHead(404).end(); return; }
    const type = TYPES[extname(file).toLowerCase()] ?? 'application/octet-stream';
    // GitHub Pages serves gzip with max-age=600; mirror that so transfer sizes are comparable.
    const headers = { 'Content-Type': type, 'Cache-Control': 'max-age=600' };
    let body = readFileSync(file);
    if (/gzip/.test(req.headers['accept-encoding'] ?? '') && /text|json|javascript|xml|yaml|csv|svg/.test(type)) {
      if (!gzCache.has(file)) gzCache.set(file, gzipSync(body));
      body = gzCache.get(file);
      headers['Content-Encoding'] = 'gzip';
    }
    headers['Content-Length'] = body.length;
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : body);
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

// ── 4. browser helpers ───────────────────────────────────────────────────────
// Records when the first matrix cell enters the DOM and when the next frame
// after that is painted, relative to navigation start.
const INIT_SCRIPT = () => {
  const m = (window.__naviMeasure = { firstCellDom: null, firstCellFrame: null, longTasks: 0, maxLongTask: 0, lastLongTaskEnd: 0 });
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) {
        m.longTasks += 1;
        m.maxLongTask = Math.max(m.maxLongTask, e.duration);
        m.lastLongTaskEnd = Math.max(m.lastLongTaskEnd, e.startTime + e.duration);
      }
    }).observe({ type: 'longtask', buffered: true });
  } catch { /* longtask timing unsupported */ }
  const check = () => {
    if (m.firstCellDom !== null) return true;
    if (document.querySelector('app-technique-cell .cell')) {
      m.firstCellDom = performance.now();
      requestAnimationFrame(() => { m.firstCellFrame = performance.now(); });
      return true;
    }
    return false;
  };
  const obs = new MutationObserver(() => { if (check()) obs.disconnect(); });
  obs.observe(document, { childList: true, subtree: true });
};

async function launch(profile, serviceWorkers) {
  const dir = mkdtempSync(join(tmpdir(), `navi-measure-${profile}-`));
  const opts = { headless: !flag('--headed'), viewport: VIEWPORT, serviceWorkers, args: ['--no-first-run', '--no-default-browser-check'] };
  if (CHROME) opts.executablePath = CHROME;
  else opts.channel = 'chrome';
  const context = await chromium.launchPersistentContext(dir, opts);
  await context.addInitScript(INIT_SCRIPT);
  const page = context.pages()[0] ?? (await context.newPage());
  const probe = await context.newCDPSession(page);
  const version = (await probe.send('Browser.getVersion')).product;
  await probe.detach();
  return { context, dir, version };
}

/** Attaches request accounting (Playwright events + CDP byte counts) to a page. */
async function instrument(page, { disableCache }) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Network.enable');
  await cdp.send('Performance.enable');
  if (disableCache) await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
  const state = { requests: [], lastStart: Date.now(), inflight: new Set(), byId: new Map() };
  page.on('request', (req) => {
    if (req.url().startsWith('data:') || req.url().startsWith('blob:')) return;
    const r = { url: req.url(), host: new URL(req.url()).host, t: Date.now(), status: null, failed: false, sw: false, decoded: 0, encoded: 0 };
    state.requests.push(r);
    state.inflight.add(req);
    state.lastStart = r.t;
    req.__m = r;
  });
  const done = (req, failed) => {
    state.inflight.delete(req);
    if (req.__m && failed) req.__m.failed = true;
  };
  page.on('requestfinished', (req) => done(req, false));
  page.on('requestfailed', (req) => done(req, true));
  page.on('response', (res) => {
    const r = res.request().__m;
    if (r) { r.status = res.status(); r.sw = res.fromServiceWorker(); }
  });
  // CDP gives decoded (dataLength) and on-the-wire (encodedDataLength) bytes.
  const bytes = { decoded: 0, encoded: 0, byHost: new Map() };
  cdp.on('Network.requestWillBeSent', (e) => state.byId.set(e.requestId, e.request.url));
  cdp.on('Network.dataReceived', (e) => {
    bytes.decoded += e.dataLength;
    const url = state.byId.get(e.requestId);
    if (url && !url.startsWith('data:')) {
      const h = new URL(url).host;
      bytes.byHost.set(h, (bytes.byHost.get(h) ?? 0) + e.dataLength);
    }
  });
  cdp.on('Network.loadingFinished', (e) => { bytes.encoded += e.encodedDataLength; });
  return { cdp, state, bytes };
}

async function waitQuiet(state, since, capMs, quietMs = QUIET_MS) {
  const deadline = since + capMs;
  while (Date.now() < deadline) {
    if (Date.now() - state.lastStart >= quietMs && Date.now() - since >= quietMs) return { quiet: true, ms: Date.now() - since };
    await delay(250);
  }
  return { quiet: false, ms: Date.now() - since };
}

/** Waits until the main thread has had no long task (> 50 ms) for idleMs, so the heap is read at rest. */
async function waitMainThreadIdle(page, idleMs = 3000, capMs = 60000) {
  const deadline = Date.now() + capMs;
  while (Date.now() < deadline) {
    const idle = await page.evaluate(() => performance.now() - (window.__naviMeasure?.lastLongTaskEnd ?? 0));
    if (idle >= idleMs) return true;
    await delay(500);
  }
  return false;
}

async function heap(cdp) {
  const pick = async () => Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map((m) => [m.name, m.value]));
  const before = (await pick()).JSHeapUsedSize;
  await cdp.send('HeapProfiler.collectGarbage');
  const after = (await pick()).JSHeapUsedSize;
  return { usedBytes: before, usedAfterGcBytes: after };
}

async function dismissOnboarding(page) {
  const overlay = page.locator('.onboarding-overlay');
  if (await overlay.isVisible().catch(() => false)) {
    await overlay.click({ position: { x: 5, y: 5 } });
    await overlay.waitFor({ state: 'hidden', timeout: 10000 }).catch(() => {});
    return true;
  }
  return false;
}

/** Counts elements a keyboard user would Tab through on the current page. */
async function tabStops(page) {
  return page.evaluate(() => {
    const sel = 'a[href],area[href],button,input,select,textarea,iframe,summary,[tabindex],[contenteditable=""],[contenteditable="true"],audio[controls],video[controls]';
    const visible = (el) => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
    const all = [...document.querySelectorAll(sel)].filter((el) =>
      el.tabIndex >= 0 && !el.disabled && !el.closest('[inert]') && !(el.type === 'hidden') && visible(el));
    const matrix = document.querySelector('app-matrix');
    return { total: all.length, inMatrix: matrix ? all.filter((el) => matrix.contains(el)).length : 0, cells: document.querySelectorAll('app-technique-cell').length };
  });
}

async function axeCounts(page) {
  const res = await new AxeBuilder({ page }).analyze();
  const out = { violations: res.violations.length, nodes: 0, byImpact: {}, rules: {} };
  for (const v of res.violations) {
    out.nodes += v.nodes.length;
    const k = v.impact ?? 'unknown';
    out.byImpact[k] = out.byImpact[k] ?? { rules: 0, nodes: 0 };
    out.byImpact[k].rules += 1;
    out.byImpact[k].nodes += v.nodes.length;
    out.rules[v.id] = { impact: v.impact, nodes: v.nodes.length };
  }
  return out;
}

function summarizeRequests(reqs, appHost) {
  const byHost = {};
  for (const r of reqs) {
    const h = r.host === appHost ? '(app, local)' : r.host;
    byHost[h] = (byHost[h] ?? 0) + 1;
  }
  const gh = reqs.filter((r) => r.host === 'api.github.com');
  return {
    total: reqs.length,
    thirdParty: reqs.filter((r) => r.host !== appHost).length,
    servedByServiceWorker: reqs.filter((r) => r.sw).length,
    byHost: Object.fromEntries(Object.entries(byHost).sort((a, b) => b[1] - a[1])),
    apiGithub: {
      count: gh.length,
      status: gh.reduce((a, r) => ({ ...a, [r.status ?? (r.failed ? 'failed' : 'pending')]: (a[r.status ?? (r.failed ? 'failed' : 'pending')] ?? 0) + 1 }), {}),
      urls: gh.map((r) => r.url.replace('https://api.github.com', '')),
    },
  };
}

/** One measured load: navigate to /matrix and wait for the boot to go quiet. */
async function measureLoad(page, inst, base, label) {
  const appHost = new URL(base).host;
  const start = Date.now();
  const firstReq = inst.state.requests.length;
  await page.goto(`${base}/#/matrix`, { waitUntil: 'commit' });
  await page.waitForSelector('app-technique-cell .cell', { timeout: 180000 });
  const q = await waitQuiet(inst.state, start, WINDOW_MS);
  const idle = await waitMainThreadIdle(page);
  const t = await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0];
    const fcp = performance.getEntriesByName('first-contentful-paint')[0];
    return {
      fcpMs: fcp ? fcp.startTime : null,
      dclMs: nav ? nav.domContentLoadedEventEnd : null,
      loadMs: nav ? nav.loadEventEnd : null,
      firstCellDomMs: window.__naviMeasure?.firstCellDom ?? null,
      firstCellFrameMs: window.__naviMeasure?.firstCellFrame ?? null,
      cells: document.querySelectorAll('app-technique-cell').length,
      longTasks: window.__naviMeasure?.longTasks ?? null,
      maxLongTaskMs: window.__naviMeasure?.maxLongTask ?? null,
      swControlled: !!navigator.serviceWorker?.controller,
    };
  });
  const reqs = inst.state.requests.slice(firstReq);
  const result = {
    label,
    ...t,
    windowMs: q.ms,
    windowQuiet: q.quiet,
    mainThreadIdleBeforeHeap: idle,
    inflightAtEnd: inst.state.inflight.size,
    decodedBytes: inst.bytes.decoded,
    encodedBytes: inst.bytes.encoded,
    decodedBytesByHost: Object.fromEntries([...inst.bytes.byHost].map(([h, b]) => [h === appHost ? '(app, local)' : h, b]).sort((a, b) => b[1] - a[1])),
    requests: summarizeRequests(reqs, appHost),
    heap: await heap(inst.cdp),
  };
  log(`${label}: FCP ${fmtMs(result.fcpMs)}, first cell ${fmtMs(result.firstCellFrameMs)}, ${result.requests.total} requests ` +
      `(${result.requests.apiGithub.count} api.github.com), ${mb(result.decodedBytes)} decoded, window ${fmtMs(q.ms)}${q.quiet ? '' : ' (cap)'}`);
  return result;
}

function heatmapModes() {
  const src = readFileSync(join(ROOT, 'src/app/models/heatmap-modes.ts'), 'utf8');
  return [...src.matchAll(/\{\s*value:\s*'([^']+)',\s*label:\s*'([^']+)',\s*short:\s*'([^']+)'/g)].map((m) => ({ value: m[1], label: m[2], short: m[3] }));
}

function routedTabs() {
  const dir = join(ROOT, 'src/app/pages');
  const tabs = [];
  for (const ws of readdirSync(dir)) {
    const f = join(dir, ws, `${ws}.routes.ts`);
    if (!existsSync(f)) continue;
    for (const m of readFileSync(f, 'utf8').matchAll(/path:\s*'([a-z0-9-]+)',\s*\n\s*loadComponent/g)) tabs.push(`/${ws}/${m[1]}`);
  }
  return ['/matrix', '/status', ...tabs];
}

/** Switch lenses through the real View menu and attribute api.github.com calls to each. */
async function lensPass(page, inst) {
  const modes = heatmapModes();
  log(`lens pass: ${modes.length} heatmap modes`);
  const out = [];
  for (const m of modes) {
    const since = Date.now();
    const first = inst.state.requests.length;
    let error = null;
    try {
      if (!(await page.locator('.views-menu').isVisible().catch(() => false))) await page.click('.heatmap-btn');
      const btn = page.locator('.heatmap-groups .heatmap-mode-btn').filter({ hasText: m.label.trim() }).first();
      await btn.click({ timeout: 10000 });
    } catch (e) {
      error = String(e.message ?? e).split('\n')[0];
    }
    await waitQuiet(inst.state, since, 45000, 3000);
    // The View button shows the active lens's short name: confirms the switch happened.
    const shown = (await page.locator('.heatmap-btn').innerText().catch(() => '')).replace(/[▾\s]+$/, '');
    if (!error && !shown.endsWith(m.short)) error = `View button shows "${shown}" after the click`;
    const reqs = inst.state.requests.slice(first);
    const gh = reqs.filter((r) => r.host === 'api.github.com');
    out.push({ lens: m.value, label: m.label, apiGithub: gh.length, apiGithubUrls: gh.map((r) => r.url.replace('https://api.github.com', '')), thirdParty: reqs.filter((r) => r.host !== new URL(page.url()).host).length, error });
  }
  return out;
}

/** Open the technique sidebar (the drawer) once and attribute api.github.com calls to it. */
async function drawerPass(page, inst) {
  const since = Date.now();
  const first = inst.state.requests.length;
  let error = null;
  try {
    await page.locator('app-technique-cell .cell').first().click();
    await page.waitForSelector('.sidebar.open', { timeout: 30000 });
  } catch (e) {
    error = String(e.message ?? e).split('\n')[0];
  }
  await waitQuiet(inst.state, since, 60000, 3000);
  const gh = inst.state.requests.slice(first).filter((r) => r.host === 'api.github.com');
  await page.keyboard.press('Escape');
  log(`drawer: ${gh.length} api.github.com calls`);
  return { apiGithub: gh.length, apiGithubUrls: gh.map((r) => r.url.replace('https://api.github.com', '')), error };
}

/** Visit every routed tab in order and attribute api.github.com calls to each. */
async function routePass(page, inst, base) {
  const routes = routedTabs();
  log(`route pass: ${routes.length} routed tabs`);
  const out = [];
  for (const r of routes) {
    const since = Date.now();
    const first = inst.state.requests.length;
    let error = null;
    try {
      await page.goto(`${base}/#${r}`, { waitUntil: 'commit' });
    } catch (e) {
      error = String(e.message ?? e).split('\n')[0];
    }
    await waitQuiet(inst.state, since, 45000, 3000);
    const reqs = inst.state.requests.slice(first);
    const gh = reqs.filter((x) => x.host === 'api.github.com');
    out.push({ route: r, apiGithub: gh.length, apiGithubUrls: gh.map((x) => x.url.replace('https://api.github.com', '')), thirdParty: reqs.filter((x) => x.host !== new URL(base).host).length, error });
  }
  return out;
}

/** The api.github.com URLs the source code can request, for the reconciliation table. */
function codeGithubLoaders() {
  const dir = join(ROOT, 'src/app/services');
  const out = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && !x.endsWith('.spec.ts'))) {
    for (const m of readFileSync(join(dir, f), 'utf8').matchAll(/https:\/\/api\.github\.com(\/[^'"`\s]+)/g)) out.push({ file: `services/${f}`, path: m[1] });
  }
  return out;
}

// ── 5. runs ──────────────────────────────────────────────────────────────────
async function coldRun(base, withPasses) {
  const { context, dir, version } = await launch('cold', 'block');
  try {
    const page = context.pages()[0] ?? (await context.newPage());
    const inst = await instrument(page, { disableCache: true });
    const load = await measureLoad(page, inst, base, 'cold');
    load.browserVersion = version;
    if (!withPasses) return { load };
    const onboardingShown = await dismissOnboarding(page);
    const stops = await tabStops(page);
    log(`tab stops on /matrix: ${stops.total} (${stops.inMatrix} inside the matrix, ${stops.cells} cells)`);
    const axe = await axeCounts(page);
    log(`axe on /matrix: ${axe.violations} violated rules, ${axe.nodes} nodes`);
    const lenses = flag('--no-lenses') ? null : await lensPass(page, inst);
    const drawer = flag('--no-routes') ? null : await drawerPass(page, inst);
    const routes = flag('--no-routes') ? null : await routePass(page, inst, base);
    return { load, onboardingShown, tabStops: stops, axe, lenses, drawer, routes };
  } finally {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

async function warmRun(base) {
  const { context, dir, version } = await launch('warm', 'allow');
  try {
    const prime = context.pages()[0] ?? (await context.newPage());
    const pinst = await instrument(prime, { disableCache: false });
    const primeLoad = await measureLoad(prime, pinst, base, 'warm (priming load)');
    await dismissOnboarding(prime);
    const swReady = await prime.evaluate(() =>
      Promise.race([navigator.serviceWorker.ready.then(() => true), new Promise((r) => setTimeout(() => r(false), 60000))]));
    await waitQuiet(pinst.state, Date.now(), WINDOW_MS);
    const page = await context.newPage();
    await prime.close();
    const inst = await instrument(page, { disableCache: false });
    const load = await measureLoad(page, inst, base, 'warm');
    load.browserVersion = version;
    load.serviceWorkerReadyBeforeSecondLoad = swReady;
    const stops = await tabStops(page);
    return { load, tabStops: stops, primeLoad: { fcpMs: primeLoad.fcpMs, firstCellFrameMs: primeLoad.firstCellFrameMs, requests: primeLoad.requests.total } };
  } finally {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── 6. report ────────────────────────────────────────────────────────────────
function fmtMs(ms) { return ms === null || ms === undefined ? 'n/a' : `${(ms / 1000).toFixed(2)} s`; }
function mb(b) { return b === null || b === undefined ? 'n/a' : `${(b / 1e6).toFixed(1)} MB`; }
function kb(b) { return b === null || b === undefined ? 'n/a' : `${(b / 1000).toFixed(1)} KB`; }
function pct(actual, ref) { return actual === null || !ref ? 'n/a' : `${(((actual - ref) / ref) * 100).toFixed(0)}%`; }

// Figures from the 2026-10-13 live walkthrough of main at 5831e2d (plan section 2).
const WALKTHROUGH = {
  warmFcpMs: 800, warmDclMs: 250, warmFirstCellMs: 6300, coldFcpMs: 6400, coldDclMs: 3100,
  heapMbLow: 43, heapMbHigh: 45, tabStops: 880, apiGithubBoot: 6, thirdPartyBoot: 45, coldDecodedMb: 115, mainKb: 719,
};

function markdown(r) {
  const c = r.cold.load;
  const w = r.warm.load;
  const within = (actual, ref) => (actual === null ? 'n/a' : Math.abs(actual - ref) / ref <= 0.15 ? 'yes' : 'no');
  const lines = [];
  const p = (s = '') => lines.push(s);
  p('# Measurements');
  p();
  p('Lab baseline for plan epic E0.4. Generated by `node scripts/measure.mjs --md docs/MEASUREMENTS.md`; do not edit by hand, rerun the script.');
  p();
  p(`- Measured: ${r.when}, target ${r.target}, checkout \`${r.commit}\`, ${r.browser}, viewport ${VIEWPORT.width}x${VIEWPORT.height}, ${r.runs} run(s) per profile (median shown).`);
  p('- Served: the production build (`ng build --stats-json`, service worker on) from a local static server on 127.0.0.1 with gzip and `max-age=600`, like GitHub Pages. Third-party data is fetched live from the internet, so third-party timings depend on the network at the time of the run.');
  p('- **Cold** = fresh Chrome profile, service workers blocked, HTTP cache disabled through CDP: a true first visit, onboarding modal on top.');
  p('- **Warm** = fresh Chrome profile with the service worker allowed; one priming load (onboarding dismissed, worker installed, IndexedDB filled), then a second load in a new tab is measured: the walkthrough\'s "warm revisit".');
  p(`- Boot window: from navigation until no new request has started for ${QUIET_MS / 1000} s, capped at ${WINDOW_MS / 1000} s. Requests and bytes are those started or received inside the window; slow third-party downloads still running at the cap are counted as requests but only their bytes received so far.`);
  p('- JS heap is read from CDP after the boot window and once the main thread has had no long task for 3 s; the figure after a forced GC is the retained heap.');
  p('- api.github.com calls are counted when the request is issued, whatever GitHub answers; the unauthenticated limit is 60 per hour per IP, so repeated runs see 403s (status counts below).');
  p();
  p('## Load baseline');
  p();
  p('| Metric | Cold (true first visit) | Warm (second load, service worker) |');
  p('|---|---|---|');
  p(`| First contentful paint | ${fmtMs(c.fcpMs)} | ${fmtMs(w.fcpMs)} |`);
  p(`| DOMContentLoaded | ${fmtMs(c.dclMs)} | ${fmtMs(w.dclMs)} |`);
  p(`| First matrix cell (in DOM) | ${fmtMs(c.firstCellDomMs)} | ${fmtMs(w.firstCellDomMs)} |`);
  p(`| First matrix cell (next frame painted) | ${fmtMs(c.firstCellFrameMs)} | ${fmtMs(w.firstCellFrameMs)} |`);
  p(`| Matrix cells rendered | ${c.cells} | ${w.cells} |`);
  p(`| Requests in boot window (third-party) | ${c.requests.total} (${c.requests.thirdParty}) | ${w.requests.total} (${w.requests.thirdParty}); ${w.requests.servedByServiceWorker} served by the service worker |`);
  p(`| api.github.com calls on boot | ${c.requests.apiGithub.count} | ${w.requests.apiGithub.count} |`);
  p(`| Decoded bytes in boot window | ${mb(c.decodedBytes)} | ${mb(w.decodedBytes)} |`);
  p(`| Bytes on the wire in boot window | ${mb(c.encodedBytes)} | ${mb(w.encodedBytes)} |`);
  p(`| Requests still in flight at window end | ${c.inflightAtEnd} | ${w.inflightAtEnd} |`);
  p(`| Boot window length | ${fmtMs(c.windowMs)}${c.windowQuiet ? '' : ' (cap)'} | ${fmtMs(w.windowMs)}${w.windowQuiet ? '' : ' (cap)'} |`);
  p(`| Long tasks during boot (longest) | ${c.longTasks} (${fmtMs(c.maxLongTaskMs)}) | ${w.longTasks} (${fmtMs(w.maxLongTaskMs)}) |`);
  p(`| JS heap used at rest (after GC) | ${mb(c.heap.usedBytes)} (${mb(c.heap.usedAfterGcBytes)}) | ${mb(w.heap.usedBytes)} (${mb(w.heap.usedAfterGcBytes)}) |`);
  p(`| Tab stops on /matrix (inside the matrix) | ${r.cold.tabStops.total} (${r.cold.tabStops.inMatrix}) | ${r.warm.tabStops.total} (${r.warm.tabStops.inMatrix}) |`);
  if (r.runs > 1) {
    p();
    p(`Spread over ${r.runs} runs (min to max): cold FCP ${r.spread.coldFcp}, cold first cell ${r.spread.coldCell}; warm FCP ${r.spread.warmFcp}, warm first cell ${r.spread.warmCell}.`);
  }
  p();
  p('The cold first-cell time above is the **Phase 3 baseline** for "Cold first matrix cells" (plan 6.5), replacing the ~6.3 s figure that was observed with a warm service worker.');
  p();
  p('## Against the walkthrough (2026-10-13, live GitHub Pages)');
  p();
  p('Acceptance: one command reproduces the walkthrough\'s warm numbers within 15%.');
  p();
  p('| Walkthrough figure | Walkthrough | This run | Delta | Within 15% |');
  p('|---|---|---|---|---|');
  p(`| Warm FCP | 0.80 s | ${fmtMs(w.fcpMs)} | ${pct(w.fcpMs, WALKTHROUGH.warmFcpMs)} | ${within(w.fcpMs, WALKTHROUGH.warmFcpMs)} |`);
  p(`| Warm DOMContentLoaded | 0.25 s | ${fmtMs(w.dclMs)} | ${pct(w.dclMs, WALKTHROUGH.warmDclMs)} | ${within(w.dclMs, WALKTHROUGH.warmDclMs)} |`);
  p(`| First cell, warm service worker | ~6.3 s | ${fmtMs(w.firstCellFrameMs)} | ${pct(w.firstCellFrameMs, WALKTHROUGH.warmFirstCellMs)} | ${within(w.firstCellFrameMs, WALKTHROUGH.warmFirstCellMs)} |`);
  p(`| JS heap on /matrix (warm) | 43-45 MB | ${mb(w.heap.usedBytes)} | ${pct(w.heap.usedBytes / 1e6, 44)} | ${within(w.heap.usedBytes / 1e6, 44)} |`);
  p(`| Tab stops on /matrix | ~880 | ${r.cold.tabStops.total} | ${pct(r.cold.tabStops.total, WALKTHROUGH.tabStops)} | ${within(r.cold.tabStops.total, WALKTHROUGH.tabStops)} |`);
  p(`| Cold FCP (not a warm figure; for reference) | 6.4 s | ${fmtMs(c.fcpMs)} | ${pct(c.fcpMs, WALKTHROUGH.coldFcpMs)} | ${within(c.fcpMs, WALKTHROUGH.coldFcpMs)} |`);
  p(`| api.github.com calls on boot (cold) | 6 | ${c.requests.apiGithub.count} | ${pct(c.requests.apiGithub.count, 6)} | ${within(c.requests.apiGithub.count, 6)} |`);
  p(`| Third-party fetches on boot (cold) | ~45 | ${c.requests.thirdParty} | ${pct(c.requests.thirdParty, 45)} | ${within(c.requests.thirdParty, 45)} |`);
  p(`| Decoded payload, cold | ~115 MB | ${mb(c.decodedBytes)} | ${pct(c.decodedBytes / 1e6, 115)} | ${within(c.decodedBytes / 1e6, 115)} |`);
  p(`| main-*.js | 719 KB | ${kb(r.bundle.mainBytes)} | ${pct(r.bundle.mainBytes / 1000, 719)} | ${within(r.bundle.mainBytes / 1000, 719)} |`);
  p();
  p('## Requests by host');
  p();
  const hosts = [...new Set([...Object.keys(c.requests.byHost), ...Object.keys(w.requests.byHost)])];
  p('| Host | Cold requests | Cold decoded | Warm requests | Warm decoded |');
  p('|---|---|---|---|---|');
  for (const h of hosts) {
    p(`| ${h} | ${c.requests.byHost[h] ?? 0} | ${mb(c.decodedBytesByHost[h] ?? 0)} | ${w.requests.byHost[h] ?? 0} | ${mb(w.decodedBytesByHost[h] ?? 0)} |`);
  }
  p();
  p('## Bundle (from browser-stats.json)');
  p();
  p('| Item | Raw | Gzip |');
  p('|---|---|---|');
  p(`| ${r.bundle.mainFile} | ${kb(r.bundle.mainBytes)} | ${kb(r.bundle.mainGzipBytes)} |`);
  p(`| Initial total (${r.bundle.initialFiles.length} files: main, polyfills, styles and their static imports) | ${kb(r.bundle.initialBytes)} | ${kb(r.bundle.initialGzipBytes)} |`);
  p(`| All JavaScript (${r.bundle.jsFiles} files, ${r.bundle.lazyJsFiles} lazy) | ${kb(r.bundle.totalJsBytes)} | |`);
  p(`| dist assets/ (data shipped with the app) | ${mb(r.bundle.assetsBytes)} | |`);
  p();
  p('## Accessibility on /matrix (cold, onboarding dismissed)');
  p();
  const ax = r.cold.axe;
  p(`axe-core (default rules): ${ax.violations} violated rules over ${ax.nodes} nodes. Report-only; the blocking gate is E8.4.`);
  p();
  p('| Impact | Rules | Nodes |');
  p('|---|---|---|');
  for (const k of ['critical', 'serious', 'moderate', 'minor', 'unknown']) if (ax.byImpact[k]) p(`| ${k} | ${ax.byImpact[k].rules} | ${ax.byImpact[k].nodes} |`);
  p();
  p('| Rule | Impact | Nodes |');
  p('|---|---|---|');
  for (const [id, v] of Object.entries(ax.rules).sort((a, b) => b[1].nodes - a[1].nodes)) p(`| ${id} | ${v.impact} | ${v.nodes} |`);
  p();
  p(`Tab stops: ${r.cold.tabStops.total} focusable elements in tab order on /matrix, ${r.cold.tabStops.inMatrix} of them inside \`app-matrix\` (${r.cold.tabStops.cells} technique cells rendered).`);
  p();
  p('## api.github.com calls on boot and per lens');
  p();
  p(`Boot (cold): ${c.requests.apiGithub.count} calls; status ${JSON.stringify(c.requests.apiGithub.status)}.`);
  p();
  for (const u of c.requests.apiGithub.urls) p(`- \`${u}\``);
  p();
  p(`Boot (warm second load): ${w.requests.apiGithub.count} calls; status ${JSON.stringify(w.requests.apiGithub.status)}.`);
  p();
  if (r.cold.lenses) {
    p('Per lens, on the cold page after boot, switched through the View menu in registry order. Counts are incremental: a loader already started at boot or by an earlier lens is not counted again.');
    p();
    p('| # | Lens | api.github.com calls | Other third-party requests | Calls |');
    p('|---|---|---|---|---|');
    r.cold.lenses.forEach((l, i) => p(`| ${i + 1} | ${l.lens} | ${l.apiGithub} | ${l.thirdParty - l.apiGithub} | ${l.error ? `switch failed: ${l.error}` : l.apiGithubUrls.map((u) => `\`${u}\``).join('<br>')} |`));
    p();
    p(`Lenses switched: ${r.cold.lenses.filter((l) => !l.error).length} of ${r.cold.lenses.length}. api.github.com calls triggered by lenses: ${r.cold.lenses.reduce((a, l) => a + l.apiGithub, 0)}.`);
    p();
  }
  if (r.cold.drawer) {
    const d = r.cold.drawer;
    p(`Technique sidebar, opened once on the first cell after the lens pass: ${d.error ? `open failed: ${d.error}` : `${d.apiGithub} calls`}.`);
    p();
    for (const u of d.apiGithubUrls) p(`- \`${u}\``);
    if (d.apiGithubUrls.length) p();
  }
  if (r.cold.routes) {
    p('Per routed tab, after the lens pass and the sidebar, visited in route order (incremental, as above). Only tabs that triggered a call are listed.');
    p();
    p('| Route | api.github.com calls | Calls |');
    p('|---|---|---|');
    for (const x of r.cold.routes.filter((x) => x.apiGithub > 0 || x.error)) p(`| ${x.route} | ${x.apiGithub} | ${x.error ? `navigation failed: ${x.error}` : x.apiGithubUrls.map((u) => `\`${u}\``).join('<br>')} |`);
    p();
    p(`Routed tabs visited: ${r.cold.routes.length}. api.github.com calls triggered by routes: ${r.cold.routes.reduce((a, x) => a + x.apiGithub, 0)}.`);
    p();
  }
  p('### Reconciliation with the loaders in code');
  p();
  p(`The source holds ${r.codeLoaders.length} api.github.com URLs. Where each was first seen in this run:`);
  p();
  p('| Code | Endpoint | First seen |');
  p('|---|---|---|');
  const seen = (path) => {
    const norm = path.split('?')[0];
    const hit = (urls) => urls.some((u) => u.split('?')[0] === norm);
    if (hit(c.requests.apiGithub.urls)) return 'boot';
    for (const l of r.cold.lenses ?? []) if (hit(l.apiGithubUrls)) return `lens ${l.lens}`;
    if (r.cold.drawer && hit(r.cold.drawer.apiGithubUrls)) return 'technique sidebar';
    for (const x of r.cold.routes ?? []) if (hit(x.apiGithubUrls)) return `route ${x.route}`;
    return 'not triggered in this run';
  };
  for (const l of r.codeLoaders) p(`| ${l.file} | \`${l.path}\` | ${seen(l.path)} |`);
  p();
  return lines.join('\n');
}

// ── main ─────────────────────────────────────────────────────────────────────
const server = REMOTE ? null : await startServer();
const base = REMOTE ?? `http://127.0.0.1:${server.address().port}`;
log(REMOTE ? `measuring deployed copy at ${base}` : `serving ${BROWSER_DIR} at ${base}`);
try {
  const bundle = bundleStats();
  log(`bundle: ${bundle.mainFile} ${kb(bundle.mainBytes)}, initial ${kb(bundle.initialBytes)}`);
  const colds = [];
  const warms = [];
  for (let i = 0; i < RUNS; i++) {
    log(`run ${i + 1} of ${RUNS}`);
    colds.push(await coldRun(base, i === 0));
    warms.push(await warmRun(base));
  }
  const pickMedian = (runs, key) => median(runs.map((x) => x.load[key]));
  const range = (runs, key) => {
    const v = runs.map((x) => x.load[key]).filter((x) => x !== null);
    return `${fmtMs(Math.min(...v))} to ${fmtMs(Math.max(...v))}`;
  };
  const cold = colds[0];
  const warm = warms[0];
  for (const k of ['fcpMs', 'dclMs', 'firstCellDomMs', 'firstCellFrameMs']) {
    cold.load[k] = pickMedian(colds, k);
    warm.load[k] = pickMedian(warms, k);
  }
  const commit = spawnSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
  const result = {
    target: REMOTE ?? 'local production build',
    when: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
    commit,
    browser: cold.load.browserVersion,
    runs: RUNS,
    bundle,
    cold,
    warm,
    spread: { coldFcp: range(colds, 'fcpMs'), coldCell: range(colds, 'firstCellFrameMs'), warmFcp: range(warms, 'fcpMs'), warmCell: range(warms, 'firstCellFrameMs') },
    allRuns: { cold: colds.map((x) => x.load), warm: warms.map((x) => x.load) },
    codeLoaders: codeGithubLoaders(),
  };
  writeFileSync(OUT, JSON.stringify(result, null, 2));
  log(`results written to ${OUT}`);
  if (MD) {
    writeFileSync(resolve(ROOT, MD), markdown(result) + '\n');
    log(`markdown written to ${MD}`);
  }
  console.log(`\ncold: FCP ${fmtMs(cold.load.fcpMs)}, first cell ${fmtMs(cold.load.firstCellFrameMs)}, api.github.com ${cold.load.requests.apiGithub.count}`);
  console.log(`warm: FCP ${fmtMs(warm.load.fcpMs)}, first cell ${fmtMs(warm.load.firstCellFrameMs)}, api.github.com ${warm.load.requests.apiGithub.count}`);
} finally {
  server?.close();
}

#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Derives docs/FACTS.md from the code, so that counts quoted in the docs have
// one source. Every value below is read from a file in the repository; nothing
// is typed in by hand.
//
//   node scripts/gen-facts.mjs           write docs/FACTS.md
//   node scripts/gen-facts.mjs --check   exit 1 if docs/FACTS.md is out of date
//   node scripts/gen-facts.mjs --json    print the facts as JSON
//
// scripts/check-facts.mjs compares the numbers stated in README.md,
// ARCHITECTURE.md, HANDOFF.md and QUICKSTART.md against these facts.

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { lintRepo } from './lint-truth-vocab.mjs';

export const FACTS_PATH = 'docs/FACTS.md';
const JSON_START = '<!-- facts-json';
const JSON_END = 'facts-json -->';

const read = (root, p) => readFileSync(join(root, p), 'utf8');
const posix = (p) => p.split('\\').join('/');

// ---------------------------------------------------------------- TS parsing

/** Index of the bracket that closes the one at `open`, skipping strings and comments. */
function matchBracket(src, open) {
  const pairs = { '{': '}', '[': ']', '(': ')' };
  const stack = [];
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) break; continue; }
    if (c === '/' && src[i + 1] === '*') { i = src.indexOf('*/', i) + 1; continue; }
    if (c === "'" || c === '"' || c === '`') {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === '}' || c === ']' || c === ')') {
      if (stack.pop() !== c) throw new Error(`unbalanced ${c} at ${i}`);
      if (stack.length === 0) return i;
    }
  }
  throw new Error(`no closing bracket for ${src[open]} at ${open}`);
}

/** Text of the array literal assigned to `export const <name>`. */
function exportedArray(src, name, file) {
  const m = new RegExp(`export const ${name}\\b[^=]*=\\s*\\[`).exec(src);
  if (!m) throw new Error(`${file}: export const ${name} = [ ... ] not found`);
  const open = m.index + m[0].length - 1;
  return src.slice(open + 1, matchBracket(src, open));
}

/** Top-level `{ ... }` elements of an array body. */
function topLevelObjects(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '/' && body[i + 1] === '/') { i = body.indexOf('\n', i); if (i < 0) break; continue; }
    if (c === '/' && body[i + 1] === '*') { i = body.indexOf('*/', i) + 1; continue; }
    if (c === '{') { const end = matchBracket(body, i); out.push(body.slice(i + 1, end)); i = end; }
  }
  return out;
}

/** The object's own text with nested brackets blanked, so own keys can be matched safely. */
function ownText(obj) {
  let out = '';
  for (let i = 0; i < obj.length; i++) {
    const c = obj[i];
    if (c === '{' || c === '[' || c === '(') { const end = matchBracket(obj, i); out += c + ' '.repeat(end - i - 1) + obj[end]; i = end; }
    else out += c;
  }
  return out;
}

function ownString(obj, key) {
  const own = ownText(obj);
  const m = new RegExp(`(?:^|[,{\\s])${key}\\s*:\\s*'([^']*)'`).exec(own);
  return m ? m[1] : undefined;
}

function ownHas(obj, key) {
  return new RegExp(`(?:^|[,{\\s])${key}\\s*:`).test(ownText(obj));
}

function ownSub(obj, key, open) {
  const own = ownText(obj);
  const m = new RegExp(`(?:^|[,{\\s])${key}\\s*:\\s*\\${open}`).exec(own);
  if (!m) return undefined;
  const start = m.index + m[0].length - 1;
  return obj.slice(start + 1, matchBracket(obj, start));
}

// ------------------------------------------------------------------ collectors

function heatmapModes(root) {
  const file = 'src/app/models/heatmap-modes.ts';
  const body = exportedArray(read(root, file), 'HEATMAP_MODES', file);
  const modes = topLevelObjects(body).map((o) => ({
    id: ownString(o, 'value'), short: ownString(o, 'short'), group: ownString(o, 'group'),
    rung: [ownString(o, 'rung'), ownString(o, 'qualifier')].filter(Boolean).join(' '),
  }));
  if (modes.some((m) => !m.id)) throw new Error(`${file}: a HEATMAP_MODES entry has no value`);
  if (modes.some((m) => !m.rung)) throw new Error(`${file}: a HEATMAP_MODES entry has no rung`);
  return { source: file, count: modes.length, modes };
}

function routes(root) {
  const appFile = 'src/app/app.routes.ts';
  const top = topLevelObjects(exportedArray(read(root, appFile), 'routes', appFile));
  const workspaces = [];
  const redirects = [];
  for (const o of top) {
    const path = ownString(o, 'path');
    if (ownHas(o, 'redirectTo')) { redirects.push({ path, to: ownString(o, 'redirectTo') }); continue; }
    const data = ownSub(o, 'data', '{');
    const ws = { path: `/${path}`, kind: ownHas(o, 'loadChildren') ? 'route file' : 'single component', title: data ? ownString(data, 'title') : undefined, tabs: [] };
    if (ws.kind === 'route file') {
      const m = /import\('\.\/(pages\/[^']+)'\)\.then\(\(?\w+\)?\s*=>\s*\w+\.(\w+)\)/.exec(o);
      if (!m) throw new Error(`${appFile}: cannot resolve loadChildren for /${path}`);
      const file = `src/app/${m[1]}.ts`;
      ws.routeFile = file;
      const shells = topLevelObjects(exportedArray(read(root, file), m[2], file));
      for (const shell of shells) {
        const sd = ownSub(shell, 'data', '{');
        if (sd && ownString(sd, 'title')) ws.title = ownString(sd, 'title');
        for (const child of topLevelObjects(ownSub(shell, 'children', '[') ?? '')) {
          if (ownHas(child, 'redirectTo')) continue;
          const cd = ownSub(child, 'data', '{');
          const tab = cd ? ownString(cd, 'tab') : undefined;
          if (!tab) throw new Error(`${file}: child route '${ownString(child, 'path')}' has no data.tab`);
          ws.tabs.push({ path: ownString(child, 'path'), tab });
        }
      }
    }
    workspaces.push(ws);
  }
  // Route files under pages/ that app.routes.ts does not load would be dead code; list them.
  const pagesDir = join(root, 'src/app/pages');
  const routeFiles = readdirSync(pagesDir).flatMap((d) => {
    const dir = join(pagesDir, d);
    return statSync(dir).isDirectory() ? readdirSync(dir).filter((f) => f.endsWith('.routes.ts')).map((f) => posix(relative(root, join(dir, f)))) : [];
  }).sort();
  const unreferenced = routeFiles.filter((f) => !workspaces.some((w) => w.routeFile === f));
  return {
    source: [appFile, 'src/app/pages/*/*.routes.ts'],
    workspaces,
    redirects,
    workspaceCount: workspaces.length,
    routeFileWorkspaceCount: workspaces.filter((w) => w.kind === 'route file').length,
    singleComponentWorkspaceCount: workspaces.filter((w) => w.kind === 'single component').length,
    tabCount: workspaces.reduce((n, w) => n + w.tabs.length, 0),
    unreferencedRouteFiles: unreferenced,
  };
}

function walk(root, dir, pred, skip = new Set(['node_modules', 'dist', '.angular', '.git'])) {
  const abs = join(root, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const name of readdirSync(abs)) {
    if (skip.has(name)) continue;
    const rel = posix(join(dir, name));
    const st = statSync(join(root, rel));
    if (st.isDirectory()) out.push(...walk(root, rel, pred, skip));
    else if (pred(rel)) out.push(rel);
  }
  return out.sort();
}

function specs(root) {
  return {
    unitSpecFiles: walk(root, 'src', (p) => p.endsWith('.spec.ts')).length,
    e2eSpecFiles: walk(root, 'e2e', (p) => p.endsWith('.spec.ts')).length,
    scriptTestFiles: walk(root, 'scripts', (p) => p.endsWith('.test.mjs')).length,
    proxyTestFiles: walk(root, 'server', (p) => /\.(test|spec)\.(m?js|ts)$/.test(p)).length,
  };
}

const BUNDLES = [
  { domain: 'Enterprise ATT&CK', file: 'src/assets/data/enterprise-attack.json' },
  { domain: 'ICS ATT&CK', file: 'src/assets/data/ics-attack.json' },
  { domain: 'Mobile ATT&CK', file: 'src/assets/data/mobile-attack.json' },
  { domain: 'CTID F3 Fraud Framework', file: 'src/assets/data/f3-attack.json' },
];

function bundles(root) {
  return BUNDLES.map(({ domain, file }) => {
    const j = JSON.parse(read(root, file));
    const objects = Array.isArray(j.objects) ? j.objects : [];
    const coll = objects.find((o) => o.type === 'x-mitre-collection');
    const version = coll?.x_mitre_version ?? j['x-mitre-version'] ?? j.x_mitre_version;
    if (!version) throw new Error(`${file}: no x-mitre-collection x_mitre_version`);
    return { domain, file, version: String(version), objects: objects.length };
  });
}

function dataAssets(root) {
  const dir = 'src/assets/data';
  return readdirSync(join(root, dir)).sort().map((name) => {
    const rel = `${dir}/${name}`;
    return statSync(join(root, rel)).isDirectory()
      ? { path: `${rel}/`, files: walk(root, rel, () => true).length }
      : { path: rel };
  });
}

// Hosts that serve data feeds. Literals on other hosts (project pages, tool
// homepages, documentation links, example hosts used in tests) are not loaders.
const DATA_HOSTS = new Set([
  'raw.githubusercontent.com', 'api.github.com', 'gitlab.com', 'api.first.org',
  'services.nvd.nist.gov', 'www.cisa.gov', 'cveawg.mitre.org', 'd3fend.mitre.org',
]);

function upstreams(root) {
  const files = walk(root, 'src/app', (p) => p.endsWith('.ts') && !p.endsWith('.spec.ts'));
  const urls = new Map();
  const lit = /(['"`])(https?:\/\/[^'"`\s]+)\1?/g;
  for (const file of files) {
    const src = read(root, file);
    for (const m of src.matchAll(lit)) {
      let url = m[2];
      const tpl = url.indexOf('${');
      if (tpl >= 0) url = url.slice(0, tpl) + '…';
      let host;
      try { host = new URL(url.replace('…', '')).host; } catch { continue; }
      if (!DATA_HOSTS.has(host)) continue;
      if (host === 'gitlab.com' && !url.includes('/-/raw/')) continue;
      if (host === 'www.cisa.gov' && !url.includes('/feeds/')) continue;
      if (host === 'cveawg.mitre.org' && /CVE-\d{4}-\d+$/.test(url)) continue; // example record in a doc string
      if (host === 'd3fend.mitre.org' && !url.includes('/api/')) continue; // technique pages are links, not feeds
      if (/\.(ps1|sh)$/.test(url)) continue; // install scripts shown to the user, not fetched by the app
      if (!urls.has(url)) urls.set(url, new Set());
      urls.get(url).add(file);
    }
  }
  return [...urls.entries()]
    .map(([url, fs]) => ({ url, files: [...fs].sort() }))
    .sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
}

function libraryLayers(root) {
  const file = 'src/assets/data/library-layers/index.json';
  const idx = JSON.parse(read(root, file));
  if (!Array.isArray(idx)) throw new Error(`${file}: expected an array`);
  const lylatFile = 'src/assets/data/lylat-mission-layers/index.json';
  let lylat;
  if (existsSync(join(root, lylatFile))) {
    const l = JSON.parse(read(root, lylatFile));
    lylat = { source: lylatFile, count: Array.isArray(l) ? l.length : Array.isArray(l.layers) ? l.layers.length : undefined };
  }
  return { source: file, count: idx.length, lylatMissionLayers: lylat };
}

function toolchain(root) {
  const lock = JSON.parse(read(root, 'package-lock.json'));
  const v = (name) => lock.packages?.[`node_modules/${name}`]?.version;
  const out = { angular: v('@angular/core'), typescript: v('typescript'), rxjs: v('rxjs'), zoneJs: v('zone.js') };
  for (const [k, val] of Object.entries(out)) if (!val) throw new Error(`package-lock.json: no version for ${k}`);
  return { source: 'package-lock.json', ...out, angularMajor: Number(out.angular.split('.')[0]), typescriptMajor: Number(out.typescript.split('.')[0]) };
}

/** Truth-vocabulary lint result (scripts/lint-truth-vocab.mjs, plan 4.1). */
function truthVocab(root) {
  const { files, findings, allows } = lintRepo(root);
  return { files, findings: findings.length, allows };
}

export function collectFacts(root) {
  return {
    heatmap: heatmapModes(root),
    routes: routes(root),
    specs: specs(root),
    bundles: bundles(root),
    libraryLayers: libraryLayers(root),
    toolchain: toolchain(root),
    dataAssets: dataAssets(root),
    upstreams: upstreams(root),
    truthVocab: truthVocab(root),
  };
}

/** The flat numbers that scripts/check-facts.mjs compares the docs against. */
export function headline(f) {
  const bundle = Object.fromEntries(f.bundles.map((b) => [b.domain, b.version]));
  return {
    heatmapModes: f.heatmap.count,
    routedWorkspaces: f.routes.workspaceCount,
    routeFileWorkspaces: f.routes.routeFileWorkspaceCount,
    routedTabs: f.routes.tabCount,
    libraryLayers: f.libraryLayers.count,
    unitSpecs: f.specs.unitSpecFiles,
    angularMajor: f.toolchain.angularMajor,
    typescriptMajor: f.toolchain.typescriptMajor,
    bundleVersions: bundle,
  };
}

// ------------------------------------------------------------------- render

export function renderFacts(f) {
  const h = headline(f);
  const L = [];
  L.push('# Facts', '');
  L.push('<!-- Generated by scripts/gen-facts.mjs. Do not edit by hand: run `node scripts/gen-facts.mjs`. -->', '');
  L.push('Counts and versions derived from the code. When a document states one of these numbers, this file is the reference; `node scripts/check-facts.mjs` fails when README.md, ARCHITECTURE.md, HANDOFF.md or QUICKSTART.md disagree with it.', '');
  L.push('## Summary', '');
  L.push('| Fact | Value | Derived from |', '| :-- | --: | :-- |');
  L.push(`| Heatmap modes | ${h.heatmapModes} | \`${f.heatmap.source}\` (\`HEATMAP_MODES\`) |`);
  L.push(`| Routed workspaces (top-level routes, redirects excluded) | ${h.routedWorkspaces} | \`src/app/app.routes.ts\` |`);
  L.push(`| Workspaces that lazy-load a route file | ${h.routeFileWorkspaces} | \`loadChildren\` in \`src/app/app.routes.ts\` |`);
  L.push(`| Routed workspace tabs | ${h.routedTabs} | child routes with \`data.tab\` in \`src/app/pages/*/*.routes.ts\` |`);
  L.push(`| Library layers | ${h.libraryLayers} | \`${f.libraryLayers.source}\` |`);
  if (f.libraryLayers.lylatMissionLayers) L.push(`| Lylat mission layers | ${f.libraryLayers.lylatMissionLayers.count} | \`${f.libraryLayers.lylatMissionLayers.source}\` |`);
  L.push(`| Unit spec files | ${h.unitSpecs} | \`src/**/*.spec.ts\` |`);
  L.push(`| Playwright spec files | ${f.specs.e2eSpecFiles} | \`e2e/**/*.spec.ts\` |`);
  L.push(`| Script test files | ${f.specs.scriptTestFiles} | \`scripts/**/*.test.mjs\` |`);
  L.push(`| Proxy test files | ${f.specs.proxyTestFiles} | \`server/**/*.test.*\` |`);
  L.push(`| Angular | ${f.toolchain.angular} | \`package-lock.json\` (\`@angular/core\`) |`);
  L.push(`| TypeScript | ${f.toolchain.typescript} | \`package-lock.json\` |`);
  L.push(`| RxJS | ${f.toolchain.rxjs} | \`package-lock.json\` |`);
  L.push(`| zone.js | ${f.toolchain.zoneJs} | \`package-lock.json\` |`);
  if (f.truthVocab) {
    L.push(`| Truth-vocabulary lint findings | ${f.truthVocab.findings} | \`node scripts/lint-truth-vocab.mjs\` over ${f.truthVocab.files} files |`);
    L.push(`| Truth-vocabulary allow directives | ${f.truthVocab.allows} | inline allow comments in those files, each with its reason |`);
  }
  L.push('');
  L.push('Unit spec files are files, not test cases; Karma prints the test-case count for the commit it ran.', '');

  L.push('## Bundled ATT&CK and F3 snapshots', '');
  L.push('| Domain | Version | Objects | File |', '| :-- | --: | --: | :-- |');
  for (const b of f.bundles) L.push(`| ${b.domain} | ${b.version} | ${b.objects} | \`${b.file}\` |`);
  L.push('', 'Version is the `x_mitre_version` of the bundle\'s `x-mitre-collection` object.', '');

  L.push('## Heatmap modes', '');
  L.push('| # | Id | Short label | Group | Rung |', '| --: | :-- | :-- | :-- | :-- |');
  f.heatmap.modes.forEach((m, i) => L.push(`| ${i + 1} | \`${m.id}\` | ${m.short} | ${m.group} | ${m.rung} |`));
  L.push('');

  L.push('## Routes and tabs', '');
  L.push('| Workspace | Title | Loads | Tabs |', '| :-- | :-- | :-- | :-- |');
  for (const w of f.routes.workspaces) {
    const tabs = w.tabs.length ? `${w.tabs.length}: ${w.tabs.map((t) => `${t.tab} (\`${t.path}\`)`).join(', ')}` : '-';
    L.push(`| \`${w.path}\` | ${w.title ?? '-'} | ${w.kind === 'route file' ? `\`${w.routeFile}\`` : 'single component'} | ${tabs} |`);
  }
  L.push('');
  L.push(`Redirects: ${f.routes.redirects.map((r) => `\`${r.path === '' ? "''" : r.path}\` → \`${r.to}\``).join(', ')}.`);
  if (f.routes.unreferencedRouteFiles.length) L.push('', `Route files under \`src/app/pages\` that \`app.routes.ts\` does not load: ${f.routes.unreferencedRouteFiles.map((p) => `\`${p}\``).join(', ')}.`);
  L.push('');

  L.push('## Bundled data assets', '');
  L.push('Contents of `src/assets/data/`:', '');
  for (const a of f.dataAssets) L.push(`- \`${a.path}\`${a.files !== undefined ? ` (${a.files} files)` : ''}`);
  L.push('');

  L.push('## Upstream data URLs in the loaders', '');
  L.push(`URL literals in \`src/app/**/*.ts\` (specs excluded) on a data host (${[...DATA_HOSTS].sort().map((h) => `\`${h}\``).join(', ')}). \`…\` marks where a template expression follows. Links to project pages and documentation are not listed.`, '');
  L.push('| URL | Referenced in |', '| :-- | :-- |');
  for (const u of f.upstreams) L.push(`| \`${u.url}\` | ${u.files.map((p) => `\`${p.replace('src/app/', '')}\``).join(', ')} |`);
  L.push('');

  L.push('## Machine-readable', '');
  L.push('Read by `scripts/check-facts.mjs`.', '');
  L.push(JSON_START);
  L.push(JSON.stringify(headline(f), null, 2));
  L.push(JSON_END, '');
  return L.join('\n');
}

/** Parse the machine-readable block out of an existing docs/FACTS.md. */
export function parseFactsMarkdown(md) {
  const s = md.indexOf(JSON_START);
  const e = md.indexOf(JSON_END);
  if (s < 0 || e < 0) throw new Error(`${FACTS_PATH}: machine-readable block not found; run node scripts/gen-facts.mjs`);
  return JSON.parse(md.slice(s + JSON_START.length, e));
}

// ---------------------------------------------------------------------- CLI

function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const facts = collectFacts(root);
  if (argv.includes('--json')) { process.stdout.write(JSON.stringify(facts, null, 2) + '\n'); return 0; }
  const md = renderFacts(facts);
  const target = join(root, FACTS_PATH);
  if (argv.includes('--check')) {
    const current = existsSync(target) ? readFileSync(target, 'utf8').replace(/\r\n/g, '\n') : '';
    if (current !== md) { console.error(`${FACTS_PATH} is out of date: run node scripts/gen-facts.mjs`); return 1; }
    console.log(`${FACTS_PATH} is current.`);
    return 0;
  }
  writeFileSync(target, md);
  const h = headline(facts);
  console.log(`wrote ${FACTS_PATH}: ${h.heatmapModes} heatmap modes, ${h.routedWorkspaces} routed workspaces, ${h.routedTabs} tabs, ${h.libraryLayers} library layers, ${h.unitSpecs} unit spec files, Angular ${facts.toolchain.angular}`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exitCode = main(process.argv.slice(2));

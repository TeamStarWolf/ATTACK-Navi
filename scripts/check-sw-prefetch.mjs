#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Guards the service-worker cold-start invariant: a visitor's cached app shell must always be
// able to BOOT, even right after a deploy that replaced every hashed file.
//
// Why this check exists
// ---------------------
// The Angular service worker (ngsw) serves the cached index.html + its entry scripts first, then
// the app boots and the router dynamically imports the initial route's chunk(s). Those boot
// chunks reach the browser through runtime `import("./chunk-*.js")` calls whose targets depend on
// routing/redirects/guards — they are NOT present in index.html and NOT statically analyzable.
//
// If any application script is cached only `lazy` (cache-on-use), a FIRST visit — during which the
// page is not yet controlled by the worker, so those requests bypass the worker and never enter
// its cache — installs the shell ALONE. After the next deploy, the cached shell asks for chunk
// hashes that exist in no cache and no longer exist on the server: every such request 404s and the
// app never starts (a dead first load; a second load picks up the new build). The reload prompt
// cannot help, because the app must boot before it can show anything.
//
// Because the boot set cannot be derived from filenames or static imports, the only robust
// guarantee is that EVERY application script emitted by the build is in a `prefetch` asset group,
// i.e. cached at install. This check fails if any `*.js` in the built ngsw.json is not. That
// strictly implies the narrower "every static import of the entry is cached" property too.
//
// Usage:  node scripts/check-sw-prefetch.mjs [distDir] [--report]
//   distDir  defaults to dist/mitre-mitigation-navigator/browser
//   --report prints the per-group install-byte accounting and the entry static-import closure,
//            and does not change the pass/fail result.
import { readFileSync, statSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';

const DEFAULT_DIST = 'dist/mitre-mitigation-navigator/browser';
const args = process.argv.slice(2);
const report = args.includes('--report');
const distDir = resolve(args.find((a) => !a.startsWith('--')) ?? DEFAULT_DIST);

const ngswPath = join(distDir, 'ngsw.json');
const indexPath = join(distDir, 'index.html');
if (!existsSync(ngswPath)) {
  console.error(`check-sw-prefetch: ${ngswPath} not found — run a production build first.`);
  process.exit(2);
}

const ngsw = JSON.parse(readFileSync(ngswPath, 'utf8'));
const groups = ngsw.assetGroups ?? [];

/** url -> { group, installMode } for every asset ngsw tracks. */
const urlGroup = new Map();
for (const g of groups) {
  for (const url of g.urls ?? []) {
    if (!urlGroup.has(url)) urlGroup.set(url, { group: g.name, installMode: g.installMode });
  }
}

const isScript = (url) => url.endsWith('.js');
const prefetchGroups = new Set(groups.filter((g) => g.installMode === 'prefetch').map((g) => g.name));
const sizeOf = (url) => {
  try {
    return statSync(join(distDir, url.replace(/^\//, ''))).size;
  } catch {
    return 0;
  }
};

// --- The invariant: every application script must be in a prefetch group. ---
const scriptUrls = [...urlGroup.keys()].filter(isScript);
const offenders = scriptUrls.filter((url) => !prefetchGroups.has(urlGroup.get(url).group));

// --- Static-import closure of the entry scripts, for the report (and belt-and-braces). ---
function entryScripts() {
  if (!existsSync(indexPath)) return [];
  const html = readFileSync(indexPath, 'utf8');
  return [...html.matchAll(/<script[^>]*\ssrc="([^"]+\.js)"/g)].map((m) => '/' + m[1].replace(/^\.?\//, ''));
}
const staticImportsOf = (url) => {
  const file = join(distDir, url.replace(/^\//, ''));
  if (!existsSync(file)) return [];
  const code = readFileSync(file, 'utf8');
  const specs = new Set();
  // esbuild ESM, minified: `import"./x.js"` (side-effect) and `...from"./x.js"` are static;
  // `import("./x.js")` is dynamic and deliberately excluded.
  for (const m of code.matchAll(/(?:\bimport|\bfrom|\bexport\s*\*\s*from)\s*"(\.\/[^"]+\.js)"/g)) {
    specs.add('/' + m[1].replace(/^\.?\//, ''));
  }
  // Drop any that were actually the dynamic form `import("./x.js")`.
  const dynamic = new Set(
    [...code.matchAll(/\bimport\(\s*"(\.\/[^"]+\.js)"\s*\)/g)].map((m) => '/' + m[1].replace(/^\.?\//, '')),
  );
  for (const d of dynamic) if (!code.includes(`from"${'.' + d}"`) && !code.includes(`import"${'.' + d}"`)) specs.delete(d);
  return [...specs];
};
function staticClosure(entries) {
  const seen = new Set(entries);
  const stack = [...entries];
  while (stack.length) {
    const cur = stack.pop();
    for (const next of staticImportsOf(cur)) {
      if (!seen.has(next)) {
        seen.add(next);
        stack.push(next);
      }
    }
  }
  return seen;
}

if (report) {
  const fmt = (n) => (n / 1024).toFixed(1) + ' kB';
  console.log(`\nservice-worker prefetch report — ${distDir}`);
  let prefetchTotal = 0;
  for (const g of groups) {
    const total = (g.urls ?? []).reduce((s, u) => s + sizeOf(u), 0);
    const js = (g.urls ?? []).filter(isScript).length;
    if (g.installMode === 'prefetch') prefetchTotal += total;
    console.log(
      `  ${g.name.padEnd(12)} installMode=${g.installMode.padEnd(8)} files=${String((g.urls ?? []).length).padStart(3)} (js=${String(js).padStart(3)})  ${fmt(total).padStart(12)}`,
    );
  }
  console.log(`  --> install downloads (sum of prefetch groups): ${fmt(prefetchTotal)}`);
  const entries = entryScripts();
  const closure = staticClosure(entries);
  const closureScripts = [...closure].filter(isScript);
  const closureNonPrefetch = closureScripts.filter((u) => !prefetchGroups.has((urlGroup.get(u) || {}).group));
  console.log(`\n  entry scripts (index.html): ${entries.join(', ') || '(none found)'}`);
  console.log(`  entry static-import closure: ${closureScripts.length} script(s)`);
  if (closureNonPrefetch.length) {
    console.log(`  entry-closure scripts NOT prefetched: ${closureNonPrefetch.length}`);
    for (const u of closureNonPrefetch.slice(0, 10)) console.log(`    - ${u} (${urlGroup.get(u).group}/${urlGroup.get(u).installMode})`);
  }
  console.log(`\n  total application scripts in ngsw.json: ${scriptUrls.length}`);
  console.log(`  scripts NOT in a prefetch group: ${offenders.length}\n`);
}

if (offenders.length) {
  console.error(
    `check-sw-prefetch: ${offenders.length} application script(s) are not in a prefetch asset group, ` +
      `so a cached shell could fail to boot after a deploy. Move them into a prefetch group in ngsw-config.json:`,
  );
  for (const url of offenders.slice(0, 20)) {
    const { group, installMode } = urlGroup.get(url);
    console.error(`  - ${url}  (group "${group}", installMode "${installMode}")`);
  }
  if (offenders.length > 20) console.error(`  ... and ${offenders.length - 20} more`);
  process.exit(1);
}

console.log(`check-sw-prefetch: OK — all ${scriptUrls.length} application scripts are prefetched (${distDir}).`);

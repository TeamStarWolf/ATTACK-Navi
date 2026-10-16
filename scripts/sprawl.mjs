// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Static sprawl audit (plan epic E0.4). Reads the source only, no build and
// no network, and writes docs/SPRAWL.md:
//
//   1. entry points per routed tab: deep-link route, nav rail, workspace tab
//      bar, command palette, hotkey, technique sidebar, and other in-app links;
//   2. the duplicate feature groups from the plan's consolidate list, with
//      where each member lives today and how big it is;
//   3. spec depth per UI surface: test count, assertion count, smoke-only.
//
// Usage: node scripts/sprawl.mjs            (writes docs/SPRAWL.md)
//        node scripts/sprawl.mjs --stdout   (prints instead)
// Rerun after IA changes; E9.3's target is "duplicate feature groups <= 2".

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const APP = join(ROOT, 'src/app');
const args = process.argv.slice(2);
if (args.some((a) => a !== '--stdout')) throw new Error(`Unknown argument: ${args.join(' ')}`);

const read = (p) => readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
const rel = (p) => relative(ROOT, p).split('\\').join('/');
const lines = (p) => (existsSync(p) ? read(p).split('\n').length : 0);

// ── routes ───────────────────────────────────────────────────────────────────
/** Every routed tab: { route, workspace, tab, label, component (folder path) }. */
function routedTabs() {
  const top = read(join(APP, 'app.routes.ts'));
  const tabs = [];
  for (const m of top.matchAll(/path:\s*'([a-z-]+)',\s*\n\s*loadComponent:[^]*?import\('\.\/([^']+)'\)[^]*?data:\s*\{\s*title:\s*'([^']+)'/g)) {
    tabs.push({ route: `/${m[1]}`, workspace: `/${m[1]}`, tab: null, label: m[3], component: `src/app/${m[2]}`, isDefault: true });
  }
  const pages = join(APP, 'pages');
  for (const ws of readdirSync(pages).sort()) {
    const f = join(pages, ws, `${ws}.routes.ts`);
    if (!existsSync(f)) continue;
    const src = read(f);
    const def = src.match(/path:\s*'',\s*pathMatch:\s*'full',\s*redirectTo:\s*'([a-z-]+)'/)?.[1];
    for (const m of src.matchAll(/path:\s*'([a-z0-9-]+)',\s*\n\s*loadComponent:\s*\(\)\s*=>\s*\n?\s*import\('([^']+)'\)[^]*?data:\s*\{\s*tab:\s*'([^']+)'/g)) {
      const comp = resolve(join(pages, ws), m[2]);
      tabs.push({ route: `/${ws}/${m[1]}`, workspace: `/${ws}`, tab: m[1], label: m[3], component: rel(comp), isDefault: m[1] === def });
    }
  }
  return tabs;
}

// panel id -> route, from the single routing map every in-app link goes through.
function panelMap() {
  const src = read(join(APP, 'app.routes-map.ts'));
  const map = new Map();
  for (const m of src.matchAll(/^\s*'?([a-z0-9-]+)'?:\s*\[([^\]]+)\]/gm)) {
    const parts = [...m[2].matchAll(/'([^']+)'/g)].map((x) => x[1]);
    map.set(m[1], parts.join('/').replace(/\/{2,}/g, '/'));
  }
  return map;
}

// ── entry points ─────────────────────────────────────────────────────────────
function collectEntryPoints(tabs, panels) {
  const byRoute = new Map(tabs.map((t) => [t.route, { route: 1, rail: 0, tabBar: t.tab ? 1 : 0, palette: [], hotkey: [], sidebar: [], other: [] }]));
  const resolveRoute = (r) => {
    if (byRoute.has(r)) return r;
    const t = tabs.find((x) => x.workspace === r && x.isDefault);
    return t?.route ?? null;
  };
  const add = (route, kind, what) => {
    const r = resolveRoute(route);
    if (r) byRoute.get(r)[kind].push(what);
  };

  // Nav rail: catalog routes land on the workspace's default tab; Settings is a separate rail link.
  const rail = read(join(APP, 'components/nav-rail/nav-rail.component.ts'));
  const railTpl = read(join(APP, 'components/nav-rail/nav-rail.component.html'));
  const railRoutes = new Set([...rail.matchAll(/route:\s*'(\/[a-z-]+)'/g)].map((m) => m[1]));
  for (const m of railTpl.matchAll(/routerLink="(\/[a-z-]+)"/g)) railRoutes.add(m[1]);
  for (const r of railRoutes) {
    const t = resolveRoute(r);
    if (t) byRoute.get(t).rail = 1;
  }

  // Command palette: "Go to" commands plus entity results that open a tab.
  const cmds = read(join(APP, 'models/palette-commands.ts'));
  for (const m of cmds.matchAll(/\{\s*panelId:\s*'([^']+)',\s*label:\s*'([^']+)'/g)) {
    if (panels.has(m[1])) add(panels.get(m[1]), 'palette', `"${m[2]}"`);
  }
  const search = read(join(APP, 'components/universal-search/universal-search.component.ts'));
  for (const m of search.matchAll(/kind === '([a-z]+)'[^\n]*\n(?:[^\n]*\n){0,2}?[^\n]*panelNav\.open\('([^']+)'\)/g)) {
    if (panels.has(m[2])) add(panels.get(m[2]), 'palette', `${m[1]} result`);
  }

  // Hotkeys: single keys in HotkeysService that open or toggle a tab.
  const hk = read(join(APP, 'services/hotkeys.service.ts'));
  for (const m of hk.matchAll(/case '([^']+)':\s*\n(?:[^\n]*\n)?\s*this\.panelNav\.(?:open|toggle)\('([^']+)'\)/g)) {
    if (panels.has(m[2])) add(panels.get(m[2]), 'hotkey', `\`${m[1]}\``);
  }

  // Sidebar (technique detail) and every other component or page.
  const callRe = /(?:panelNav\.(?:open|toggle)|openPanel)\('([a-z0-9-]+)'\)|panel:\s*'([a-z0-9-]+)'/g;
  const routeRe = /route:\s*\[\s*'(\/[a-z-]+)'(?:\s*,\s*'([a-z0-9-]+)')?\s*\]|routerLink="(\/[a-z-]+(?:\/[a-z0-9-]+)?)"/g;
  const skip = ['components/nav-rail', 'components/universal-search', 'layout/workspace-shell'];
  for (const file of walk(APP)) {
    const r = rel(file).replace(/^src\/app\//, '');
    if (!/\.(ts|html)$/.test(file) || file.endsWith('.spec.ts') || skip.some((s) => r.startsWith(s))) continue;
    if (/^(services|models|app\.routes|pages\/[a-z]+\/[a-z]+\.routes)/.test(r)) continue;
    const src = read(file);
    const kind = r.startsWith('components/sidebar/') ? 'sidebar' : 'other';
    const owner = r.startsWith('pages/') ? r.split('/').pop().replace(/\.component\.(ts|html)$/, '') : r.split('/').slice(0, -1).pop() ?? r;
    for (const m of src.matchAll(callRe)) {
      const id = m[1] ?? m[2];
      if (panels.has(id)) add(panels.get(id), kind, owner);
    }
    for (const m of src.matchAll(routeRe)) {
      const route = m[3] ?? (m[2] ? `${m[1]}/${m[2]}` : m[1]);
      if (r.startsWith('components/toolbar/') && route === '/matrix') { add(route, 'other', 'toolbar (brand link)'); continue; }
      add(route, kind, owner);
    }
  }
  return byRoute;
}

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else yield p;
  }
}

// ── surfaces and spec depth ──────────────────────────────────────────────────
function surfaces() {
  const out = [];
  for (const d of readdirSync(join(APP, 'components')).sort()) out.push({ name: d, dir: join(APP, 'components', d), kind: 'component' });
  for (const d of readdirSync(join(APP, 'layout')).sort()) out.push({ name: d, dir: join(APP, 'layout', d), kind: 'layout' });
  for (const ws of readdirSync(join(APP, 'pages')).sort()) {
    for (const f of readdirSync(join(APP, 'pages', ws)).filter((x) => /\.component\.ts$/.test(x))) {
      out.push({ name: f.replace('.component.ts', ''), dir: join(APP, 'pages', ws), kind: 'page', stem: f.replace('.ts', '') });
    }
  }
  return out.map((s) => {
    const files = readdirSync(s.dir).filter((f) => !s.stem || f.startsWith(s.stem));
    const ts = files.filter((f) => f.endsWith('.ts') && !f.endsWith('.spec.ts'));
    const html = files.filter((f) => f.endsWith('.html'));
    const specs = files.filter((f) => f.endsWith('.spec.ts'));
    let tests = 0, assertions = 0, trivial = 0;
    for (const f of specs) {
      const src = read(join(s.dir, f));
      tests += [...src.matchAll(/\b(?:it|fit)\(\s*['"`]/g)].length;
      assertions += [...src.matchAll(/\bexpect\(/g)].length;
      trivial += [...src.matchAll(/\bexpect\(\s*[\w.]+\s*\)\s*\.(?:not\.)?(?:toBeTruthy|toBeDefined)\(\s*\)/g)].length;
    }
    const loc = [...ts, ...html].reduce((a, f) => a + lines(join(s.dir, f)), 0);
    return {
      ...s,
      path: rel(s.dir) + (s.stem ? `/${s.stem}` : ''),
      loc,
      specFiles: specs.length,
      tests,
      assertions,
      meaningful: assertions - trivial,
      depth: specs.length === 0 ? 'none' : assertions - trivial === 0 ? 'smoke-only' : assertions - trivial < 5 ? 'shallow' : 'tested',
    };
  });
}

// ── duplicate feature groups (plan section 5 "consolidate", plus section 2) ──
const GROUPS = [
  { name: 'CVE decision (SSVC computed in three panels)', members: ['cve-panel', 'dossier-panel', 'ssvc-panel'], into: '#/cve/:id and Exposure > Inbox', epic: 'E5.1' },
  { name: "'Which mitigation next' views", members: ['priority-panel', 'target-panel', 'roadmap-panel', 'whatif-panel', 'risk-matrix-panel'], into: 'Exposure > Plan', epic: 'E5.5' },
  { name: 'Gap finders', members: ['gap-view', 'gap-analysis-panel', 'coverage-breakdown'], into: 'Gap overlay + Detect > Gaps', epic: 'E2.2, E7.2' },
  { name: 'Detection-readiness formulas', members: ['detection-panel', 'purple-team-panel'], into: 'Detect > Coverage; scorecard into Validation', epic: 'E6.3' },
  { name: 'Detection content exporters', members: ['sigma-export', 'siem-export', 'yara-export'], into: 'Detect > Content builder', epic: 'E1.6, E7.1' },
  { name: 'Actor lists and compare panels', members: ['threat-panel', 'actor-profile-panel', 'actor-compare-panel', 'comparison-panel'], into: 'Threats > Actors + #/actor/:id', epic: 'E7.3' },
  { name: 'Planners whose output never fed validation', members: ['scenario-panel', 'emulation-plan-panel', 'purple-team-panel'], into: 'Threats > Emulate', epic: 'E7.3' },
  { name: 'Posture over time (diff, kill chain rollup)', members: ['coverage-diff-panel', 'killchain-panel', 'timeline-panel'], into: 'Posture > Trend', epic: 'E9.2' },
  { name: "'What you said you have'", members: ['custom-mit-panel', 'controls-panel'], into: 'Posture > Stack', epic: 'E6.1' },
  { name: 'Layer stores and catalogs', members: ['layers-panel', 'collection-panel', 'export-hub', 'services/layers.service.ts', 'services/user-layer.service.ts'], into: 'Library > Layers (UserLayerService)', epic: 'E6.6' },
  { name: 'Personal state next to the reference index', members: ['watchlist-panel', 'tags-panel', 'services/annotation.service.ts'], into: 'Library > Mine + My items drawer', epic: 'E4.7' },
  { name: 'Summary dashboards with their own numbers', members: ['dashboard-panel', 'analytics-panel'], into: 'Home tiles + Executive one-pager', epic: 'E4.2, E9.3' },
  { name: 'Tactic-coverage renderings', members: ['stats-bar', 'tactic-summary'], into: 'TacticRollup on PostureService', epic: 'E1.7, E9.3' },
  { name: 'Report engines (plan section 2)', members: ['report-panel', 'services/html-report.service.ts', 'services/pdf-report.service.ts'], into: 'one report engine', epic: 'E9.3' },
];

// ── report ───────────────────────────────────────────────────────────────────
function main() {
  const tabs = routedTabs();
  const panels = panelMap();
  const entries = collectEntryPoints(tabs, panels);
  const surf = surfaces();
  const surfByName = new Map(surf.map((s) => [s.name, s]));
  const compToRoutes = new Map();
  for (const t of tabs) {
    const name = t.component.split('/').pop().replace(/\.component$/, '');
    compToRoutes.set(name, [...(compToRoutes.get(name) ?? []), t.route]);
  }
  const out = [];
  const p = (s = '') => out.push(s);
  const ws = new Set(tabs.map((t) => t.workspace));

  p('# Sprawl audit');
  p();
  p('Static baseline for plan epic E0.4. Generated by `node scripts/sprawl.mjs` from the source (no build, no network); do not edit by hand, rerun the script.');
  p();
  p('## Summary');
  p();
  const totals = [...entries.values()].map((e) => entryTotal(e));
  const present = GROUPS.map((g) => g.members.filter((m) => memberExists(m, surfByName)).length);
  const smoke = surf.filter((s) => s.depth === 'smoke-only').length;
  const withSpec = surf.filter((s) => s.specFiles > 0).length;
  p('| Measure | Value |');
  p('|---|---|');
  p(`| Top-level routes / routed tabs | ${ws.size} / ${tabs.filter((t) => t.tab).length} workspace tabs (plus the single-page matrix and status routes) |`);
  p(`| UI surfaces | ${surf.length} (${surf.filter((s) => s.kind === 'component').length} component folders, ${surf.filter((s) => s.kind === 'page').length} page components, ${surf.filter((s) => s.kind === 'layout').length} layout components) |`);
  const noPalette = [...entries].filter(([, e]) => e.palette.length === 0).map(([r]) => `\`#${r}\``);
  const bare = [...entries].filter(([, e]) => entryTotal(e) - e.route - e.tabBar - e.rail === 0).map(([r]) => `\`#${r}\``);
  p(`| Routes with no palette command | ${noPalette.length}: ${noPalette.join(', ')} |`);
  p(`| Routes reachable only by deep link, rail or tab bar | ${bare.length}: ${bare.join(', ')} |`);
  p(`| Entry points per routed tab (min / median / max) | ${Math.min(...totals)} / ${median(totals)} / ${Math.max(...totals)} |`);
  p(`| Duplicate feature groups with two or more members still present | ${present.filter((n) => n >= 2).length} of ${GROUPS.length} listed |`);
  p(`| Surfaces with a spec / smoke-only specs / no spec | ${withSpec} / ${smoke} / ${surf.length - withSpec} |`);
  p();
  p('The plan headline counts 12 duplicate feature groups; this audit lists the 13 consolidate rows of plan section 5 plus the report engines from section 2, so the rerunnable figure is the "still present" count above.');
  p();

  p('## Entry points per routed tab');
  p();
  p('Columns: **Route** a deep link always exists; **Rail** the nav rail lands on this tab; **Tabs** the workspace tab bar; **Palette** Ctrl+K "Go to" commands and entity results; **Hotkey** single-key shortcuts in HotkeysService; **Sidebar** links from the technique sidebar; **Other** links from other components and pages. Each source is counted once per tab, however many call sites it has. All panel ids resolve through `app.routes-map.ts`.');
  p();
  p('| Route | Tab | Rail | Tabs | Palette | Hotkey | Sidebar | Other | Total |');
  p('|---|---|---|---|---|---|---|---|---|');
  for (const t of tabs) {
    const e = entries.get(t.route);
    const list = (xs) => {
      const u = [...new Set(xs)];
      return u.length ? `${u.length}: ${u.join(', ')}` : '0';
    };
    p(`| \`#${t.route}\` | ${t.label} | ${e.rail} | ${e.tabBar} | ${list(e.palette)} | ${list(e.hotkey)} | ${list(e.sidebar)} | ${list(e.other)} | ${entryTotal(e)} |`);
  }
  p();

  p('## Duplicate feature groups');
  p();
  p('From the plan\'s consolidate list. A member is a component folder (or a service where the duplicate is a store or engine). Lines are TypeScript plus HTML, without specs.');
  p();
  p('| Group | Members present | Members (routed tab, lines, spec assertions) | Becomes | Epic |');
  p('|---|---|---|---|---|');
  GROUPS.forEach((g, i) => {
    const desc = g.members.map((m) => {
      if (m.startsWith('services/')) {
        const f = join(APP, m);
        return existsSync(f) ? `${m} (${lines(f)} lines)` : `${m} (gone)`;
      }
      const s = surfByName.get(m);
      if (!s) return `${m} (gone)`;
      const routes = compToRoutes.get(m) ?? [];
      return `${m} (${routes.length ? routes.map((r) => `\`#${r}\``).join(' ') : 'embedded'}, ${s.loc} lines, ${s.assertions})`;
    });
    p(`| ${g.name} | ${present[i]} of ${g.members.length} | ${desc.join('<br>')} | ${g.into} | ${g.epic} |`);
  });
  p();

  p('## Spec depth per UI surface');
  p();
  p('**Assertions** counts `expect(` calls; **meaningful** excludes `expect(x).toBeTruthy()` and `toBeDefined()` on a bare reference. **Depth**: none (no spec), smoke-only (no meaningful assertion), shallow (1-4), tested (5 or more).');
  p();
  p('| Surface | Kind | Routed at | Lines | Specs | Tests | Assertions | Meaningful | Depth |');
  p('|---|---|---|---|---|---|---|---|---|');
  for (const s of surf) {
    const routes = compToRoutes.get(s.name) ?? [];
    p(`| ${s.path} | ${s.kind} | ${routes.length ? routes.map((r) => `\`#${r}\``).join(' ') : '-'} | ${s.loc} | ${s.specFiles} | ${s.tests} | ${s.assertions} | ${s.meaningful} | ${s.depth} |`);
  }
  p();
  const byDepth = surf.reduce((a, s) => ({ ...a, [s.depth]: (a[s.depth] ?? 0) + 1 }), {});
  p(`Depth totals: ${Object.entries(byDepth).map(([k, v]) => `${k} ${v}`).join(', ')}.`);
  p();
  return out.join('\n');
}

function entryTotal(e) {
  const n = (xs) => new Set(xs).size;
  return e.route + e.rail + e.tabBar + n(e.palette) + n(e.hotkey) + n(e.sidebar) + n(e.other);
}
function memberExists(m, surfByName) {
  return m.startsWith('services/') ? existsSync(join(APP, m)) : surfByName.has(m);
}
function median(xs) {
  const v = [...xs].sort((a, b) => a - b);
  const m = Math.floor(v.length / 2);
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

const md = main() + '\n';
if (args.includes('--stdout')) process.stdout.write(md);
else {
  writeFileSync(join(ROOT, 'docs/SPRAWL.md'), md);
  console.log('wrote docs/SPRAWL.md');
}

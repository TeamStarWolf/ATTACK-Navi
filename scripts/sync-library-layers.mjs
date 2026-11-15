#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Keeps the Library Layers picker in step with the TeamStarWolf library: every
// ATT&CK Navigator layer the library publishes under https://teamstarwolf.com/navigator/
// becomes a library layer here, grouped, with its source address and sha256 in a
// lock file.
//
//   node scripts/sync-library-layers.mjs                pull from the live site and write
//   node scripts/sync-library-layers.mjs --check        offline: lock, files, index and docs agree
//   node scripts/sync-library-layers.mjs --docs         offline: rewrite the generated doc sections
//   node scripts/sync-library-layers.mjs --report FILE  also write the Markdown sync report to FILE
//
// What it pulls: the published set (navigator/library-layers/index.json and every
// file it names) and every other layer under navigator/ (case-studies, vendors,
// stages, computed, analytics, ai, fraud and the loose files at the top), listed
// from the library repository's file tree.
//
// What it writes, all under src/assets/data/library-layers/:
//   - each synced layer, byte for byte as served (line endings normalized to LF),
//     under a group prefix (study-, actor-, vendor-, stage-, computed-, analytics-,
//     ai-, fraud-) so it never collides with a bundled file;
//   - index.json: the bundled entries untouched apart from a `group`, then the
//     synced entries, each with `group` and `source`;
//   - library-sync.json, the lock: synced date, the source index's sha256, and for
//     each synced file its source address, sha256 and the rows the bundled ATT&CK
//     data cannot resolve (unknown ids, retired ids, tactic mismatches). Nothing
//     is dropped: a layer naming an id the bundled data does not know is kept and
//     the id is recorded here, so the owner can decide on an ATT&CK data refresh.
// It also rewrites the generated block of docs/LIBRARY_LAYERS.md and the layer
// counts in that guide and in docs/README.md.
//
// Duplicates: a library layer with the same name as a bundled layer, or with the
// same rows (domain, technique, tactic, score) as a layer already kept, is not
// added; the published-set copy wins over a copy in another folder, and the
// bundled copy wins over both. Every duplicate is recorded in the lock.
//
// Sha256 values are of the LF-normalized text, so a Windows checkout with
// core.autocrlf verifies the same as Linux CI.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SITE = 'https://teamstarwolf.com/navigator/';
export const TREE = 'https://api.github.com/repos/TeamStarWolf/TeamStarWolf/git/trees/main?recursive=1';
export const LAYER_DIR = 'src/assets/data/library-layers';
export const INDEX = 'index.json';
export const LOCK = 'library-sync.json';
export const DOC = 'docs/LIBRARY_LAYERS.md';
export const DOCS_README = 'docs/README.md';
export const DOC_START = '<!-- library-sync:start -->';
export const DOC_END = '<!-- library-sync:end -->';

/** Groups of the bundled layers, in picker order. */
export const BUNDLED_GROUPS = ['Curated themes', 'Threat groups', 'HTB frequency', 'Agentic AI', 'Lylat'];
/** Groups of the synced layers, in picker order, after the bundled ones. */
export const SYNCED_GROUPS = ['Case studies', 'Threat actors', 'Vendors', 'Kill-chain stages', 'Computed', 'Analytics', 'AI', 'Fraud'];
export const GROUP_ORDER = [...BUNDLED_GROUPS, ...SYNCED_GROUPS];

/** The file-name prefix of each synced group. */
export const GROUP_PREFIX = {
  'Case studies': 'study-',
  'Threat actors': 'actor-',
  Vendors: 'vendor-',
  'Kill-chain stages': 'stage-',
  Computed: 'computed-',
  Analytics: 'analytics-',
  AI: 'ai-',
  Fraud: 'fraud-',
};

/** Library folders under navigator/ other than the published set, and their group. */
export const FOLDER_GROUP = {
  'case-studies': 'Case studies',
  vendors: 'Vendors',
  stages: 'Kill-chain stages',
  computed: 'Computed',
  analytics: 'Analytics',
  ai: 'AI',
  fraud: 'Fraud',
  // Loose layer files directly under navigator/ (today the NIST 800-53 control-depth layer).
  '': 'Computed',
};

/** A layer whose name says it is about threat actors goes to Threat actors, not Case studies. */
export const ACTOR_NAME = /\bthreat actors?\b|\bstate-linked\b/i;

/** The group a bundled (unsynced) manifest entry belongs to, from its file name. */
export function bundledGroup(file) {
  if (file.startsWith('group-')) return 'Threat groups';
  if (file.startsWith('htb-')) return 'HTB frequency';
  if (file.startsWith('agentic-')) return 'Agentic AI';
  if (file.startsWith('lylat-')) return 'Lylat';
  return 'Curated themes';
}

export const sha256 = (text) => createHash('sha256').update(text).digest('hex');
export const lf = (text) => text.replace(/\r\n/g, '\n');

/** The served file name for a library file: group prefix, lower case, [a-z0-9-] only. */
export function targetName(group, sourceFile) {
  const base = sourceFile.replace(/\.json$/i, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return `${GROUP_PREFIX[group]}${base}.json`;
}

/** Display name without the library's "TeamStarWolf - " prefix (the picker does the same). */
export const layerLabel = (name) => name.replace(/^TeamStarWolf\s*[-\u2013]\s*/, '');

// ─── Layer validation ─────────────────────────────────────────────────────────

/**
 * Problems that make a file unusable as a Navigator layer here: no name, no
 * domain, no layer version, no techniques array, a row without a techniqueID, a
 * tactic or score of the wrong type. A missing tactic is allowed (Navigator
 * applies the score to every tactic of the technique) and counted in the lock.
 */
export function validateLayer(layer) {
  const problems = [];
  if (!layer || typeof layer !== 'object' || Array.isArray(layer)) return ['not a JSON object'];
  if (typeof layer.name !== 'string' || !layer.name.trim()) problems.push('no name');
  if (typeof layer.domain !== 'string' || !layer.domain.trim()) problems.push('no domain');
  if (!layer.versions || typeof layer.versions !== 'object' || typeof layer.versions.layer !== 'string') problems.push('no versions.layer');
  if (!Array.isArray(layer.techniques)) problems.push('no techniques array');
  else {
    layer.techniques.forEach((row, i) => {
      if (!row || typeof row.techniqueID !== 'string' || !row.techniqueID.trim()) problems.push(`techniques[${i}]: no techniqueID`);
      else if (row.tactic !== undefined && typeof row.tactic !== 'string') problems.push(`techniques[${i}]: tactic is not a string`);
      else if (row.score !== undefined && row.score !== null && typeof row.score !== 'number') problems.push(`techniques[${i}]: score is not a number`);
    });
    if (!layer.techniques.length) problems.push('no techniques');
  }
  return problems;
}

/** Distinct technique ids in a layer. */
export const distinctIds = (layer) => new Set(layer.techniques.map((t) => t.techniqueID)).size;

/** Rows identity used for de-duplication: domain plus the sorted technique/tactic/score rows. */
export function rowsKey(layer) {
  const rows = [...new Set(layer.techniques.map((t) => `${t.techniqueID}|${t.tactic ?? ''}|${t.score ?? ''}`))].sort();
  return `${layer.domain}\n${rows.join('\n')}`;
}

// ─── Bundled ATT&CK data ──────────────────────────────────────────────────────

/** Bundled snapshots: the domain key a layer's domain resolves against. */
export const BUNDLE_FILES = {
  enterprise: 'src/assets/data/enterprise-attack.json',
  ics: 'src/assets/data/ics-attack.json',
  mobile: 'src/assets/data/mobile-attack.json',
  f3: 'src/assets/data/f3-attack.json',
};

/** The bundles a layer domain resolves against; null when no bundled matrix exists (ATLAS). */
export function bundlesFor(domain) {
  if (domain === 'enterprise-attack') return ['enterprise'];
  if (domain === 'ics-attack') return ['ics'];
  if (domain === 'mobile-attack') return ['mobile'];
  if (/^f3/.test(domain)) return ['f3', 'enterprise'];
  return null;
}

/** Live techniques (id -> tactics) and retired ones (id -> successor id or null) of one bundle. */
export function indexBundle(bundle) {
  const objects = bundle.objects ?? [];
  const idOf = (o) => (o.external_references ?? []).find((r) => /^mitre-/.test(r?.source_name ?? '') && typeof r.external_id === 'string')?.external_id;
  const byStix = new Map(objects.filter((o) => o.type === 'attack-pattern').map((o) => [o.id, o]));
  const revokedBy = new Map(objects
    .filter((o) => o.type === 'relationship' && o.relationship_type === 'revoked-by')
    .map((o) => [o.source_ref, o.target_ref]));
  const live = new Map();
  const retired = new Map();
  for (const o of byStix.values()) {
    const id = idOf(o);
    if (!id) continue;
    if (o.revoked || o.x_mitre_deprecated) {
      const target = byStix.get(revokedBy.get(o.id));
      retired.set(id, target ? idOf(target) ?? null : null);
    } else {
      live.set(id, (o.kill_chain_phases ?? []).map((p) => p.phase_name).sort());
    }
  }
  const version = objects.find((o) => o.type === 'x-mitre-collection')?.x_mitre_version ?? null;
  return { live, retired, version };
}

export function loadBundles(root) {
  const out = {};
  for (const [key, file] of Object.entries(BUNDLE_FILES)) {
    out[key] = indexBundle(JSON.parse(readFileSync(join(root, file), 'utf8')));
  }
  return out;
}

/**
 * Rows of a layer the bundled data cannot resolve. ATLAS ids (AML.*) and layers
 * of a domain with no bundled matrix are counted as unchecked, not as unknown.
 */
export function resolveLayer(layer, bundles) {
  const keys = bundlesFor(layer.domain);
  const unknown = new Set();
  const retired = new Map();
  const tactics = new Map();
  let noTactic = 0;
  let unchecked = 0;
  for (const row of layer.techniques) {
    if (!row.tactic) noTactic += 1;
    if (!keys || row.techniqueID.startsWith('AML.')) { unchecked += 1; continue; }
    const hit = keys.map((k) => bundles[k]).find((b) => b.live.has(row.techniqueID));
    if (hit) {
      const has = hit.live.get(row.techniqueID);
      if (row.tactic && !has.includes(row.tactic)) tactics.set(`${row.techniqueID}|${row.tactic}`, { id: row.techniqueID, tactic: row.tactic, bundled: has });
      continue;
    }
    const gone = keys.map((k) => bundles[k]).find((b) => b.retired.has(row.techniqueID));
    if (gone) retired.set(row.techniqueID, gone.retired.get(row.techniqueID));
    else unknown.add(row.techniqueID);
  }
  const out = {};
  if (unknown.size) out.unknown = [...unknown].sort();
  if (retired.size) out.retired = [...retired].sort(([a], [b]) => (a < b ? -1 : 1)).map(([id, successor]) => ({ id, successor }));
  if (tactics.size) out.tacticMismatch = [...tactics.values()].sort((a, b) => (`${a.id}|${a.tactic}` < `${b.id}|${b.tactic}` ? -1 : 1));
  if (noTactic) out.noTactic = noTactic;
  if (unchecked) out.unchecked = unchecked;
  return out;
}

// ─── Fetching ─────────────────────────────────────────────────────────────────

const UA = 'ATTACK-Navi library-layer sync (+https://github.com/TeamStarWolf/ATTACK-Navi)';

async function fetchText(url, headers = {}) {
  let last;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': UA, ...headers }, signal: AbortSignal.timeout(60000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (err) {
      last = err;
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
  throw new Error(`${url}: ${last?.message ?? last}`);
}

/** The library's navigator/ layer files outside the published set, from its git tree. */
export function extraPaths(tree) {
  if (tree.truncated) throw new Error('library tree listing is truncated');
  const out = [];
  const unmapped = [];
  for (const item of tree.tree ?? []) {
    if (item.type !== 'blob' || !/^navigator\/.+\.json$/i.test(item.path)) continue;
    const rel = item.path.slice('navigator/'.length);
    const parts = rel.split('/');
    if (parts[0] === 'library-layers') continue; // the published set comes from its index
    const folder = parts.length === 1 ? '' : parts[0];
    if (parts.length > 2 || !(folder in FOLDER_GROUP)) { unmapped.push(rel); continue; }
    out.push({ rel, folder, file: parts[parts.length - 1] });
  }
  // Folder order of FOLDER_GROUP, then file name, so the output is stable.
  const order = Object.keys(FOLDER_GROUP);
  out.sort((a, b) => order.indexOf(a.folder) - order.indexOf(b.folder) || (a.rel < b.rel ? -1 : 1));
  return { paths: out, unmapped: unmapped.sort() };
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  }));
  return out;
}

/** Everything the library publishes: candidates in priority order (published set first). */
export async function pullLibrary() {
  const indexUrl = `${SITE}library-layers/${INDEX}`;
  const indexText = lf(await fetchText(indexUrl, { accept: 'application/json' }));
  const published = JSON.parse(indexText);
  const list = Array.isArray(published) ? published : published.layers;
  if (!Array.isArray(list)) throw new Error(`${indexUrl}: no layer list`);
  const ghToken = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  const tree = JSON.parse(await fetchText(TREE, {
    accept: 'application/vnd.github+json',
    ...(ghToken ? { authorization: `Bearer ${ghToken}` } : {}),
  }));
  const { paths, unmapped } = extraPaths(tree);

  const jobs = [
    ...list.map((entry) => ({ kind: 'published', rel: `library-layers/${entry.file}`, file: entry.file, entry })),
    ...paths.map((p) => ({ kind: 'extra', rel: p.rel, file: p.file, folder: p.folder })),
  ];
  const candidates = await mapLimit(jobs, 8, async (job) => {
    const source = `${SITE}${job.rel}`;
    const text = lf(await fetchText(source, { accept: 'application/json' }));
    return { ...job, source, text };
  });
  return {
    indexUrl,
    indexSha256: sha256(indexText),
    indexVersion: Array.isArray(published) ? null : (published.version ?? null),
    candidates,
    unmapped,
  };
}

// ─── Planning ─────────────────────────────────────────────────────────────────

/**
 * Decide what to keep. `bundled` is the manifest entries that are not synced
 * (with their parsed layer files); `candidates` is the pull in priority order.
 */
export function plan(bundled, candidates, bundles) {
  const keptNames = new Map(bundled.map((b) => [b.entry.name, { file: b.entry.file, bundled: true }]));
  const keptRows = new Map(bundled.map((b) => [rowsKey(b.layer), { file: b.entry.file, bundled: true }]));
  const bundledFiles = new Set(bundled.map((b) => b.entry.file));
  const kept = [];
  const duplicates = [];
  const invalid = [];
  const usedTargets = new Set();

  for (const c of candidates) {
    let layer;
    try { layer = JSON.parse(c.text); } catch (err) { invalid.push({ source: c.source, problems: [`not JSON: ${err.message}`] }); continue; }
    const problems = validateLayer(layer);
    if (problems.length) { invalid.push({ source: c.source, problems: problems.slice(0, 5) }); continue; }

    const group = c.kind === 'published'
      ? (ACTOR_NAME.test(layer.name) ? 'Threat actors' : 'Case studies')
      : (FOLDER_GROUP[c.folder] === 'Case studies' && ACTOR_NAME.test(layer.name) ? 'Threat actors' : FOLDER_GROUP[c.folder]);
    const sameName = keptNames.get(layer.name);
    const sameRows = keptRows.get(rowsKey(layer));
    if (sameName || sameRows) {
      const other = sameName ?? sameRows;
      duplicates.push({
        source: c.source,
        name: layer.name,
        techniques: distinctIds(layer),
        reason: sameName ? 'same name' : 'same rows',
        keptAs: other.file,
        keptFrom: other.bundled ? 'bundled' : other.source,
      });
      continue;
    }
    const file = targetName(group, c.file);
    if (bundledFiles.has(file) || usedTargets.has(file)) throw new Error(`${c.source}: served name ${file} collides with another layer`);
    usedTargets.add(file);
    const entry = {
      file,
      name: layer.name,
      description: (c.entry?.description ?? layer.description ?? '').trim(),
      ...(c.entry?.blurb ? { blurb: c.entry.blurb } : {}),
      group,
      source: c.source,
    };
    const record = { file, group, source: c.source, sha256: sha256(c.text), domain: layer.domain, techniques: distinctIds(layer), ...resolveLayer(layer, bundles) };
    kept.push({ entry, record, text: c.text, layer });
    keptNames.set(layer.name, { file, source: c.source });
    keptRows.set(rowsKey(layer), { file, source: c.source });
  }

  const order = (e) => SYNCED_GROUPS.indexOf(e.group);
  kept.sort((a, b) => order(a.entry) - order(b.entry) || a.entry.name.localeCompare(b.entry.name, 'en'));
  return { kept, duplicates, invalid };
}

// ─── Index, lock and docs ─────────────────────────────────────────────────────

export const serialize = (value) => `${JSON.stringify(value, null, 2)}\n`;

/** Bundled entries (no `source`) keep their fields and order; `group` is added when missing. */
export function bundledEntries(index) {
  return index.filter((e) => !e.source).map((e) => (e.group ? e : { ...e, group: bundledGroup(e.file) }));
}

/** Text safe inside a Markdown table cell: backslashes first, then pipes. */
export const tableCell = (text) => text.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');

/** Markdown-table-safe one-line note from a blurb or description. */
export function noteFor(entry, record) {
  const text = (entry.blurb || entry.description || '').replace(/\s+/g, ' ').trim();
  let sentence = text.match(/^.*?[.!?](?=\s|$)/)?.[0] ?? text;
  if (sentence.length > 180) sentence = `${sentence.slice(0, 180).replace(/[\s,;:(]+\S*$/, '')}...`;
  else if (sentence && !/[.!?]$/.test(sentence)) sentence += '.';
  const parts = [sentence];
  const domain = { 'ics-attack': 'ICS ATT&CK layer', 'mobile-attack': 'Mobile ATT&CK layer' }[record.domain]
    ?? (/atlas/.test(record.domain) ? 'ATLAS layer: no bundled matrix renders it' : /^f3/.test(record.domain) ? 'F3 fraud layer' : null);
  if (domain) parts.push(`${domain}.`);
  const unresolved = (record.unknown?.length ?? 0) + (record.retired?.length ?? 0);
  if (unresolved) parts.push(`${unresolved} id${unresolved === 1 ? '' : 's'} not in the bundled data (library-sync.json).`);
  return tableCell(parts.join(' ')).replace(/[–—]/g, ',');
}

/** The generated block of docs/LIBRARY_LAYERS.md: one section per synced group. */
export function renderDocBlock(index, lock) {
  const records = new Map(lock.files.map((f) => [f.file, f]));
  const synced = index.filter((e) => e.source);
  const L = [DOC_START, '', '## Synced from the library', ''];
  L.push(`These ${synced.length} layers come from the TeamStarWolf library's published Navigator set and its other Navigator folders, copied by \`node scripts/sync-library-layers.mjs\` (source address and sha256 of each in [library-sync.json](../src/assets/data/library-layers/library-sync.json)). They target ATT&CK v20 while the bundled data is ${lock.bundledVersions?.enterprise ? `v${lock.bundledVersions.enterprise}` : 'older'}, so an id the bundled data does not know is kept in the layer and listed in the lock; it has no cell to color until the ATT&CK data is refreshed. Layers in the ICS, Mobile and F3 domains color those matrices; ATLAS layers have no bundled matrix. Last synced ${lock.synced}.`);
  L.push('');
  for (const group of SYNCED_GROUPS) {
    const rows = synced.filter((e) => e.group === group);
    if (!rows.length) continue;
    L.push(`### ${group} (synced)`, '', '| Layer | Techniques | Notes |', '|---|---|---|');
    for (const e of rows) {
      const r = records.get(e.file);
      L.push(`| ${tableCell(layerLabel(e.name))} | ${r?.techniques ?? '?'} | ${noteFor(e, r ?? {})} |`);
    }
    L.push('');
  }
  if (lock.duplicates?.length) {
    L.push(`${lock.duplicates.length} library layers were not added because a layer with the same name or the same rows is already listed; library-sync.json names each one and the copy kept.`, '');
  }
  L.push(DOC_END);
  return L.join('\n');
}

const COUNT_PATTERNS = [
  { doc: DOC, re: /(This build ships \*\*)(\d+)( layers\*\*)/ },
  { doc: DOCS_README, re: /(The )(\d+)( bundled ATT&CK overlays)/ },
];

/** Docs with the generated block and the layer counts set from the index; text is LF. */
export function renderDocs(root, index, lock) {
  const out = {};
  for (const { doc } of COUNT_PATTERNS) out[doc] = lf(readFileSync(join(root, doc), 'utf8'));
  const guide = out[DOC];
  const a = guide.indexOf(DOC_START);
  const b = guide.indexOf(DOC_END);
  if (a < 0 || b < a) throw new Error(`${DOC}: the ${DOC_START} ... ${DOC_END} markers are missing`);
  out[DOC] = guide.slice(0, a) + renderDocBlock(index, lock) + guide.slice(b + DOC_END.length);
  for (const { doc, re } of COUNT_PATTERNS) {
    if (!re.test(out[doc])) throw new Error(`${doc}: layer-count sentence not found`);
    out[doc] = out[doc].replace(re, (_, p, _n, s) => `${p}${index.length}${s}`);
  }
  return out;
}

/** Write text keeping the file's existing line endings. */
function writeKeepingEol(path, text) {
  const crlf = existsSync(path) && readFileSync(path, 'utf8').includes('\r\n');
  writeFileSync(path, crlf ? text.replace(/\n/g, '\r\n') : text);
}

// ─── Check ────────────────────────────────────────────────────────────────────

/** Offline consistency of lock, files, index and docs. Returns a list of problems. */
export function check(root) {
  const dir = join(root, LAYER_DIR);
  const problems = [];
  const read = (f) => lf(readFileSync(join(dir, f), 'utf8'));
  if (!existsSync(join(dir, LOCK))) return [`${LAYER_DIR}/${LOCK} is missing: run node scripts/sync-library-layers.mjs`];
  const lock = JSON.parse(read(LOCK));
  const index = JSON.parse(read(INDEX));
  const bundles = loadBundles(root);

  // The index lists every file in the folder exactly once, and nothing else.
  const onDisk = readdirSync(dir).filter((f) => f !== INDEX && f !== LOCK).sort();
  const listed = index.map((e) => e.file);
  const seen = new Set();
  for (const f of listed) {
    if (seen.has(f)) problems.push(`${INDEX} lists ${f} more than once`);
    seen.add(f);
    if (!onDisk.includes(f)) problems.push(`${INDEX} lists ${f}, which is not in ${LAYER_DIR}`);
  }
  for (const f of onDisk) if (!seen.has(f)) problems.push(`${LAYER_DIR}/${f} is not listed in ${INDEX}`);

  // Every entry has a known group; bundled entries come first, groups in order.
  let lastBundled = -1;
  index.forEach((e, i) => {
    if (!GROUP_ORDER.includes(e.group)) problems.push(`${INDEX}: ${e.file} has group ${JSON.stringify(e.group)}, not one of ${GROUP_ORDER.join(', ')}`);
    if (!e.source) {
      if (i !== lastBundled + 1) problems.push(`${INDEX}: bundled entry ${e.file} comes after a synced entry`);
      lastBundled = i;
      if (!BUNDLED_GROUPS.includes(e.group)) problems.push(`${INDEX}: bundled entry ${e.file} is in synced group ${e.group}`);
    } else if (!SYNCED_GROUPS.includes(e.group)) problems.push(`${INDEX}: synced entry ${e.file} is in bundled group ${e.group}`);
  });

  // Synced entries and lock records match one to one, and each file matches its sha256.
  const records = new Map(lock.files.map((r) => [r.file, r]));
  const synced = index.filter((e) => e.source);
  if (synced.length !== lock.files.length) problems.push(`${INDEX} has ${synced.length} synced entries, ${LOCK} records ${lock.files.length}`);
  for (const e of synced) {
    const r = records.get(e.file);
    if (!r) { problems.push(`${INDEX}: ${e.file} has a source but no record in ${LOCK}`); continue; }
    if (r.source !== e.source) problems.push(`${e.file}: source ${e.source} in ${INDEX}, ${r.source} in ${LOCK}`);
    if (r.group !== e.group) problems.push(`${e.file}: group ${e.group} in ${INDEX}, ${r.group} in ${LOCK}`);
    if (!onDisk.includes(e.file)) continue;
    const text = read(e.file);
    if (sha256(text) !== r.sha256) { problems.push(`${e.file}: sha256 does not match ${LOCK} (edited by hand? re-run the sync)`); continue; }
    const layer = JSON.parse(text);
    if (layer.name !== e.name) problems.push(`${e.file}: name ${JSON.stringify(layer.name)} differs from ${INDEX}`);
    // Unresolved rows are recomputed against the bundled data, so a bundle refresh
    // without a re-sync, or a hand-edited report, fails here instead of hiding an id.
    const now = { file: r.file, group: r.group, source: r.source, sha256: r.sha256, domain: layer.domain, techniques: distinctIds(layer), ...resolveLayer(layer, bundles) };
    if (JSON.stringify(now) !== JSON.stringify(r)) problems.push(`${e.file}: the ${LOCK} record (domain, counts, unresolved ids) does not match the file against the bundled data; re-run the sync`);
  }
  for (const r of lock.files) if (!seen.has(r.file)) problems.push(`${LOCK} records ${r.file}, which ${INDEX} does not list`);

  // The generated docs match the index and lock.
  try {
    const docs = renderDocs(root, index, lock);
    for (const [doc, text] of Object.entries(docs)) {
      if (lf(readFileSync(join(root, doc), 'utf8')) !== text) problems.push(`${doc} is out of date: run node scripts/sync-library-layers.mjs --docs`);
    }
  } catch (err) {
    problems.push(err.message);
  }
  return problems;
}

// ─── Report ───────────────────────────────────────────────────────────────────

/** A Markdown report: counts per group, duplicates, unresolved ids, skipped files. */
export function renderReport(index, lock) {
  const L = [];
  const count = (g) => index.filter((e) => e.group === g).length;
  L.push('| Group | Layers | Origin |', '|---|---|---|');
  for (const g of GROUP_ORDER) if (count(g)) L.push(`| ${g} | ${count(g)} | ${BUNDLED_GROUPS.includes(g) ? 'bundled' : 'synced'} |`);
  L.push(`| Total | ${index.length} | ${index.filter((e) => !e.source).length} bundled, ${lock.files.length} synced |`, '');

  L.push(`Duplicates not added (${lock.duplicates.length}):`, '');
  if (lock.duplicates.length) {
    L.push('| Library file | Techniques | Reason | Kept as |', '|---|---|---|---|');
    for (const d of lock.duplicates) {
      L.push(`| ${d.source.replace(SITE, '')} | ${d.techniques} | ${d.reason} | ${d.keptAs} (${d.keptFrom === 'bundled' ? 'bundled' : d.keptFrom.replace(SITE, 'library ')}) |`);
    }
  } else L.push('none');
  L.push('');

  const unresolved = lock.files.filter((r) => r.unknown || r.retired || r.tacticMismatch);
  const allUnknown = new Set(unresolved.flatMap((r) => r.unknown ?? []));
  const allRetired = new Set(unresolved.flatMap((r) => (r.retired ?? []).map((x) => x.id)));
  L.push(`Rows the bundled ATT&CK data (Enterprise/ICS/Mobile ${lock.bundledVersions.enterprise}, F3 ${lock.bundledVersions.f3}) does not resolve: ${unresolved.length} layers; ${allUnknown.size} distinct unknown ids, ${allRetired.size} distinct retired ids. The layers are kept whole.`, '');
  if (unresolved.length) {
    L.push('| Layer file | Unknown ids | Retired ids (successor) | Tactic mismatches |', '|---|---|---|---|');
    for (const r of unresolved) {
      L.push(`| ${r.file} | ${(r.unknown ?? []).join(', ') || '-'} | ${(r.retired ?? []).map((x) => `${x.id}${x.successor ? ` (${x.successor})` : ''}`).join(', ') || '-'} | ${(r.tacticMismatch ?? []).map((x) => `${x.id} ${x.tactic}`).join(', ') || '-'} |`);
    }
    L.push('');
  }
  const unchecked = lock.files.filter((r) => r.unchecked);
  if (unchecked.length) L.push(`Not checkable (no bundled matrix): ${unchecked.map((r) => `${r.file} (${r.unchecked} rows)`).join(', ')}.`, '');
  if (lock.invalid.length) L.push(`Not synced, not a usable Navigator layer: ${lock.invalid.map((x) => `${x.source.replace(SITE, '')} (${x.problems.join('; ')})`).join(', ')}.`, '');
  if (lock.unmapped.length) L.push(`Not synced, outside the known folders: ${lock.unmapped.join(', ')}.`, '');
  return L.join('\n');
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function readIndex(root) {
  return JSON.parse(readFileSync(join(root, LAYER_DIR, INDEX), 'utf8'));
}

function readLock(root) {
  const p = join(root, LAYER_DIR, LOCK);
  return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null;
}

function writeDocs(root, index, lock) {
  for (const [doc, text] of Object.entries(renderDocs(root, index, lock))) writeKeepingEol(join(root, doc), text);
}

/**
 * Write the files, index, lock and docs for a pull (pullLibrary's result, or a
 * fixture in the tests). `today` is the YYYY-MM-DD the lock records.
 */
export function applySync(root, pulled, today) {
  const dir = join(root, LAYER_DIR);
  const bundles = loadBundles(root);
  const index = readIndex(root);
  const previous = readLock(root);
  const bundledList = bundledEntries(index).map((entry) => ({ entry, layer: JSON.parse(readFileSync(join(dir, entry.file), 'utf8')) }));
  const { kept, duplicates, invalid } = plan(bundledList, pulled.candidates, bundles);

  // Remove files a previous sync wrote that the library no longer publishes.
  const keptFiles = new Set(kept.map((k) => k.entry.file));
  for (const r of previous?.files ?? []) {
    if (!keptFiles.has(r.file) && existsSync(join(dir, r.file))) unlinkSync(join(dir, r.file));
  }
  for (const k of kept) writeFileSync(join(dir, k.entry.file), k.text);

  const newIndex = [...bundledList.map((b) => b.entry), ...kept.map((k) => k.entry)];
  const lock = {
    source: SITE,
    index: pulled.indexUrl,
    indexVersion: pulled.indexVersion,
    indexSha256: pulled.indexSha256,
    synced: today,
    bundledVersions: Object.fromEntries(Object.entries(bundles).map(([k, b]) => [k, b.version])),
    files: kept.map((k) => k.record),
    duplicates,
    invalid,
    unmapped: pulled.unmapped,
  };
  // Keep the earlier date when nothing else changed, so a no-op sync writes nothing.
  if (previous) {
    const same = JSON.stringify({ ...previous, synced: '' }) === JSON.stringify({ ...lock, synced: '' });
    if (same) lock.synced = previous.synced;
  }
  writeFileSync(join(dir, INDEX), serialize(newIndex));
  writeFileSync(join(dir, LOCK), serialize(lock));
  writeDocs(root, newIndex, lock);
  return { index: newIndex, lock };
}

async function sync(root, today) {
  return applySync(root, await pullLibrary(), today);
}

async function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const reportAt = argv.indexOf('--report');
  const reportFile = reportAt >= 0 ? argv[reportAt + 1] : null;
  const known = new Set(['--check', '--docs', '--report']);
  for (const [i, a] of argv.entries()) {
    if (a.startsWith('--') && !known.has(a)) throw new Error(`unknown argument ${a}`);
    if (!a.startsWith('--') && argv[i - 1] !== '--report') throw new Error(`unexpected argument ${a}`);
  }

  if (argv.includes('--check')) {
    const problems = check(root);
    if (problems.length) {
      for (const p of problems) console.error(`sync-library-layers --check: ${p}`);
      return 1;
    }
    const index = readIndex(root);
    const lock = readLock(root);
    console.log(`sync-library-layers --check: ${index.length} index entries (${lock.files.length} synced, each matching its sha256 in ${LOCK}); every file listed once; docs current`);
    return 0;
  }

  let index;
  let lock;
  if (argv.includes('--docs')) {
    index = readIndex(root);
    lock = readLock(root);
    if (!lock) throw new Error(`${LOCK} is missing: run the sync first`);
    writeDocs(root, index, lock);
    console.log(`sync-library-layers --docs: wrote ${DOC} and ${DOCS_README} for ${index.length} layers`);
  } else {
    ({ index, lock } = await sync(root, new Date().toISOString().slice(0, 10)));
    const unresolved = lock.files.filter((r) => r.unknown || r.retired).length;
    console.log(`sync-library-layers: ${index.length} layers (${lock.files.length} synced from ${SITE}), ${lock.duplicates.length} duplicates not added, ${unresolved} layers with ids the bundled data does not know, ${lock.invalid.length} invalid, ${lock.unmapped.length} outside the known folders`);
  }
  if (reportFile) {
    writeFileSync(reportFile, `${renderReport(index, lock)}\n`);
    console.log(`sync-library-layers: report written to ${reportFile}`);
  }
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
    console.error(`sync-library-layers: ${err.message}`);
    process.exit(1);
  });
}

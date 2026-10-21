// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/assets/data/rule-coverage-snapshot.json: for three public rule
// repositories, which ATT&CK techniques their rules name, read from the rule BODIES
// at a pinned commit. The app used to read technique ids from GitHub tree listings
// (file paths), and none of these upstreams puts ids in file names, so it found none.
//
//   Elastic        elastic/detection-rules            rules/**/*.toml (not rules/_deprecated/):
//                  [rule] name, and every id inside [[rule.threat.technique]] and
//                  [[rule.threat.technique.subtechnique]] (tactic ids TA#### are ignored)
//   Splunk         splunk/security_content            detections/**/*.yml (not detections/deprecated/):
//                  name, and the mitre_attack_id list (top level, or under tags: in older files)
//   mdecrevoisier  mdecrevoisier/SIGMA-detection-rules **/*.yaml: title, and attack.tNNNN(.NNN)
//                  tags (any case), normalised to TNNNN.NNN
//
// Each upstream is pinned to a commit SHA. The tarball comes anonymously from
// codeload.github.com, is gunzipped with node:zlib and read as a ustar stream by
// hand (no dependency). The licence of each upstream is read from its LICENSE file
// in the same tarball, never assumed.
//
//   node scripts/build-rule-coverage-snapshot.mjs                 rebuild at the SHAs recorded in the
//                                                                 committed file (PINS below when there is none)
//   node scripts/build-rule-coverage-snapshot.mjs --check         rebuild and compare, write nothing (exit 1 on drift)
//   node scripts/build-rule-coverage-snapshot.mjs --update-pins   move every pin to its branch head
//                                                                 (gh api repos/<o>/<r>/commits/<branch>), rewrite
//                                                                 PINS, then build and write
//
// The pin of record is the SHA in the committed file, as the KEV snapshot keeps its
// pinned date in its own file: the monthly refresh-data.yml carries only
// src/assets/data/ into its review PR, so a moved pin travels inside the asset, and
// --check rebuilds from the SHAs the asset names. PINS is the starting point when
// no asset exists and what a local --update-pins rewrites.
//
// Requires Node 20+ (built-in fetch). --update-pins runs `gh` (no shell); the other
// modes make anonymous HTTPS requests only.
//
// Licences: Elastic detection-rules is under the Elastic License 2.0, Splunk
// security_content under the Apache License 2.0, mdecrevoisier SIGMA-detection-rules
// under CC0 1.0 (as read from the tarballs at the pins below). The file holds rule
// names, repository paths and technique ids, not rule logic.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const OUT = 'src/assets/data/rule-coverage-snapshot.json';
export const SCRIPT = 'scripts/build-rule-coverage-snapshot.mjs';
export const SOURCE_KEYS = ['elastic', 'splunk', 'mdecrevoisier'];

/** Rules listed per technique; the count is always the full number. */
export const MAX_RULES = 10;
/** Rules listed per technique when MAX_RULES would make the file larger than SIZE_LIMIT. */
export const FALLBACK_MAX_RULES = 5;
export const SIZE_LIMIT = 1.5 * 1024 * 1024;

// PINS-BEGIN (rewritten by --update-pins)
export const PINNED_ON = '2026-10-21';
export const PINS = {
  elastic: { owner: 'elastic', repo: 'detection-rules', branch: 'main', sha: '7115bb0ab06c11c7994486ffe2bc0dc801ad8502' },
  splunk: { owner: 'splunk', repo: 'security_content', branch: 'develop', sha: '678e76c5f36f6fadd93a1eaa0d82c1dbe273c486' },
  mdecrevoisier: { owner: 'mdecrevoisier', repo: 'SIGMA-detection-rules', branch: 'main', sha: 'd61408af8769c74c96296b7ccc92d4bc3abb15af' },
};
// PINS-END

const SHA = /^[0-9a-f]{40}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;

// ─── ustar reader ───────────────────────────────────────────────────────────

/** A NUL-terminated string field of a header block. */
function field(block, start, length) {
  const raw = block.subarray(start, start + length);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? raw.length : end).toString('utf8');
}

/** An octal number field (size, mtime, checksum); spaces and NULs around it are allowed. */
function octal(block, start, length, what) {
  const text = field(block, start, length).trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) throw new Error(`tar: bad ${what} field ${JSON.stringify(text)}`);
  return parseInt(text, 8);
}

/** The header checksum: every byte summed, with the checksum field itself read as spaces. */
function checksum(block) {
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : block[i];
  return sum;
}

/** Records of a pax extended header ("<length> <key>=<value>\n", length counted in bytes). */
export function parsePax(buf) {
  const out = {};
  let off = 0;
  while (off < buf.length) {
    const space = buf.indexOf(0x20, off);
    if (space === -1) break;
    const len = parseInt(buf.subarray(off, space).toString('ascii'), 10);
    if (!Number.isSafeInteger(len) || len <= 0 || off + len > buf.length) throw new Error('tar: bad pax record length');
    const record = buf.subarray(space + 1, off + len - 1).toString('utf8');
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    off += len;
  }
  return out;
}

/**
 * Read an uncompressed tar (ustar, with pax and GNU long-name headers) held in memory.
 * Returns { globalPax, entries: [{ path, type, mtime, data }] } for regular files and
 * directories; `path` is the full archive path (the top-level directory included).
 */
export function readTar(tar) {
  const entries = [];
  let globalPax = {};
  let nextPax = null;
  let nextLongName = null;
  let off = 0;
  while (off + 512 <= tar.length) {
    const block = tar.subarray(off, off + 512);
    if (block.every((b) => b === 0)) break; // end of archive (two zero blocks; one is enough to stop)
    const want = octal(block, 148, 8, 'checksum');
    if (want !== checksum(block)) throw new Error(`tar: header checksum mismatch at byte ${off}`);
    const size = octal(block, 124, 12, 'size');
    const mtime = octal(block, 136, 12, 'mtime');
    const type = String.fromCharCode(block[156] || 0x30);
    const start = off + 512;
    if (start + size > tar.length) throw new Error(`tar: entry at byte ${off} runs past the end of the archive`);
    const data = tar.subarray(start, start + size);
    off = start + Math.ceil(size / 512) * 512;

    if (type === 'g') { globalPax = { ...globalPax, ...parsePax(data) }; continue; }
    if (type === 'x') { nextPax = parsePax(data); continue; }
    if (type === 'L') { nextLongName = field(data, 0, data.length); continue; }

    const name = field(block, 0, 100);
    const magic = field(block, 257, 6);
    const prefix = magic.startsWith('ustar') ? field(block, 345, 155) : '';
    let path = prefix ? `${prefix}/${name}` : name;
    if (nextLongName !== null) path = nextLongName;
    if (nextPax?.path) path = nextPax.path;
    nextPax = null;
    nextLongName = null;
    if (type === '0' || type === '7') entries.push({ path, type: 'file', mtime, data });
    else if (type === '5') entries.push({ path, type: 'dir', mtime, data: null });
    // Links, devices and FIFOs carry no rule text and are skipped.
  }
  return { globalPax, entries };
}

/** The path inside the repository: the archive's top-level directory removed. */
export function stripTopDir(path) {
  const slash = path.indexOf('/');
  return slash === -1 ? '' : path.slice(slash + 1);
}

// ─── field extraction (hand-written, line based) ─────────────────────────────

/** True when `s` holds an unescaped occurrence of the multi-line delimiter `delim`. */
function closesMultiline(s, delim) {
  let from = 0;
  for (;;) {
    const at = s.indexOf(delim, from);
    if (at === -1) return false;
    if (delim === "'''") return true;
    let backslashes = 0;
    for (let i = at - 1; i >= 0 && s[i] === '\\'; i--) backslashes++;
    if (backslashes % 2 === 0) return true;
    from = at + 1;
  }
}

/** A TOML basic ("...") or literal ('...') single-line string at the start of `rest`, or null. */
export function tomlString(rest) {
  const basic = /^"((?:[^"\\]|\\.)*)"/.exec(rest);
  if (basic) {
    try {
      return JSON.parse(`"${basic[1]}"`);
    } catch {
      return basic[1];
    }
  }
  const literal = /^'([^']*)'/.exec(rest);
  return literal ? literal[1] : null;
}

/**
 * An Elastic rule file: the [rule] name and the technique ids named in
 * [[rule.threat.technique]] and [[rule.threat.technique.subtechnique]] tables. Tactic
 * ids ([rule.threat.tactic], TA####) are never read. Multi-line strings (queries,
 * notes) are skipped, so a query line such as "[process where ...]" is not a table.
 */
export function parseElasticRule(text) {
  let table = '';
  let open = null;
  let name = null;
  const techniques = new Set();
  for (const raw of text.split(/\r?\n/)) {
    if (open) {
      if (closesMultiline(raw, open)) open = null;
      continue;
    }
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const header = /^\[\[?\s*([A-Za-z0-9_.-]+)\s*\]\]?\s*(?:#.*)?$/.exec(line);
    if (header) { table = header[1]; continue; }
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const [, key, rest] = kv;
    const delim = rest.startsWith('"""') ? '"""' : rest.startsWith("'''") ? "'''" : null;
    if (delim) {
      if (!closesMultiline(rest.slice(3), delim)) open = delim;
      continue;
    }
    if (table === 'rule' && key === 'name') name = tomlString(rest);
    else if (key === 'id' && (table === 'rule.threat.technique' || table === 'rule.threat.technique.subtechnique')) {
      const id = (tomlString(rest) ?? '').trim().toUpperCase();
      if (TECHNIQUE.test(id)) techniques.add(id);
    }
  }
  return name ? { name, techniques } : null;
}

/** Where a quoted YAML scalar that starts at `s[0]` ends on this line (index of the closing quote), or -1. */
function yamlQuoteEnd(s) {
  const q = s[0];
  for (let i = 1; i < s.length; i++) {
    if (q === "'" && s[i] === "'") {
      if (s[i + 1] === "'") { i++; continue; }
      return i;
    }
    if (q === '"') {
      if (s[i] === '\\') { i++; continue; }
      if (s[i] === '"') return i;
    }
  }
  return -1;
}

/** A YAML scalar as written after `key:` or `- ` on one line: quotes removed, trailing comment dropped. */
export function yamlScalar(rest) {
  const s = rest.trim();
  if (s.startsWith("'") || s.startsWith('"')) {
    const end = yamlQuoteEnd(s);
    if (end === -1) return s.slice(1);
    const inner = s.slice(1, end);
    if (s[0] === "'") return inner.replace(/''/g, "'");
    try {
      return JSON.parse(`"${inner}"`);
    } catch {
      return inner;
    }
  }
  return s.replace(/\s+#.*$/, '').trim();
}

/** The items of a flow sequence written on one line: "[a, 'b', c]". */
function flowItems(rest) {
  const s = rest.trim().replace(/\s+#.*$/, '');
  if (!s.startsWith('[') || !s.endsWith(']')) return null;
  return s.slice(1, -1).split(',').map((x) => yamlScalar(x)).filter((x) => x !== '');
}

/**
 * The top-level values of a YAML document set, read line by line: for each top-level
 * key, its one-line scalar, or the items of the sequence under it. Nested keys one
 * level down are reported as "parent.child" (Splunk's older tags.mitre_attack_id).
 * Block scalars and multi-line quoted scalars are skipped, so their content is never
 * read as keys.
 */
export function yamlTopLevel(text) {
  const scalars = new Map();
  const lists = new Map();
  const addList = (key, items) => lists.set(key, [...(lists.get(key) ?? []), ...items]);
  const lines = text.split(/\r?\n/);
  let parent = null;
  let listKey = null;
  let listIndent = -1;
  let skipQuote = null;
  let blockIndent = -1;
  for (const raw of lines) {
    if (skipQuote) {
      if (yamlQuoteEnd(skipQuote + raw) !== -1) skipQuote = null;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (blockIndent >= 0) {
      if (line === '' || indent > blockIndent) continue;
      blockIndent = -1;
    }
    if (line === '' || line.startsWith('#')) continue;
    if (line === '---' || line === '...') { parent = null; listKey = null; continue; }
    const item = /^-\s+(.*)$|^-$/.exec(line);
    if (item && listKey !== null && indent >= listIndent) {
      const v = yamlScalar(item[1] ?? '');
      if (v !== '') addList(listKey, [v]);
      continue;
    }
    listKey = null;
    const kv = /^([A-Za-z0-9_.-]+):(?:\s+(.*))?$/.exec(line);
    if (!kv) continue;
    const key = kv[1];
    const rest = kv[2] ?? '';
    let full;
    if (indent === 0) { parent = key; full = key; }
    else if (parent !== null) full = `${parent}.${key}`;
    else continue;
    if (/^[|>][-+0-9]*\s*(#.*)?$/.test(rest)) { blockIndent = indent; continue; }
    if (rest === '' || rest.startsWith('#')) { listKey = full; listIndent = indent; continue; }
    const flow = flowItems(rest);
    if (flow) { addList(full, flow); continue; }
    const t = rest.trim();
    if ((t.startsWith("'") || t.startsWith('"')) && yamlQuoteEnd(t) === -1) skipQuote = t[0];
    if (indent === 0 && !scalars.has(full)) scalars.set(full, yamlScalar(rest));
    else if (indent > 0 && !scalars.has(full)) scalars.set(full, yamlScalar(rest));
  }
  return { scalars, lists };
}

/** A Splunk detection: its name and the ids in mitre_attack_id (top level, or tags.mitre_attack_id). */
export function parseSplunkDetection(text) {
  const { scalars, lists } = yamlTopLevel(text);
  const name = scalars.get('name');
  if (!name) return null;
  const techniques = new Set();
  for (const raw of [...(lists.get('mitre_attack_id') ?? []), ...(lists.get('tags.mitre_attack_id') ?? [])]) {
    const id = String(raw).trim().toUpperCase();
    if (TECHNIQUE.test(id)) techniques.add(id);
  }
  return { name, techniques };
}

/** attack.t1003.001 (any case) as T1003.001, or null for a tactic or any other tag. */
export function sigmaTagTechnique(tag) {
  const m = /^attack\.t(\d{4})(?:\.(\d{3}))?$/i.exec(String(tag).trim());
  return m ? `T${m[1]}${m[2] ? `.${m[2]}` : ''}` : null;
}

/** A Sigma rule file: the first title, and the technique tags of every document in it. */
export function parseSigmaRule(text) {
  const { scalars, lists } = yamlTopLevel(text);
  const name = scalars.get('title');
  if (!name) return null;
  const techniques = new Set();
  for (const tag of lists.get('tags') ?? []) {
    const id = sigmaTagTechnique(tag);
    if (id) techniques.add(id);
  }
  return { name, techniques };
}

/** Which repository paths are rules for each source, and how each is parsed. */
export const SOURCE_RULES = {
  elastic: {
    select: (p) => p.startsWith('rules/') && p.endsWith('.toml') && !p.startsWith('rules/_deprecated/'),
    parse: parseElasticRule,
  },
  splunk: {
    select: (p) => p.startsWith('detections/') && p.endsWith('.yml') && !p.startsWith('detections/deprecated/'),
    parse: parseSplunkDetection,
  },
  mdecrevoisier: {
    select: (p) => p.endsWith('.yaml') && !p.split('/').some((seg) => seg.startsWith('.')),
    parse: parseSigmaRule,
  },
};

/** An SPDX identifier for an upstream LICENSE text; an unknown text stops the build for review. */
export function identifyLicence(text) {
  const head = text.slice(0, 4000);
  if (/Elastic License 2\.0/.test(head)) return 'Elastic-2.0';
  if (/Apache License[\s\S]{0,80}Version 2\.0/.test(head)) return 'Apache-2.0';
  if (/CC0 1\.0 Universal/.test(head)) return 'CC0-1.0';
  if (/GNU GENERAL PUBLIC LICENSE[\s\S]{0,80}Version 3/.test(head)) return 'GPL-3.0';
  if (/Permission is hereby granted, free of charge/.test(head)) return 'MIT';
  return null;
}

/** The repository's top-level LICENSE file (LICENSE, LICENSE.txt, LICENSE.md, ...), or null. */
function licenceFile(files) {
  return files.find((f) => /^(LICENSE|LICENCE|COPYING)(\.[A-Za-z]+)?$/i.test(f.path)) ?? null;
}

/** ISO 8601 UTC, seconds precision, for an epoch-seconds tar mtime. */
export function isoFromEpoch(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * One source of the snapshot from its tarball contents (pure).
 * `files` are { path (inside the repository), data } of regular files.
 */
export function buildSource(key, pin, files, commitDate, maxRules = MAX_RULES) {
  const spec = SOURCE_RULES[key];
  const lic = licenceFile(files);
  const licence = lic ? identifyLicence(lic.data.toString('utf8')) : null;
  if (!licence) {
    throw new Error(`${pin.owner}/${pin.repo}@${pin.sha.slice(0, 7)}: LICENSE ${lic ? 'text not recognised' : 'file not found'}; review it and add its identifier to identifyLicence()`);
  }
  const byTechnique = new Map();
  let ruleCount = 0;
  let mapped = 0;
  for (const f of files) {
    if (!spec.select(f.path)) continue;
    const rule = spec.parse(f.data.toString('utf8'));
    if (!rule) continue;
    ruleCount++;
    // A rule naming a sub-technique also counts once for its parent, so a parent's
    // count is the distinct rules that name it or any of its sub-techniques.
    const ids = new Set(rule.techniques);
    for (const id of rule.techniques) if (id.includes('.')) ids.add(id.slice(0, 5));
    if (ids.size) mapped++;
    for (const id of ids) {
      if (!byTechnique.has(id)) byTechnique.set(id, []);
      byTechnique.get(id).push({ name: rule.name, path: f.path });
    }
  }
  const techniques = {};
  for (const id of [...byTechnique.keys()].sort()) {
    const rules = byTechnique.get(id).sort((a, b) => cmp(a.name, b.name) || cmp(a.path, b.path));
    techniques[id] = { count: rules.length, rules: rules.slice(0, maxRules) };
  }
  return {
    source: {
      owner: pin.owner,
      repo: pin.repo,
      branch: pin.branch,
      sha: pin.sha,
      commitDate,
      licence,
      ruleCount,
      techniqueCount: Object.keys(techniques).length,
      techniques,
    },
    mapped,
  };
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Object keys sorted at every level (arrays keep their order). */
export function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeys(value[k]);
    return out;
  }
  return value;
}

/** Deterministic text: sorted keys, two-space indent, LF, one trailing newline. */
export function serialize(doc) {
  return JSON.stringify(sortKeys(doc), null, 2) + '\n';
}

/** Problems that make a snapshot unusable; an empty list means it is sound. */
export function validateSnapshot(doc) {
  const problems = [];
  if (!DATE.test(doc?.generated ?? '')) problems.push(`generated is not YYYY-MM-DD: ${doc?.generated}`);
  for (const key of SOURCE_KEYS) {
    const s = doc?.sources?.[key];
    if (!s) { problems.push(`sources.${key} is missing`); continue; }
    for (const f of ['owner', 'repo', 'branch', 'licence']) if (typeof s[f] !== 'string' || !s[f]) problems.push(`${key}.${f} is empty`);
    if (!SHA.test(s.sha ?? '')) problems.push(`${key}.sha is not a full commit sha: ${s.sha}`);
    if (!ISO.test(s.commitDate ?? '')) problems.push(`${key}.commitDate is not ISO 8601 UTC: ${s.commitDate}`);
    if (!(s.ruleCount > 0)) problems.push(`${key}: no rules parsed`);
    const ids = Object.keys(s.techniques ?? {});
    if (ids.length === 0) problems.push(`${key}: no technique ids read`);
    if (s.techniqueCount !== ids.length) problems.push(`${key}.techniqueCount ${s.techniqueCount} != ${ids.length} techniques`);
    for (const id of ids) {
      const t = s.techniques[id];
      if (!TECHNIQUE.test(id)) problems.push(`${key}: bad technique id ${id}`);
      if (!(t.count > 0) || !Array.isArray(t.rules) || t.rules.length === 0 || t.rules.length > t.count) {
        problems.push(`${key} ${id}: count ${t.count} does not fit ${t.rules?.length} listed rules`);
      }
      for (const r of t.rules ?? []) if (!r.name || !r.path) problems.push(`${key} ${id}: a rule without name or path`);
    }
  }
  return problems;
}

// ─── network ────────────────────────────────────────────────────────────────

/** The gzipped tarball of `owner/repo` at `sha`, anonymously from codeload.github.com. */
export async function fetchTarball(pin) {
  const url = `https://codeload.github.com/${pin.owner}/${pin.repo}/tar.gz/${pin.sha}`;
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': 'ATTACK-Navi build script' } });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} from ${url}`);
      return Buffer.from(await res.arrayBuffer());
    } catch (err) {
      lastError = err;
      if (attempt < 3) await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  throw lastError;
}

/** The head commit of a branch, through the GitHub CLI (it carries GH_TOKEN in CI). */
export function resolveHead(pin) {
  const out = execFileSync('gh', ['api', `repos/${pin.owner}/${pin.repo}/commits/${pin.branch}`, '--jq', '.sha'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim();
  if (!SHA.test(out)) throw new Error(`could not resolve ${pin.owner}/${pin.repo}@${pin.branch}: ${JSON.stringify(out)}`);
  return out;
}

/** Unpack a gzipped tarball into { commitDate, files } and check it is the pinned commit. */
export function unpack(gz, pin) {
  const { globalPax, entries } = readTar(gunzipSync(gz));
  if (globalPax.comment && globalPax.comment !== pin.sha) {
    throw new Error(`${pin.owner}/${pin.repo}: tarball is commit ${globalPax.comment}, expected ${pin.sha}`);
  }
  if (!entries.length) throw new Error(`${pin.owner}/${pin.repo}: empty tarball`);
  // GitHub stamps every entry with the commit's committer date.
  const commitDate = isoFromEpoch(entries[0].mtime);
  const files = entries
    .filter((e) => e.type === 'file')
    .map((e) => ({ path: stripTopDir(e.path), data: e.data }))
    .filter((f) => f.path !== '');
  return { commitDate, files };
}

// ─── pins ───────────────────────────────────────────────────────────────────

/** The PINS block as source text. */
export function pinsBlock(pins, pinnedOn) {
  const row = (k) => {
    const p = pins[k];
    return `  ${k}: { owner: '${p.owner}', repo: '${p.repo}', branch: '${p.branch}', sha: '${p.sha}' },`;
  };
  return [
    '// PINS-BEGIN (rewritten by --update-pins)',
    `export const PINNED_ON = '${pinnedOn}';`,
    'export const PINS = {',
    ...SOURCE_KEYS.map(row),
    '};',
    '// PINS-END',
  ].join('\n');
}

/** `script` with its PINS block replaced. */
export function rewritePins(script, pins, pinnedOn) {
  const re = /\/\/ PINS-BEGIN[^\n]*\n[\s\S]*?\/\/ PINS-END/;
  if (!re.test(script)) throw new Error('PINS-BEGIN / PINS-END markers not found');
  return script.replace(re, pinsBlock(pins, pinnedOn));
}

/** The pins recorded in a committed snapshot, or null when it does not name all of them. */
export function pinsFromSnapshot(doc) {
  const out = {};
  for (const key of SOURCE_KEYS) {
    const s = doc?.sources?.[key];
    if (!s || !SHA.test(s.sha ?? '') || !s.owner || !s.repo || !s.branch) return null;
    out[key] = { owner: s.owner, repo: s.repo, branch: s.branch, sha: s.sha };
  }
  return DATE.test(doc?.generated ?? '') ? { pins: out, generated: doc.generated } : null;
}

// ─── build ──────────────────────────────────────────────────────────────────

/** Build the snapshot text for `pins`, dropping to FALLBACK_MAX_RULES when the file would be too large. */
export async function buildText(pins, generated, getTarball = fetchTarball, log = () => {}) {
  const unpacked = {};
  for (const key of SOURCE_KEYS) {
    const pin = pins[key];
    unpacked[key] = unpack(await getTarball(pin), pin);
    log(`${key}: ${pin.owner}/${pin.repo}@${pin.sha.slice(0, 7)} (${unpacked[key].commitDate}), ${unpacked[key].files.length} files`);
  }
  let text = '';
  let doc = null;
  let stats = {};
  for (const maxRules of [MAX_RULES, FALLBACK_MAX_RULES]) {
    doc = { generated, sources: {} };
    stats = {};
    for (const key of SOURCE_KEYS) {
      const { source, mapped } = buildSource(key, pins[key], unpacked[key].files, unpacked[key].commitDate, maxRules);
      doc.sources[key] = source;
      stats[key] = { ruleCount: source.ruleCount, mapped, techniqueCount: source.techniqueCount, licence: source.licence };
    }
    text = serialize(doc);
    if (Buffer.byteLength(text) <= SIZE_LIMIT) return { text, doc, stats, maxRules };
    log(`${Buffer.byteLength(text)} bytes with ${maxRules} rules per technique is over ${SIZE_LIMIT}; trying fewer`);
  }
  return { text, doc, stats, maxRules: FALLBACK_MAX_RULES };
}

function parseArgs(argv) {
  const out = { check: false, updatePins: false };
  for (const a of argv) {
    if (a === '--check') out.check = true;
    else if (a === '--update-pins') out.updatePins = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (out.check && out.updatePins) throw new Error('--check and --update-pins do not combine');
  return out;
}

/**
 * The command. `deps` lets the test run it offline: { root, getTarball, resolveHead, today, log }.
 * Returns the exit code.
 */
export async function run(argv, deps = {}) {
  const root = deps.root ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const getTarball = deps.getTarball ?? fetchTarball;
  const head = deps.resolveHead ?? resolveHead;
  const log = deps.log ?? ((m) => console.log(m));
  const args = parseArgs(argv);
  const target = join(root, OUT);
  const onDisk = existsSync(target) ? readFileSync(target, 'utf8').replace(/\r\n/g, '\n') : null;
  let current = null;
  try {
    current = onDisk ? JSON.parse(onDisk) : null;
  } catch {
    current = null;
  }

  let pins;
  let generated;
  if (args.updatePins) {
    pins = {};
    for (const key of SOURCE_KEYS) pins[key] = { ...PINS[key], sha: head(PINS[key]) };
    generated = (deps.today ?? new Date().toISOString().slice(0, 10));
    const scriptPath = join(root, SCRIPT);
    if (existsSync(scriptPath)) {
      const before = readFileSync(scriptPath, 'utf8');
      const after = rewritePins(before, pins, generated);
      if (after !== before) writeFileSync(scriptPath, after);
    }
    log(`pins moved to the branch heads on ${generated}`);
  } else {
    const recorded = pinsFromSnapshot(current);
    pins = recorded?.pins ?? PINS;
    generated = recorded?.generated ?? PINNED_ON;
  }

  const { text, doc, stats, maxRules } = await buildText(pins, generated, getTarball, log);
  const problems = validateSnapshot(doc);
  if (problems.length) throw new Error(`snapshot rejected:\n  ${problems.slice(0, 20).join('\n  ')}`);
  const size = Buffer.byteLength(text);
  for (const key of SOURCE_KEYS) {
    const s = stats[key];
    log(`${key}: ${s.ruleCount} rules parsed, ${s.mapped} name at least one technique, ${s.techniqueCount} techniques, licence ${s.licence}`);
  }

  if (args.check) {
    if (onDisk !== text) {
      console.error(`${OUT} differs from a rebuild at the SHAs it records: run node ${SCRIPT}`);
      return 1;
    }
    log(`${OUT} matches a rebuild at the pinned commits (${size} bytes, up to ${maxRules} rules per technique).`);
    return 0;
  }
  writeFileSync(target, text);
  log(`wrote ${OUT}: ${size} bytes (${Math.round(size / 1024)} KB), up to ${maxRules} rules per technique, generated ${generated}`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  run(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(err.message ?? err); process.exitCode = 1; },
  );
}

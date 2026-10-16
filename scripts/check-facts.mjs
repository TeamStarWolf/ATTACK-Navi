#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Fails when README.md, ARCHITECTURE.md, HANDOFF.md or QUICKSTART.md state a
// count or version that disagrees with docs/FACTS.md, or when docs/FACTS.md no
// longer matches the code (regenerate it with node scripts/gen-facts.mjs).
//
//   node scripts/check-facts.mjs                    check the four docs
//   node scripts/check-facts.mjs FILE...            check other markdown files
//   node scripts/check-facts.mjs --root DIR --no-freshness
//                                                   check DIR's docs against
//                                                   DIR/docs/FACTS.md only
//
// Phrases it understands (digits or number words): "N heatmap modes",
// "N routed workspaces" (also "N workspaces", "N lazily loaded workspaces"),
// "the other N workspaces lazy-load a route file", "N routed tabs",
// "N library layers", "lists N overlays", "N unit specs" / "N spec files",
// "Angular N", "TypeScript N", and the version column of a markdown table whose
// header names "Bundled snapshot". A line containing `facts:ignore`, a block
// between `<!-- facts:ignore-start -->` and `<!-- facts:ignore-end -->`, and
// fenced code are skipped: use the marker for historical statements.

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FACTS_PATH, parseFactsMarkdown, collectFacts, renderFacts } from './gen-facts.mjs';

export const DEFAULT_DOCS = ['README.md', 'ARCHITECTURE.md', 'HANDOFF.md', 'QUICKSTART.md'];

const UNITS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
  'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen'];
const TENS = ['', '', 'twenty', 'thirty', 'forty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety'];
const WORD = `(?:(?:${TENS.slice(2).join('|')})(?:-(?:${UNITS.slice(1, 10).join('|')}))?|${UNITS.slice().reverse().join('|')})`;
const NUM = `(\\d[\\d,]*|${WORD})(\\+?)`;

export function parseNumber(s) {
  const t = s.toLowerCase().replace(/,/g, '');
  if (/^\d+$/.test(t)) return Number(t);
  if (UNITS.includes(t)) return UNITS.indexOf(t);
  const [tens, unit] = t.split('-');
  if (TENS.includes(tens)) return TENS.indexOf(tens) * 10 + (unit ? UNITS.indexOf(unit) : 0);
  return NaN;
}

const rx = (src) => new RegExp(src, 'gi');

/** Each rule maps a phrase to a key of the facts-json block in docs/FACTS.md. */
export const RULES = [
  { fact: 'heatmapModes', label: 'heatmap modes', re: rx(`\\b${NUM}\\s+heatmap\\s+modes?\\b`) },
  { fact: 'routeFileWorkspaces', label: 'workspaces that lazy-load a route file', re: rx(`\\bother\\s+${NUM}\\s+workspaces\\b`) },
  { fact: 'routedWorkspaces', label: 'routed workspaces', re: rx(`(?<!\\bother\\s+)\\b${NUM}\\s+(?:routed\\s+|lazily[- ]loaded\\s+|lazy[- ]loaded\\s+|top-level\\s+)?workspaces\\b`) },
  { fact: 'routedTabs', label: 'routed workspace tabs', re: rx(`\\b${NUM}\\s+(?:routed|workspace)\\s+tabs\\b`) },
  { fact: 'libraryLayers', label: 'library layers', re: rx(`\\b${NUM}\\s+library\\s+(?:layers|overlays)\\b`) },
  { fact: 'libraryLayers', label: 'library layers', re: rx(`\\blists\\s+${NUM}\\s+overlays\\b`) },
  { fact: 'unitSpecs', label: 'unit spec files', re: rx(`\\b${NUM}\\s+(?:unit\\s+specs?|unit\\s+spec\\s+files|spec\\s+files)\\b`) },
  { fact: 'angularMajor', label: 'Angular major version', re: /\bAngular\s+v?(\d+)()(?=[.\s,;:)/]|$)/g },
  { fact: 'typescriptMajor', label: 'TypeScript major version', re: /\bTypeScript\s+v?(\d+)()(?=[.\s,;:)/]|$)/g },
];

const BUNDLE_ROW = /^\|\s*([^|]+?)\s*\|.*\|\s*v?(\d+(?:\.\d+)+)\s*\|\s*$/;

/**
 * Check one markdown text against the headline facts. Returns a list of
 * { file, line, text, fact, stated, expected } for every disagreement.
 */
export function checkText(text, facts, file = '<text>') {
  const problems = [];
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  let fence = null;
  let ignoring = false;
  let bundleTable = false;
  lines.forEach((line, i) => {
    const n = i + 1;
    const fm = /^\s*(```|~~~)/.exec(line);
    if (fm) { fence = fence === null ? fm[1] : fence === fm[1] ? null : fence; return; }
    if (fence !== null) return;
    if (line.includes('facts:ignore-start')) { ignoring = true; return; }
    if (line.includes('facts:ignore-end')) { ignoring = false; return; }
    if (ignoring || line.includes('facts:ignore')) return;

    // Bundled-snapshot tables: header row names the column, rows give versions.
    if (/^\s*\|/.test(line)) {
      if (/bundled snapshot/i.test(line)) { bundleTable = true; return; }
      if (bundleTable) {
        const m = BUNDLE_ROW.exec(line);
        if (m && facts.bundleVersions && m[1] in facts.bundleVersions) {
          const expected = facts.bundleVersions[m[1]];
          if (m[2] !== expected) problems.push({ file, line: n, text: line.trim(), fact: `bundleVersions.${m[1]}`, label: `${m[1]} bundled version`, stated: m[2], expected });
        }
      }
    } else bundleTable = false;

    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      for (const m of line.matchAll(rule.re)) {
        const stated = parseNumber(m[1]);
        const atLeast = m[2] === '+';
        const expected = facts[rule.fact];
        if (expected === undefined || Number.isNaN(stated)) continue;
        const ok = atLeast ? expected >= stated : expected === stated;
        if (!ok) problems.push({ file, line: n, text: m[0], fact: rule.fact, label: rule.label, stated: m[1] + m[2], expected });
      }
    }
  });
  return problems;
}

/** Problems when docs/FACTS.md differs from what scripts/gen-facts.mjs would write now. */
export function checkFreshness(root) {
  const target = join(root, FACTS_PATH);
  const current = existsSync(target) ? readFileSync(target, 'utf8').replace(/\r\n/g, '\n') : '';
  return current === renderFacts(collectFacts(root))
    ? []
    : [{ file: FACTS_PATH, line: 1, text: '', fact: 'freshness', label: 'docs/FACTS.md', stated: 'stale', expected: 'regenerated: run node scripts/gen-facts.mjs' }];
}

export function checkRepo(root, { files = DEFAULT_DOCS, freshness = true } = {}) {
  const factsFile = join(root, FACTS_PATH);
  if (!existsSync(factsFile)) throw new Error(`${FACTS_PATH} not found under ${root}: run node scripts/gen-facts.mjs`);
  const facts = parseFactsMarkdown(readFileSync(factsFile, 'utf8'));
  const problems = freshness ? checkFreshness(root) : [];
  for (const f of files) {
    const p = join(root, f);
    if (!existsSync(p)) throw new Error(`${f} not found under ${root}`);
    problems.push(...checkText(readFileSync(p, 'utf8'), facts, f));
  }
  return problems;
}

function main(argv) {
  let root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  let freshness = true;
  const files = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root') root = resolve(argv[++i]);
    else if (argv[i] === '--no-freshness') freshness = false;
    else files.push(argv[i]);
  }
  const checked = files.length ? files : DEFAULT_DOCS;
  const problems = checkRepo(root, { files: checked, freshness });
  if (problems.length) {
    for (const p of problems) {
      if (p.fact === 'freshness') console.error(`${p.file}: out of date with the code; run node scripts/gen-facts.mjs and commit the result`);
      else console.error(`${p.file}:${p.line}: "${p.text}" states ${p.stated} ${p.label}; ${FACTS_PATH} says ${p.expected}`);
    }
    console.error(`check-facts: ${problems.length} disagreement(s). Fix the doc, or regenerate ${FACTS_PATH} if the code changed. Mark a historical statement with facts:ignore.`);
    return 1;
  }
  console.log(`check-facts: ${checked.join(', ')} agree with ${FACTS_PATH}${freshness ? ', and it matches the code' : ''}.`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) { console.error(`check-facts: ${e.message}`); process.exitCode = 2; }
}

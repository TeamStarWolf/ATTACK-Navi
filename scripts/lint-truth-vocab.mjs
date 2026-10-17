#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Truth-vocabulary lint (plan epic E1.1, section 4.1 "The honest vocabulary:
// Known, Covered, Proven"). Fails when user-facing text claims more than the
// data behind it can support.
//
//   node scripts/lint-truth-vocab.mjs                 lint the repository
//   node scripts/lint-truth-vocab.mjs --root DIR      lint another checkout
//   node scripts/lint-truth-vocab.mjs FILE...         lint only these files
//   node scripts/lint-truth-vocab.mjs --json          machine-readable report
//
// It reports, never fixes. Each finding is printed as `file:line:col  rule
// "matched text"  hint`, and the exit code is 1 when there is any finding.
//
// What is scanned (the surfaces a reader sees):
//   - src/app/**/*.html templates: text, human-facing attributes (title,
//     aria-label, placeholder, alt, ...) and quoted literals inside bindings,
//     interpolations and control-flow expressions;
//   - src/app/**/*.ts (not *.spec.ts, not src/app/testing/): string literals
//     and template-literal text, with inline `template:` strings read as
//     HTML. Comments are not scanned. A literal that looks like an
//     identifier (no whitespace, no capital letter: 'covered', 'kev-linked',
//     'wazuh-xdr') is a key, enum value or CSS class rather than prose, and is
//     skipped; the e2e DOM scan (journey 4) catches what such a key renders.
//   - README.md and docs/**/*.md: prose, with fenced code blocks, inline code
//     spans, link targets and HTML comments skipped.
//
// Deliberate uses are allowed inline, with a reason after `--`:
//   <text>  // truth-vocab-allow covered-unqualified -- why this is fine
//   <!-- truth-vocab-allow-next-line proven-only -- why this is fine -->
// `truth-vocab-allow` covers its own line, `truth-vocab-allow-next-line` the
// line after it. Several rule ids may be given, separated by commas. A
// directive with no reason, an unknown rule id, or one that suppresses
// nothing is itself a finding, so allowances cannot go stale silently.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname, extname, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

// ─── The rung allowlist (plan 4.1, "Allowed words" column) ─────────────────
//
// Every number, cell, badge and report line belongs to one rung. These are the
// words each rung may use. The rules below are derived from this table: a word
// owned by a higher rung may not appear on lower-rung data.
export const RUNGS = Object.freeze({
  known: {
    tier: 'reference',
    meaning: 'The world knows how to mitigate, detect or test it. No claim about you.',
    allowed: ['mapped', 'available', 'reference depth'],
  },
  covered: {
    tier: 'attested',
    meaning: 'Something is deployed for it but has not been shown to fire.',
    allowed: ['covered (self-attested)', 'covered (range)', 'deployed', 'implemented (self-attested)', 'partial', 'planned'],
    qualifiers: ['self-attested', 'range'],
  },
  proven: {
    tier: 'evidenced',
    meaning: 'A named detection fired, or the technique was blocked, on a recorded date.',
    allowed: ['proven', 'validated on <date> by <source>', 'defended'],
    words: ['proven', 'validated', 'defended', 'undefended'],
  },
  threat: {
    tier: 'dimension',
    meaning: 'How much adversaries care. Never a posture rung.',
    allowed: ['used by N groups', 'KEV-linked', 'exploit available'],
  },
  exposure: {
    tier: 'dimension',
    meaning: 'Reachable in my estate. Never a posture rung.',
    allowed: ['affects N of your assets'],
  },
});

const KNOWN_WORDS = RUNGS.known.allowed.map(w => `'${w}'`).join(', ');
/** A literal string as a regular-expression source (every metacharacter escaped). */
const escapeRegExp = (s) => s.replace(/[\\^$.*+?()[\]{}|-]/g, '\\$&');
const QUALIFIER_RE = RUNGS.covered.qualifiers.map(escapeRegExp).join('|');

// Labels retired by E1.1 PR 1 (#166) and PR 2 (#171), with their replacement.
export const RETIRED_LABELS = Object.freeze([
  { re: /\bunified\s+coverage\b/gi, use: "'Reference depth'" },
  // Capitalised only: that is the label. Lower-case 'unified' is the heat=
  // value, which links and docs keep (Phase 1 renames no route or heat= value).
  { re: /\bUnified\b/g, use: "'Reference depth' (the old Unified lens)" },
  { re: /\bintel(?:ligence)?\s+coverage\b/gi, use: "'Mitigation-mapped %'" },
  { re: /\bcoverage\s*%/gi, use: "'Mitigation-mapped %'" },
  { re: /\brisk\s+score\b/gi, use: "'Threat-weighted mapping gap'" },
  { re: /\bwazuh\s+xdr\b/gi, use: "'Wazuh stock rules (curated)'" },
  { re: /\b(?:theoretical|implemented)\s+coverage\b/gi, use: "'Theoretical: mitigation mapped' / 'Implemented (self-attested)'" },
  { re: /\btechniques\s+at\s+risk\b/gi, use: "'no mapped mitigation'" },
  { re: /\buncovered\b/gi, use: "'unmapped' or 'no mapped mitigation'" },
  { re: /\bATT(?:&|&amp;)CK\s+Navigator\s+Export\b/gi, use: "'Generated by ATTACK-Navi'" },
  { re: /\bGenerated\s+by\s+(?:MITRE\s+)?ATT(?:&|&amp;)CK\s+Navigator\b/gi, use: "'Generated by ATTACK-Navi' (D13)" },
]);

/**
 * The rules. Each has an id (used by allow directives), one or more patterns,
 * and the hint printed with a finding.
 */
export const RULES = Object.freeze([
  {
    id: 'banned',
    patterns: [/\blow[\s-]+risk\b/gi, /\bprotected\b/gi, /\bcoverage\s+score\b/gi],
    hint: () => "banned everywhere (plan 4.1: 'low risk', 'protected', letter grades, 'Coverage Score')",
  },
  {
    id: 'letter-grade',
    // 'government-grade' and 'production-grade' describe a thing, not a grading.
    // 'no grades' and 'never a grade' say a grade is absent.
    patterns: [/(?<!\b(?:no|not|never|without)\s+(?:a\s+)?)(?<![\w-])grades?\b(?!-)/gi, /\bexcellent\b/gi],
    hint: () => `letter grades and grade words are banned (plan 4.1); Known data reads ${KNOWN_WORDS}`,
  },
  {
    id: 'covered-unqualified',
    // The qualifier may be written in brackets, 'covered (self-attested)', the
    // way the legend's rung badge writes it (plan 4.7), 'COVERED self-attested',
    // or after a comma, 'Covered, self-attested'.
    patterns: [new RegExp(`\\bcovered\\b(?!\\s*[(,]?\\s*(?:${QUALIFIER_RE})\\b)`, 'gi')],
    hint: () => `'covered' only on Covered-or-higher data, always with its qualifier: 'covered (self-attested)' or 'covered (range)'; Known data reads ${KNOWN_WORDS}`,
  },
  {
    id: 'proven-only',
    // A negation ('not validated', 'never proven', '**not** a validated
    // result') makes no Proven claim.
    patterns: [new RegExp(`(?<!\\b(?:not|never|nor)\\b[*_]*\\s+(?:(?:a|an|any|the)\\s+)?)\\b(?:${RUNGS.proven.words.map(escapeRegExp).join('|')})\\b`, 'gi')],
    hint: () => "'proven', 'validated' and 'defended' only on Proven data, with its date and source (allow it where the data is Proven)",
  },
  {
    id: 'posture-claim',
    // Claims about the reader's posture ('you are secure', 'fully compliant',
    // 'safe against T1059'), not names that merely contain the word: 'Secure
    // Configuration' is a CIS control title and 'secure proxy' is transport.
    patterns: [
      /\b(?:is|are|be|been|being|looks?|appears?|fully|considered|rated|marked|remains?|stays?|now|you're)\s+(?:secure|compliant|safe)\b/gi,
      /\b(?:secure|compliant|safe)\s+(?:against|from|posture)\b/gi,
    ],
    hint: () => `'secure', 'compliant' and 'safe' claim a posture that reference data cannot show; Known data reads ${KNOWN_WORDS}`,
  },
  {
    id: 'retired-label',
    patterns: RETIRED_LABELS.map(r => r.re),
    hint: (m) => {
      const hit = RETIRED_LABELS.find(r => new RegExp(r.re.source, 'i').test(m));
      return `label retired by E1.1; use ${hit ? hit.use : 'the relabelled wording'}`;
    },
  },
]);

const RULE_IDS = new Set(RULES.map(r => r.id));

// Naming the vocabulary itself ('the Known / Covered / Proven rungs') is not a
// claim about any data, so it is blanked before the rules run.
const VOCABULARY_NAME = /\bKnown\s*[/,]\s*Covered\s*[/,]?\s*(?:and\s+|or\s+)?Proven\b/gi;

// ─── Targets ────────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set(['node_modules', 'dist', '.angular', '.git', 'testing', '__snapshots__']);

function walk(root, dir, pred, out = []) {
  const abs = join(root, dir);
  if (!existsSync(abs)) return out;
  for (const name of readdirSync(abs).sort()) {
    const rel = join(dir, name);
    const st = statSync(join(root, rel));
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(name)) walk(root, rel, pred, out);
    } else if (pred(rel)) {
      out.push(rel.split(sep).join('/'));
    }
  }
  return out;
}

/** The files the lint reads, relative to `root`, in a stable order. */
export function targetFiles(root) {
  const app = walk(root, 'src/app', p => (p.endsWith('.html') || p.endsWith('.ts')) && !p.endsWith('.spec.ts'));
  const docs = walk(root, 'docs', p => p.endsWith('.md'));
  const readme = existsSync(join(root, 'README.md')) ? ['README.md'] : [];
  return [...app, ...readme, ...docs];
}

/** How a file is read: 'html', 'ts' or 'md'. */
export function kindOf(file) {
  const ext = extname(file).toLowerCase();
  if (ext === '.html') return 'html';
  if (ext === '.ts' || ext === '.mts') return 'ts';
  if (ext === '.md') return 'md';
  return null;
}

// ─── Segments: the parts of a file a reader sees ───────────────────────────
//
// A segment is { start, text, literal }. `literal` marks a quoted string taken
// out of code (TS, a binding or an interpolation); identifier-like literals
// are skipped because they are keys, not prose.

const IDENTIFIER_LIKE = /^[a-z0-9_$.:/#@*+=?-]*$/;

function literalSegment(start, text) {
  return IDENTIFIER_LIKE.test(text) ? null : { start, text, literal: true };
}

/** Quoted literals inside an Angular expression starting at `offset`. */
function expressionLiterals(expr, offset, out) {
  const re = /'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g;
  let m;
  while ((m = re.exec(expr))) {
    const body = m[1] ?? m[2] ?? m[3] ?? '';
    const seg = literalSegment(offset + m.index + 1, body);
    if (seg) out.push(seg);
  }
}

// Attributes whose plain value a reader sees (or a screen reader announces).
const HUMAN_ATTRS = new Set([
  'title', 'aria-label', 'aria-description', 'aria-placeholder', 'aria-valuetext', 'aria-roledescription',
  'placeholder', 'alt', 'label', 'tooltip', 'mattooltip', 'data-tooltip', 'summary',
]);

function isBinding(name) {
  return /^[[(*]/.test(name) || name.startsWith('bind-') || name.startsWith('on-');
}

/** Find the index of the bracket that closes the one at `open`. */
function closeParen(src, open) {
  let depth = 0;
  let quote = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return i;
  }
  return src.length - 1;
}

/** Push text segments, splitting out {{ }} interpolations and @block (...) headers. */
function textSegments(text, offset, out) {
  const re = /\{\{([\s\S]*?)\}\}|@(?:if|else\s+if|for|switch|case|defer|let)\b\s*/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push({ start: offset + last, text: text.slice(last, m.index), literal: false });
    if (m[0].startsWith('{{')) {
      expressionLiterals(m[1], offset + m.index + 2, out);
      last = re.lastIndex;
    } else if (m[0].startsWith('@let')) {
      const end = text.indexOf(';', re.lastIndex);
      const stop = end === -1 ? text.length : end + 1;
      expressionLiterals(text.slice(re.lastIndex, stop), offset + re.lastIndex, out);
      last = re.lastIndex = stop;
    } else if (text[re.lastIndex] === '(') {
      const close = closeParen(text, re.lastIndex);
      expressionLiterals(text.slice(re.lastIndex, close + 1), offset + re.lastIndex, out);
      last = re.lastIndex = close + 1;
    } else {
      last = re.lastIndex;
    }
  }
  if (last < text.length) out.push({ start: offset + last, text: text.slice(last), literal: false });
}

/** Segments of an HTML template (a file, or an inline template at `base`). */
export function htmlSegments(src, base = 0) {
  const out = [];
  let i = 0;
  let textStart = 0;
  const flushText = (end) => {
    if (end > textStart) textSegments(src.slice(textStart, end), base + textStart, out);
  };
  while (i < src.length) {
    if (src.startsWith('<!--', i)) {
      flushText(i);
      const end = src.indexOf('-->', i + 4);
      i = textStart = end === -1 ? src.length : end + 3;
      continue;
    }
    if (src[i] === '<' && /[A-Za-z/!]/.test(src[i + 1] ?? '')) {
      flushText(i);
      // Read the tag up to its closing '>', respecting quoted attribute values.
      let j = i + 1;
      let quote = null;
      for (; j < src.length; j++) {
        const c = src[j];
        if (quote) { if (c === quote) quote = null; }
        else if (c === '"' || c === "'") quote = c;
        else if (c === '>') break;
      }
      const tag = src.slice(i, j + 1);
      const nameMatch = /^<\/?\s*([A-Za-z][\w:-]*)/.exec(tag);
      const tagName = nameMatch ? nameMatch[1].toLowerCase() : '';
      const attrRe = /([^\s=/>"']+)(?:\s*=\s*("([^"]*)"|'([^']*)'|[^\s>]+))?/g;
      attrRe.lastIndex = nameMatch ? nameMatch[0].length : 1;
      let a;
      while ((a = attrRe.exec(tag))) {
        const name = a[1].toLowerCase();
        const value = a[3] ?? a[4];
        if (value === undefined) continue;
        const valueStart = base + i + a.index + a[0].indexOf(a[2]) + 1;
        if (isBinding(name)) {
          expressionLiterals(value, valueStart, out);
        } else if (HUMAN_ATTRS.has(name)) {
          textSegments(value, valueStart, out);
        }
      }
      i = textStart = j + 1;
      // Skip raw-text elements entirely.
      if (tagName === 'script' || tagName === 'style') {
        const close = src.toLowerCase().indexOf(`</${tagName}`, i);
        i = textStart = close === -1 ? src.length : close;
      }
      continue;
    }
    i++;
  }
  flushText(src.length);
  return out;
}

// Properties whose string value is never shown to a reader.
// `rung` holds a rung's own name ('Covered'), which the legend renders as the
// rung badge beside its qualifier (plan 4.7).
const NON_DISPLAY_PROPS = new Set(['selector', 'styleUrl', 'styleUrls', 'templateUrl', 'styles', 'host', 'providedIn', 'rung']);

/** Segments of a TypeScript file: its string literals and template text. */
export function tsSegments(src, file = 'file.ts') {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const out = [];
  const propName = (node) => {
    const p = node.parent;
    if (p && ts.isPropertyAssignment(p) && p.initializer === node && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) {
      return p.name.text;
    }
    return null;
  };
  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node) || ts.isImportTypeNode?.(node)) return;
    if (ts.isLiteralTypeNode(node)) return; // 'a' | 'b' type unions are keys
    if (ts.isPropertyAssignment(node) && NON_DISPLAY_PROPS.has(node.name.getText(sf))) return;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      // Object keys written as strings ({ 'covered': 1 }) are keys, not prose.
      if (node.parent && ts.isPropertyAssignment(node.parent) && node.parent.name === node) return;
      if (node.parent && ts.isElementAccessExpression(node.parent)) return;
      const start = node.getStart(sf) + 1;
      if (propName(node) === 'template') {
        out.push(...htmlSegments(node.text, start));
        return;
      }
      const seg = literalSegment(start, src.slice(start, node.getEnd() - 1));
      if (seg) out.push(seg);
      return;
    }
    if (ts.isTemplateExpression(node)) {
      const isTemplate = propName(node) === 'template';
      const parts = [node.head, ...node.templateSpans.map(s => s.literal)];
      for (const part of parts) {
        const start = part.getStart(sf) + 1;
        const end = part.getEnd() - (ts.isTemplateTail(part) ? 1 : 2);
        const text = src.slice(start, end);
        if (isTemplate) out.push(...htmlSegments(text, start));
        else if (text.trim()) out.push({ start, text, literal: false });
      }
      node.templateSpans.forEach(s => visit(s.expression));
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/** Segments of a markdown file: prose without code, link targets or comments. */
export function mdSegments(src) {
  const out = [];
  const lines = src.split('\n');
  let offset = 0;
  let fence = null;
  let inComment = false;
  for (const line of lines) {
    const start = offset;
    offset += line.length + 1;
    const fenceMatch = /^\s*(```+|~~~+)/.exec(line);
    if (fence) {
      if (fenceMatch && fenceMatch[1][0] === fence[0] && fenceMatch[1].length >= fence.length) fence = null;
      continue;
    }
    if (fenceMatch) { fence = fenceMatch[1]; continue; }
    // Blank out comments, inline code and link targets, keeping offsets.
    let text = line;
    if (inComment) {
      const end = text.indexOf('-->');
      if (end === -1) continue;
      text = ' '.repeat(end + 3) + text.slice(end + 3);
      inComment = false;
    }
    text = text.replace(/<!--[\s\S]*?-->/g, s => ' '.repeat(s.length));
    const open = text.indexOf('<!--');
    if (open !== -1) { text = text.slice(0, open); inComment = true; }
    text = text
      .replace(/(`+)[\s\S]*?\1/g, s => ' '.repeat(s.length))
      .replace(/\]\([^)]*\)/g, s => ' '.repeat(s.length))
      .replace(/<https?:[^>]*>|https?:\/\/\S+/g, s => ' '.repeat(s.length));
    if (text.trim()) out.push({ start, text, literal: false });
  }
  return out;
}

// ─── Allow directives ───────────────────────────────────────────────────────

// The reason separator is '--' but not the start of an HTML comment's '-->'.
const DIRECTIVE_RE = /truth-vocab-allow(-next-line)?(?:[ \t]+([A-Za-z0-9_,-]+))?(?:[ \t]*--(?!>)[ \t]*(.*?))?[ \t]*(?:-->|\*\/|$)/;

/** Allow directives in a file, by the line they cover. */
export function parseDirectives(lines) {
  const directives = [];
  lines.forEach((line, idx) => {
    const m = DIRECTIVE_RE.exec(line);
    if (!m) return;
    directives.push({
      line: idx + 1,
      appliesTo: m[1] ? idx + 2 : idx + 1,
      rules: (m[2] ?? '').split(',').map(s => s.trim()).filter(Boolean),
      reason: (m[3] ?? '').trim(),
      used: false,
    });
  });
  return directives;
}

// ─── Linting ────────────────────────────────────────────────────────────────

function lineStarts(src) {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') starts.push(i + 1);
  return starts;
}

function position(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
  }
  return { line: lo + 1, col: offset - starts[lo] + 1 };
}

/**
 * Lint one file's text. Returns { findings, directives } where each finding is
 * { file, line, col, rule, match, hint }.
 */
export function lintText(raw, kind, file = `file.${kind}`) {
  const src = raw.replace(/\r\n?/g, '\n');
  const segments = kind === 'html' ? htmlSegments(src) : kind === 'ts' ? tsSegments(src, file) : kind === 'md' ? mdSegments(src) : [];
  const starts = lineStarts(src);
  const lines = src.split('\n');
  const directives = parseDirectives(lines);
  const findings = [];
  const seen = new Set();

  for (const d of directives) {
    const bad = !d.rules.length ? 'names no rule id' : d.rules.find(r => !RULE_IDS.has(r)) ? `names an unknown rule id (${d.rules.filter(r => !RULE_IDS.has(r)).join(', ')})` : !d.reason ? "gives no reason after '--'" : null;
    if (bad) {
      findings.push({ file, line: d.line, col: 1, rule: 'bad-allow', match: lines[d.line - 1].trim(), hint: `allow directive ${bad}` });
      d.used = true; // reported once, as bad-allow
      d.rules = [];
    }
  }

  for (const raw of segments) {
    const seg = { ...raw, text: raw.text.replace(VOCABULARY_NAME, s => ' '.repeat(s.length)) };
    for (const rule of RULES) {
      // Every match of the rule's patterns. Overlapping matches of one rule are
      // one finding ('Unified' inside 'Unified Coverage', 'Intel Coverage' and
      // 'Coverage %' in 'Intel Coverage %'): the earliest, then longest, wins.
      const hits = [];
      for (const pattern of rule.patterns) {
        const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
        let m;
        while ((m = re.exec(seg.text))) hits.push({ from: m.index, to: m.index + m[0].length, text: m[0] });
      }
      hits.sort((a, b) => a.from - b.from || b.to - a.to);
      let reach = -1;
      for (const hit of hits) {
        if (hit.from < reach) continue;
        reach = hit.to;
        const offset = seg.start + hit.from;
        const key = `${rule.id}@${offset}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const { line, col } = position(starts, offset);
        const allow = directives.find(d => d.appliesTo === line && d.rules.includes(rule.id));
        if (allow) { allow.used = true; continue; }
        findings.push({ file, line, col, rule: rule.id, match: hit.text, hint: rule.hint(hit.text) });
      }
    }
  }

  for (const d of directives) {
    if (!d.used) {
      findings.push({ file, line: d.line, col: 1, rule: 'unused-allow', match: lines[d.line - 1].trim(), hint: `allow directive suppresses nothing on line ${d.appliesTo}; remove it` });
    }
  }
  findings.sort((a, b) => a.line - b.line || a.col - b.col || a.rule.localeCompare(b.rule));
  return { findings, directives };
}

/** Lint a checkout. `files` (relative to root) defaults to targetFiles(root). */
export function lintRepo(root, files = targetFiles(root)) {
  const findings = [];
  let allows = 0;
  for (const file of files) {
    const kind = kindOf(file);
    if (!kind) continue;
    const result = lintText(readFileSync(join(root, file), 'utf8'), kind, file);
    findings.push(...result.findings);
    allows += result.directives.filter(d => d.rules.length).length;
  }
  return { files: files.length, findings, allows };
}

function format(f) {
  return `${f.file}:${f.line}:${f.col}  ${f.rule}  "${f.match}"  ${f.hint}`;
}

function main(argv) {
  let root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  let json = false;
  const files = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root') root = resolve(argv[++i]);
    else if (argv[i] === '--json') json = true;
    else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('usage: node scripts/lint-truth-vocab.mjs [--root DIR] [--json] [FILE...]');
      return 0;
    } else files.push(argv[i]);
  }
  const rel = files.map(f => relative(root, resolve(f)).split(sep).join('/'));
  const result = lintRepo(root, rel.length ? rel : undefined);
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const f of result.findings) console.log(format(f));
    const n = result.findings.length;
    console.log(`lint-truth-vocab: ${n} finding${n === 1 ? '' : 's'} in ${result.files} files (${result.allows} allow directive${result.allows === 1 ? '' : 's'})`);
  }
  return result.findings.length ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = main(process.argv.slice(2));
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Checks the file citations in the STRIDE threat model
// (ThreatDragonModels/ATTACK-Navi/ATTACK-Navi.json). The model's summary
// promises that each threat cites the relevant files; a citation that points at
// a missing file or past its last line cannot be checked by a reviewer, so this
// script fails on either.
//
// A citation is a `path:line` or `path:first-last` token inside any string value
// of the model, where `path` is relative to the repository root. Paths under a
// `node_modules/` directory are verified when the package is installed and
// reported as unverified otherwise, so the check works on a tree without
// dependencies installed.
//
// Usage: node scripts/validate-threat-model-citations.mjs [path/to/model.json]
// Exit code 0 when every citation resolves, 1 otherwise.

import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MODEL = 'ThreatDragonModels/ATTACK-Navi/ATTACK-Navi.json';

// A path token: optional directories, then a file name with a known extension,
// or a bare Dockerfile; followed by `:line` and an optional `-line`.
const CITATION = /((?:[\w@.-]+\/)*(?:[\w.-]+\.(?:ts|js|mjs|cjs|json|yml|yaml|conf|md|html|scss|css|txt|example|webmanifest)|Dockerfile)):(\d+)(?:-(\d+))?/g;

export function extractCitations(model) {
  const found = [];
  const visit = (value, where) => {
    if (typeof value === 'string') {
      for (const m of value.matchAll(CITATION)) {
        found.push({ path: m[1].replace(/^\.\//, ''), from: Number(m[2]), to: m[3] ? Number(m[3]) : null, where });
      }
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => visit(v, `${where}[${i}]`));
    } else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) visit(v, where ? `${where}.${k}` : k);
    }
  };
  visit(model, '');
  return found;
}

function countLines(file) {
  const text = readFileSync(file, 'utf8');
  if (text.length === 0) return 0;
  const lines = text.split('\n');
  return text.endsWith('\n') ? lines.length - 1 : lines.length;
}

export function checkCitations(citations, root = REPO_ROOT) {
  const problems = [];
  let verified = 0;
  let unverified = 0;
  const lineCache = new Map();
  for (const c of citations) {
    const abs = resolve(root, c.path);
    if (!abs.startsWith(root + sep) && abs !== root) {
      problems.push(`${c.path}: citation escapes the repository root`);
      continue;
    }
    const inNodeModules = c.path.split('/').includes('node_modules');
    if (!existsSync(abs) || !statSync(abs).isFile()) {
      if (inNodeModules) { unverified += 1; continue; }
      problems.push(`${c.path}:${c.from}${c.to ? '-' + c.to : ''}: file not found (${c.where})`);
      continue;
    }
    if (!lineCache.has(abs)) lineCache.set(abs, countLines(abs));
    const total = lineCache.get(abs);
    const last = c.to ?? c.from;
    if (c.from < 1 || (c.to !== null && c.to < c.from)) {
      problems.push(`${c.path}:${c.from}-${c.to}: malformed line range (${c.where})`);
    } else if (last > total) {
      problems.push(`${c.path}:${c.from}${c.to ? '-' + c.to : ''}: past end of file (${total} lines) (${c.where})`);
    } else {
      verified += 1;
    }
  }
  return { problems, verified, unverified };
}

function main() {
  const modelPath = resolve(REPO_ROOT, process.argv[2] ?? DEFAULT_MODEL);
  const model = JSON.parse(readFileSync(modelPath, 'utf8'));
  const citations = extractCitations(model);
  const { problems, verified, unverified } = checkCitations(citations);
  console.log(`threat model: ${join(modelPath).replace(REPO_ROOT + sep, '')}`);
  console.log(`citations: ${citations.length} found, ${verified} verified, ${unverified} unverified (package not installed), ${problems.length} broken`);
  for (const p of problems) console.log(`  BROKEN ${p}`);
  process.exit(problems.length === 0 ? 0 : 1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

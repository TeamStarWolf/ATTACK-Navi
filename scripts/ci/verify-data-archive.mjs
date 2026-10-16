// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Trust boundary for the monthly data refresh (.github/workflows/refresh-data.yml).
//
// The `refresh` job downloads data and later runs `npm ci` (lifecycle scripts
// of hundreds of packages) with a read-only token. The `open-pr` job holds
// contents/pull-requests write and applies what `refresh` produced. The
// artifact that crosses between them is therefore UNTRUSTED input to the
// privileged job: an archive entry with `..`, an absolute path, a symlink or
// a hardlink could write into .git/hooks or .github/workflows before the push.
//
// This script is dependency-free (node: built-ins only) and fails closed.
//
//   manifest <list-file> <manifest-out>
//       refresh job, BEFORE npm ci: every listed path must be a regular file
//       under src/assets/data/ (strict charset, no `.`/`..` segments, no
//       symlinks); writes { version, prefix, files: [{ path, size, sha256 }] }.
//   check-manifest <manifest>
//       validate the manifest's shape and every path in it.
//   check-archive <archive.tgz> <manifest>
//       parse the gzip'd tar natively (header checksums, type flags, names,
//       content sha256) AND read `tar -tzvf` from the system tar; reject any
//       entry that is not a regular file, is outside the prefix, contains
//       `..`, starts with `/`, is a symlink/hardlink, is missing from or
//       duplicated in the manifest, or whose content hash differs.
//   check-extracted <dir> <manifest>
//       after `tar -xzf --no-same-owner --no-overwrite-dir -C <dir>`: the tree
//       may hold only the manifest's regular files (hashes re-checked) and
//       their parent directories; no symlinks or other file types.
//   install <dir> <manifest> <workspace>
//       copy only the manifest's paths from <dir> into <workspace>, refusing
//       any destination that is not a plain file inside
//       <workspace>/src/assets/data reached through plain directories.
//
// Set TAR to choose the tar binary used for `tar -tzvf` (default: tar).
// Tests: node --test scripts/ci/verify-data-archive.test.mjs

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  constants, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const PREFIX = 'src/assets/data/';
const SEGMENT = /^[A-Za-z0-9._-]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_PATH = 255; // ustar name+prefix limit; the archive is written --format=ustar
const MAX_FILES = 10000;

export class ArchiveError extends Error {}
const fail = (msg) => { throw new ArchiveError(msg); };

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** A path is allowed only if it is a plain relative path under PREFIX. */
export function checkPath(p) {
  if (typeof p !== 'string' || p.length === 0) fail(`path is not a non-empty string: ${JSON.stringify(p)}`);
  if (p.length > MAX_PATH) fail(`path longer than ${MAX_PATH} characters: ${JSON.stringify(p)}`);
  if (p.startsWith('/')) fail(`absolute path: ${JSON.stringify(p)}`);
  if (p.includes('\\') || p.includes('\0')) fail(`backslash or NUL in path: ${JSON.stringify(p)}`);
  if (p.includes('..')) fail(`'..' in path: ${JSON.stringify(p)}`);
  if (!p.startsWith(PREFIX)) fail(`path outside ${PREFIX}: ${JSON.stringify(p)}`);
  const segments = p.split('/');
  for (const s of segments) {
    if (s === '' || s === '.' || !SEGMENT.test(s)) fail(`unsafe path segment ${JSON.stringify(s)} in ${JSON.stringify(p)}`);
    const lower = s.toLowerCase();
    if (lower === '.git' || lower === '.github') fail(`path reaches ${s}: ${JSON.stringify(p)}`);
  }
  if (segments.length < 4) fail(`path is not a file under ${PREFIX}: ${JSON.stringify(p)}`);
  return p;
}

/** Parse and validate a manifest object (or JSON text). Returns Map<path, {size, sha256}>. */
export function parseManifest(input) {
  let m = input;
  if (typeof input === 'string' || Buffer.isBuffer(input)) {
    try { m = JSON.parse(String(input)); } catch (e) { fail(`manifest is not JSON: ${e.message}`); }
  }
  if (!m || typeof m !== 'object' || Array.isArray(m)) fail('manifest is not an object');
  if (m.version !== 1) fail(`unsupported manifest version: ${JSON.stringify(m.version)}`);
  if (m.prefix !== PREFIX) fail(`manifest prefix must be ${PREFIX}`);
  if (!Array.isArray(m.files) || m.files.length === 0) fail('manifest lists no files');
  if (m.files.length > MAX_FILES) fail(`manifest lists more than ${MAX_FILES} files`);
  const files = new Map();
  for (const f of m.files) {
    if (!f || typeof f !== 'object') fail('manifest entry is not an object');
    checkPath(f.path);
    if (files.has(f.path)) fail(`duplicate manifest path: ${f.path}`);
    if (!Number.isSafeInteger(f.size) || f.size < 0) fail(`bad size for ${f.path}`);
    if (typeof f.sha256 !== 'string' || !SHA256.test(f.sha256)) fail(`bad sha256 for ${f.path}`);
    files.set(f.path, { size: f.size, sha256: f.sha256 });
  }
  return files;
}

/** refresh job: build the manifest from the newline-separated list of changed files, relative to cwd. */
export function buildManifest(listText, cwd = process.cwd()) {
  const paths = String(listText).split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l !== '');
  if (paths.length === 0) fail('file list is empty');
  const seen = new Set();
  const files = [];
  for (const p of paths) {
    checkPath(p);
    if (seen.has(p)) fail(`duplicate path in list: ${p}`);
    seen.add(p);
    // Every component must be a real directory and the leaf a regular file.
    const parts = p.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const abs = join(cwd, ...parts.slice(0, i));
      let st;
      try { st = lstatSync(abs); } catch { fail(`listed path does not exist: ${p}`); }
      if (st.isSymbolicLink()) fail(`symlink in listed path: ${parts.slice(0, i).join('/')}`);
      if (i < parts.length ? !st.isDirectory() : !st.isFile()) fail(`not a regular file under plain directories: ${p}`);
    }
    const buf = readFileSync(join(cwd, ...parts));
    files.push({ path: p, size: buf.length, sha256: sha256(buf) });
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const manifest = { version: 1, prefix: PREFIX, files };
  parseManifest(manifest); // self-check
  return manifest;
}

function cstr(buf, start, len) {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? len : nul).toString('latin1');
}

function octal(buf, start, len, what) {
  if (buf[start] & 0x80) fail(`base-256 ${what} field is not accepted`);
  const s = cstr(buf, start, len).trim();
  if (!/^[0-7]+$/.test(s)) fail(`bad ${what} field: ${JSON.stringify(s)}`);
  return parseInt(s, 8);
}

/** Natively walk a gzip'd tar. Returns [{ name, type, size, linkname, sha256 }]. */
export function readTarEntries(gz) {
  let tar;
  try { tar = gunzipSync(gz); } catch (e) { fail(`archive is not gzip: ${e.message}`); }
  const entries = [];
  let off = 0;
  for (;;) {
    if (off + 512 > tar.length) fail('archive is truncated (no end-of-archive marker)');
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
    if (sum !== octal(h, 148, 8, 'checksum')) fail(`bad header checksum at offset ${off}`);
    const name = cstr(h, 0, 100);
    const magic = cstr(h, 257, 6);
    const prefix = magic.startsWith('ustar') ? cstr(h, 345, 155) : '';
    const full = prefix ? `${prefix}/${name}` : name;
    const flag = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    const size = octal(h, 124, 12, 'size');
    const linkname = cstr(h, 157, 100);
    const start = off + 512;
    if (start + size > tar.length) fail(`entry ${JSON.stringify(full)} runs past the end of the archive`);
    entries.push({ name: full, type: flag, size, linkname, sha256: sha256(tar.subarray(start, start + size)) });
    if (entries.length > MAX_FILES) fail(`archive has more than ${MAX_FILES} entries`);
    off = start + Math.ceil(size / 512) * 512;
  }
  return entries;
}

const TYPE_NAMES = {
  0: 'regular file', 1: 'hardlink', 2: 'symlink', 3: 'char device', 4: 'block device', 5: 'directory',
  6: 'fifo', 7: 'contiguous file', x: 'pax header', g: 'pax global header', L: 'GNU long name', K: 'GNU long link',
};

/** `tar -tzvf -` on the archive bytes; returns the listing lines. */
export function tarListing(gz, tarBin = process.env.TAR || 'tar') {
  const r = spawnSync(tarBin, ['-tzvf', '-'], { input: gz, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) fail(`could not run ${tarBin}: ${r.error.message}`);
  if (r.status !== 0) fail(`${tarBin} -tzvf failed (${r.status}): ${r.stderr.trim()}`);
  return r.stdout.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.trim() !== '');
}

/** Validate an archive against its manifest. Returns the list of paths on success. */
export function checkArchive(gz, manifestInput, { listing } = {}) {
  const files = parseManifest(manifestInput);
  const entries = readTarEntries(gz);
  const seen = new Set();
  for (const e of entries) {
    if (e.type !== '0') {
      const kind = TYPE_NAMES[e.type] ?? `type '${e.type}'`;
      fail(`entry ${JSON.stringify(e.name)} is a ${kind}${e.linkname ? ` -> ${JSON.stringify(e.linkname)}` : ''}; only regular files are accepted`);
    }
    if (e.linkname) fail(`regular-file entry ${JSON.stringify(e.name)} carries a link target`);
    checkPath(e.name);
    if (seen.has(e.name)) fail(`duplicate archive entry: ${e.name}`);
    seen.add(e.name);
    const want = files.get(e.name);
    if (!want) fail(`archive entry not in manifest: ${e.name}`);
    if (want.size !== e.size || want.sha256 !== e.sha256) fail(`content of ${e.name} does not match the manifest`);
  }
  for (const p of files.keys()) if (!seen.has(p)) fail(`manifest path missing from archive: ${p}`);

  // Second opinion from the system tar, which is what extracts the archive.
  const lines = listing ?? tarListing(gz);
  if (lines.length !== entries.length) fail(`tar -tzvf lists ${lines.length} entries, header walk found ${entries.length}`);
  lines.forEach((line, i) => {
    if (line[0] !== '-') fail(`tar -tzvf: not a regular file: ${line}`);
    if (line.includes(' -> ') || line.includes(' link to ')) fail(`tar -tzvf: link entry: ${line}`);
    if (!line.endsWith(` ${entries[i].name}`)) fail(`tar -tzvf: entry name differs from the header walk: ${line}`);
  });
  return [...files.keys()];
}

/** Validate a directory produced by extracting the archive. */
export function checkExtracted(dir, manifestInput) {
  const files = parseManifest(manifestInput);
  const allowedDirs = new Set();
  for (const p of files.keys()) {
    const parts = p.split('/');
    for (let i = 1; i < parts.length; i++) allowedDirs.add(parts.slice(0, i).join('/'));
  }
  const found = new Set();
  const walk = (rel) => {
    for (const name of readdirSync(join(dir, ...rel.split('/').filter(Boolean)))) {
      const r = rel ? `${rel}/${name}` : name;
      const st = lstatSync(join(dir, ...r.split('/')));
      if (st.isSymbolicLink()) fail(`extracted tree holds a symlink: ${r}`);
      if (st.isDirectory()) {
        if (!allowedDirs.has(r)) fail(`extracted tree holds an unexpected directory: ${r}`);
        walk(r);
      } else if (st.isFile()) {
        const want = files.get(r);
        if (!want) fail(`extracted tree holds a file not in the manifest: ${r}`);
        if (st.nlink !== 1) fail(`extracted file has ${st.nlink} links: ${r}`);
        const buf = readFileSync(join(dir, ...r.split('/')));
        if (buf.length !== want.size || sha256(buf) !== want.sha256) fail(`extracted ${r} does not match the manifest sha256`);
        found.add(r);
      } else {
        fail(`extracted tree holds a special file: ${r}`);
      }
    }
  };
  walk('');
  for (const p of files.keys()) if (!found.has(p)) fail(`manifest path not extracted: ${p}`);
  return [...found].sort();
}

/** Copy the manifest's files from the verified extraction dir into the workspace. */
export function install(dir, manifestInput, workspace) {
  const files = parseManifest(manifestInput);
  checkExtracted(dir, manifestInput);
  const ws = resolve(workspace);
  const root = resolve(ws, ...PREFIX.split('/').filter(Boolean));
  for (const [p, want] of files) {
    const parts = p.split('/');
    const dest = resolve(ws, ...parts);
    if (!dest.startsWith(root + sep)) fail(`destination escapes ${PREFIX}: ${p}`);
    // Every component below the workspace must be a plain directory (never a symlink).
    for (let i = 1; i < parts.length; i++) {
      const abs = join(ws, ...parts.slice(0, i));
      let st = null;
      try { st = lstatSync(abs); } catch { /* missing: created below */ }
      if (st && (st.isSymbolicLink() || !st.isDirectory())) fail(`workspace path component is not a plain directory: ${parts.slice(0, i).join('/')}`);
      if (!st) mkdirSync(abs);
    }
    let st = null;
    try { st = lstatSync(dest); } catch { /* new file */ }
    if (st && (st.isSymbolicLink() || !st.isFile())) fail(`workspace destination is not a regular file: ${p}`);
    if (st) rmSync(dest);
    copyFileSync(join(dir, ...parts), dest, constants.COPYFILE_EXCL);
    if (sha256(readFileSync(dest)) !== want.sha256) fail(`installed ${p} does not match the manifest`);
  }
  return [...files.keys()];
}

function main(argv) {
  const [cmd, ...args] = argv;
  const need = (n, usage) => { if (args.length !== n) fail(`usage: verify-data-archive.mjs ${cmd} ${usage}`); };
  switch (cmd) {
    case 'manifest': {
      need(2, '<list-file> <manifest-out>');
      const m = buildManifest(readFileSync(args[0], 'utf8'));
      writeFileSync(args[1], `${JSON.stringify(m, null, 2)}\n`);
      console.log(`manifest: ${m.files.length} regular file(s) under ${PREFIX}`);
      for (const f of m.files) console.log(`  ${f.sha256}  ${f.path}`);
      break;
    }
    case 'check-manifest': {
      need(1, '<manifest>');
      const files = parseManifest(readFileSync(args[0]));
      console.log(`manifest OK: ${files.size} path(s), all under ${PREFIX}`);
      break;
    }
    case 'check-archive': {
      need(2, '<archive.tgz> <manifest>');
      const paths = checkArchive(readFileSync(args[0]), readFileSync(args[1]));
      console.log(`archive OK: ${paths.length} regular file(s), hashes match the manifest`);
      break;
    }
    case 'check-extracted': {
      need(2, '<dir> <manifest>');
      const paths = checkExtracted(args[0], readFileSync(args[1]));
      console.log(`extracted tree OK: ${paths.length} file(s)`);
      break;
    }
    case 'install': {
      need(3, '<dir> <manifest> <workspace>');
      const paths = install(args[0], readFileSync(args[1]), args[2]);
      for (const p of paths) console.log(`installed ${p}`);
      break;
    }
    default:
      fail('usage: verify-data-archive.mjs manifest|check-manifest|check-archive|check-extracted|install ...');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    const msg = e instanceof ArchiveError ? e.message : (e.stack ?? String(e));
    console.error(`::error::refreshed-data artifact rejected: ${msg}`);
    process.exit(1);
  }
}

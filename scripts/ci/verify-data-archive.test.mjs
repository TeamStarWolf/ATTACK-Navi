// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/ci/verify-data-archive.mjs. Run: node --test scripts/ci/verify-data-archive.test.mjs
//
// The adversarial cases build REAL archives with the system tar (GNU tar; on
// a host that cannot create symlinks, the symlink archive is written by
// bsdtar from an mtree description instead) and prove the verifier rejects
// each of them while accepting a well-formed archive end to end
// (check-archive -> GNU tar extract -> check-extracted -> install).

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';

import {
  ArchiveError, buildManifest, checkArchive, checkExtracted, checkPath, install, parseManifest, readTarEntries,
} from './verify-data-archive.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');

function findTar(kind) {
  const candidates = kind === 'gnu'
    ? [process.env.GNU_TAR, 'tar', 'gtar', 'C:\\Program Files\\Git\\usr\\bin\\tar.exe']
    : [process.env.BSD_TAR, 'bsdtar', 'C:\\Windows\\System32\\tar.exe', 'tar'];
  for (const bin of candidates.filter(Boolean)) {
    const r = spawnSync(bin, ['--version'], { encoding: 'utf8' });
    if (r.status !== 0 || r.error) continue;
    if (kind === 'gnu' ? /GNU tar/.test(r.stdout) : /bsdtar|libarchive/.test(r.stdout)) return bin;
  }
  return null;
}

function run(bin, args, cwd, input) {
  const r = spawnSync(bin, args, { cwd, input, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(r.error, undefined, `${bin} could not start: ${r.error?.message}`);
  assert.equal(r.status, 0, `${bin} ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

const GOOD = {
  'src/assets/data/enterprise-attack.json': '{"type":"bundle","objects":[]}\n',
  'src/assets/data/library-layers/apt29.json': '{"name":"layer"}\n',
};
const goodManifest = () => ({
  version: 1,
  prefix: 'src/assets/data/',
  files: Object.entries(GOOD).map(([path, body]) => ({ path, size: Buffer.byteLength(body), sha256: sha(body) })),
});

describe('checkPath', () => {
  it('accepts plain files under src/assets/data/', () => {
    for (const p of Object.keys(GOOD)) assert.equal(checkPath(p), p);
  });
  const bad = {
    '../ traversal': 'src/assets/data/../../../.git/hooks/pre-commit',
    'embedded ..': 'src/assets/data/a..b.json',
    absolute: '/src/assets/data/x.json',
    'outside prefix': '.github/workflows/ci.yml',
    'prefix look-alike': 'src/assets/database/x.json',
    'prefix only': 'src/assets/data/',
    'empty segment': 'src/assets/data//x.json',
    'dot segment': 'src/assets/data/./x.json',
    backslash: 'src/assets/data\\..\\x.json',
    'drive letter': 'C:/src/assets/data/x.json',
    '.git segment': 'src/assets/data/.git/config',
    '.github segment': 'src/assets/data/.GitHub/x.yml',
    'space / quoting': 'src/assets/data/a b.json',
    newline: 'src/assets/data/a\nb.json',
  };
  for (const [label, p] of Object.entries(bad)) {
    it(`rejects ${label}`, () => assert.throws(() => checkPath(p), ArchiveError));
  }
});

describe('parseManifest', () => {
  it('accepts a well-formed manifest', () => {
    assert.equal(parseManifest(JSON.stringify(goodManifest())).size, 2);
  });
  it('rejects a manifest path with .. or an absolute path or a path outside the prefix', () => {
    for (const path of ['src/assets/data/../../x', '/etc/passwd', '.git/hooks/pre-commit']) {
      const m = goodManifest();
      m.files[0].path = path;
      assert.throws(() => parseManifest(m), ArchiveError, path);
    }
  });
  it('rejects duplicates, bad hashes, empty lists and the wrong prefix', () => {
    const dup = goodManifest(); dup.files.push({ ...dup.files[0] });
    const badSha = goodManifest(); badSha.files[0].sha256 = 'abc';
    const empty = goodManifest(); empty.files = [];
    const prefix = goodManifest(); prefix.prefix = '';
    for (const m of [dup, badSha, empty, prefix]) assert.throws(() => parseManifest(m), ArchiveError);
    assert.throws(() => parseManifest('not json'), ArchiveError);
  });
});

describe('adversarial archives built with real tar', () => {
  let work; let gnu; let bsd;
  const archives = {};

  before(() => {
    gnu = findTar('gnu');
    assert.ok(gnu, 'GNU tar is required for this spec (set GNU_TAR to its path)');
    bsd = findTar('bsd');
    work = mkdtempSync(join(tmpdir(), 'verify-data-archive-'));
    const src = join(work, 'src');
    mkdirSync(join(src, 'src/assets/data/library-layers'), { recursive: true });
    mkdirSync(join(src, '.git/hooks'), { recursive: true });
    for (const [p, body] of Object.entries(GOOD)) writeFileSync(join(src, p), body);
    writeFileSync(join(src, '.git/hooks/pre-commit'), '#!/bin/sh\necho pwned\n');
    writeFileSync(join(src, 'src/assets/data/evil-abs.json'), 'evil\n');
    const good = Object.keys(GOOD);
    const tar = (args) => run(gnu, ['--format=ustar', '-czf', '-', ...args], src);

    archives.good = tar(['--no-recursion', ...good]);
    // 1. '..' entry: -P keeps the name verbatim instead of stripping it.
    archives.dotdot = tar(['-P', ...good, 'src/assets/data/../../../.git/hooks/pre-commit']);
    // 2. absolute entry, renamed to /etc/cron.d/evil inside the archive.
    archives.absolute = tar(['-P', '--transform=s,^src/assets/data/evil-abs\\.json$,/etc/cron.d/evil,', ...good, 'src/assets/data/evil-abs.json']);
    // 3. symlink src/assets/data/hooks -> ../../../.git/hooks, then a file written through it.
    let symlinkMade = false;
    try {
      symlinkSync('../../../.git/hooks', join(src, 'src/assets/data/hooks'));
      symlinkMade = true;
    } catch { /* e.g. Windows without symlink privilege: fall back to bsdtar + mtree below */ }
    if (symlinkMade) {
      archives.symlink = tar(['--no-recursion', ...good, 'src/assets/data/hooks']);
      rmSync(join(src, 'src/assets/data/hooks'));
    } else {
      assert.ok(bsd, 'no symlink privilege and no bsdtar to write the symlink archive');
      const mtree = [
        '#mtree',
        ...good.map((p) => `${p} type=file mode=0644 contents=${p}`),
        'src/assets/data/hooks type=link mode=0777 link=../../../.git/hooks',
        '',
      ].join('\n');
      writeFileSync(join(work, 'symlink.mtree'), mtree);
      archives.symlink = run(bsd, ['--format=ustar', '-czf', '-', `@${join(work, 'symlink.mtree')}`], src);
    }
    // 4. hardlink: the second name is stored as a link to the first.
    linkSync(join(src, good[0]), join(src, 'src/assets/data/hardlink.json'));
    archives.hardlink = tar(['--no-recursion', ...good, 'src/assets/data/hardlink.json']);
    rmSync(join(src, 'src/assets/data/hardlink.json'));
    for (const [k, buf] of Object.entries(archives)) writeFileSync(join(work, `${k}.tgz`), buf);
  });

  after(() => { if (work) rmSync(work, { recursive: true, force: true }); });

  it('the malicious archives really contain what they claim (sanity)', () => {
    const kinds = (k) => readTarEntries(archives[k]).map((e) => `${e.type}:${e.name}${e.linkname ? `->${e.linkname}` : ''}`);
    assert.ok(kinds('dotdot').includes('0:src/assets/data/../../../.git/hooks/pre-commit'), kinds('dotdot').join(' '));
    assert.ok(kinds('absolute').includes('0:/etc/cron.d/evil'), kinds('absolute').join(' '));
    assert.ok(kinds('symlink').includes('2:src/assets/data/hooks->../../../.git/hooks'), kinds('symlink').join(' '));
    assert.ok(kinds('hardlink').some((k) => k.startsWith('1:src/assets/data/hardlink.json->')), kinds('hardlink').join(' '));
  });

  it('REJECTS the archive with a ../ entry', () => {
    assert.throws(() => checkArchive(archives.dotdot, goodManifest()), /'\.\.' in path/);
  });
  it('REJECTS the archive with an absolute-path entry', () => {
    assert.throws(() => checkArchive(archives.absolute, goodManifest()), /absolute path/);
  });
  it('REJECTS the archive with a symlink pointing at .git/hooks', () => {
    assert.throws(() => checkArchive(archives.symlink, goodManifest()), /is a symlink -> "\.\.\/\.\.\/\.\.\/\.git\/hooks"/);
  });
  it('REJECTS the archive with a hardlink entry', () => {
    assert.throws(() => checkArchive(archives.hardlink, goodManifest()), /is a hardlink/);
  });
  it('REJECTS them even when the attacker also forges the manifest to list the evil paths', () => {
    for (const [k, name] of [['dotdot', 'src/assets/data/../../../.git/hooks/pre-commit'], ['absolute', '/etc/cron.d/evil']]) {
      const m = goodManifest();
      m.files.push({ path: name, size: 5, sha256: sha('evil\n') });
      assert.throws(() => checkArchive(archives[k], m), ArchiveError, k);
    }
  });
  it('the system tar listing agrees: none of the malicious archives is all regular files', () => {
    for (const k of ['symlink', 'hardlink']) {
      const lines = run(gnu, ['-tzvf', '-'], work, archives[k]).toString('utf8').trim().split('\n');
      assert.ok(lines.some((l) => l[0] !== '-'), `${k}: ${lines.join(' | ')}`);
    }
  });

  it('ACCEPTS the good archive and installs it end to end', () => {
    const manifest = goodManifest();
    assert.deepEqual(checkArchive(archives.good, manifest).sort(), Object.keys(GOOD).sort());
    const extract = mkdtempSync(join(work, 'extract-'));
    run(gnu, ['-xzf', '-', '--no-same-owner', '--no-overwrite-dir', '-C', '.'], extract, archives.good);
    assert.deepEqual(checkExtracted(extract, manifest), Object.keys(GOOD).sort());
    const ws = join(work, 'workspace');
    mkdirSync(join(ws, 'src/assets/data/library-layers'), { recursive: true });
    writeFileSync(join(ws, 'src/assets/data/enterprise-attack.json'), 'old\n');
    assert.deepEqual(install(extract, manifest, ws).sort(), Object.keys(GOOD).sort());
    for (const [p, body] of Object.entries(GOOD)) assert.equal(readFileSync(join(ws, p), 'utf8'), body);
    assert.equal(existsSync(join(ws, '.git')), false);
  });

  it('REJECTS the good archive when its content does not match the manifest hash', () => {
    const m = goodManifest();
    m.files[0].sha256 = sha('something else');
    assert.throws(() => checkArchive(archives.good, m), /does not match the manifest/);
  });
  it('REJECTS a manifest path that is missing from the archive', () => {
    const m = goodManifest();
    m.files.push({ path: 'src/assets/data/ics-attack.json', size: 1, sha256: sha('x') });
    assert.throws(() => checkArchive(archives.good, m), /missing from archive/);
  });
  it('REJECTS an extracted tree holding anything beyond the manifest', () => {
    const extract = mkdtempSync(join(work, 'extract-extra-'));
    run(gnu, ['-xzf', '-', '--no-same-owner', '--no-overwrite-dir', '-C', '.'], extract, archives.good);
    writeFileSync(join(extract, 'src/assets/data/extra.json'), '{}');
    assert.throws(() => checkExtracted(extract, goodManifest()), /not in the manifest/);
    rmSync(join(extract, 'src/assets/data/extra.json'));
    mkdirSync(join(extract, '.git'));
    assert.throws(() => checkExtracted(extract, goodManifest()), /unexpected directory: \.git/);
  });
  it('REJECTS a non-gzip or truncated archive', () => {
    assert.throws(() => checkArchive(Buffer.from('plain text'), goodManifest()), /not gzip/);
  });
});

describe('buildManifest (refresh job)', () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'verify-data-manifest-'));
    mkdirSync(join(dir, 'src/assets/data/library-layers'), { recursive: true });
    mkdirSync(join(dir, '.github/workflows'), { recursive: true });
    for (const [p, body] of Object.entries(GOOD)) writeFileSync(join(dir, p), body);
    writeFileSync(join(dir, '.github/workflows/ci.yml'), 'on: push\n');
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it('hashes every listed file and sorts the result', () => {
    const m = buildManifest(`${Object.keys(GOOD).reverse().join('\n')}\n`, dir);
    assert.deepEqual(m, goodManifest());
  });
  it('fails the job when a path outside src/assets/data/ is listed', () => {
    assert.throws(() => buildManifest('src/assets/data/enterprise-attack.json\n.github/workflows/ci.yml\n', dir), /outside src\/assets\/data\//);
  });
  it('fails on a missing file, a directory, a duplicate or an empty list', () => {
    assert.throws(() => buildManifest('src/assets/data/nope.json\n', dir), /does not exist/);
    assert.throws(() => buildManifest('src/assets/data/library-layers\n', dir), /not a regular file/);
    assert.throws(() => buildManifest('src/assets/data/enterprise-attack.json\nsrc/assets/data/enterprise-attack.json\n', dir), /duplicate/);
    assert.throws(() => buildManifest('\n', dir), /empty/);
  });
  it('fails on a listed path that is a symlink (where the host can create one)', (t) => {
    try {
      symlinkSync('../../../.github/workflows/ci.yml', join(dir, 'src/assets/data/link.json'));
    } catch {
      t.skip('host cannot create symlinks; the archive-level symlink case above still runs');
      return;
    }
    assert.throws(() => buildManifest('src/assets/data/link.json\n', dir), /symlink/);
  });
});

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/build-rule-coverage-snapshot.mjs and the snapshot it wrote. No
// network: one real rule file per upstream (scripts/fixtures/rule-coverage/) is packed
// into in-memory tarballs shaped like codeload.github.com's, and the command runs
// against them in a temporary directory.
//
//   node --test scripts/build-rule-coverage-snapshot.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import {
  FALLBACK_MAX_RULES, MAX_RULES, OUT, PINNED_ON, PINS, SCRIPT, SIZE_LIMIT, SOURCE_KEYS,
  buildSource, identifyLicence, parseElasticRule, parseSigmaRule, parseSplunkDetection, pinsFromSnapshot,
  readTar, rewritePins, run, serialize, sigmaTagTechnique, stripTopDir, validateSnapshot,
} from './build-rule-coverage-snapshot.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');
const FIX = 'scripts/fixtures/rule-coverage';
const ELASTIC = read(`${FIX}/elastic-rule.toml`);
const SPLUNK = read(`${FIX}/splunk-detection.yml`);
const SIGMA = read(`${FIX}/mdecrevoisier-rule.yaml`);

// ─── a minimal ustar writer (the shape codeload.github.com serves) ───────────

const MTIME = Date.UTC(2026, 9, 20, 23, 33, 59) / 1000; // 2026-10-20T23:33:59Z

function header(name, size, type, prefix = '') {
  const b = Buffer.alloc(512);
  b.write(name, 0, 100, 'utf8');
  b.write('0000644\0', 100, 'ascii');
  b.write('0000000\0', 108, 'ascii');
  b.write('0000000\0', 116, 'ascii');
  b.write(size.toString(8).padStart(11, '0') + '\0', 124, 'ascii');
  b.write(MTIME.toString(8).padStart(11, '0') + '\0', 136, 'ascii');
  b.write('        ', 148, 'ascii');
  b.write(type, 156, 'ascii');
  b.write('ustar\0', 257, 'ascii');
  b.write('00', 263, 'ascii');
  b.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const x of b) sum += x;
  b.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  return b;
}

function padded(data) {
  const out = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(out);
  return out;
}

function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  let len = Buffer.byteLength(body) + 1;
  while (String(len).length + Buffer.byteLength(body) !== len) len = String(len).length + Buffer.byteLength(body);
  return `${len}${body}`;
}

/** A gzipped tarball: global pax comment = sha, a top-level directory, then the files. */
function tarball(sha, top, files, { longNameVia = 'pax' } = {}) {
  const parts = [];
  const g = Buffer.from(paxRecord('comment', sha));
  parts.push(header('pax_global_header', g.length, 'g'), padded(g));
  parts.push(header(`${top}/`, 0, '5'));
  for (const [path, text] of Object.entries(files)) {
    const full = `${top}/${path}`;
    const data = Buffer.from(text);
    if (Buffer.byteLength(full) > 100) {
      if (longNameVia === 'pax') {
        const x = Buffer.from(paxRecord('path', full));
        parts.push(header('PaxHeaders/x', x.length, 'x'), padded(x));
      } else {
        const l = Buffer.from(full + '\0');
        parts.push(header('././@LongLink', l.length, 'L'), padded(l));
      }
      parts.push(header(full.slice(0, 99), data.length, '0'));
    } else {
      parts.push(header(full, data.length, '0'));
    }
    parts.push(padded(data));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

const LICENCE_TEXT = {
  elastic: 'Elastic License 2.0\n\nURL: https://www.elastic.co/licensing/elastic-license\n',
  splunk: '                                 Apache License\n                           Version 2.0, January 2004\n',
  mdecrevoisier: 'Creative Commons Legal Code\n\nCC0 1.0 Universal\n',
};

const LONG_DIR = 'windows-active_directory/a-very-long-folder-name-that-pushes-the-archive-path-past-one-hundred-bytes';

/** The three fixture repositories: one real rule each, plus a deprecated copy that must be skipped. */
function fixtureFiles(key) {
  if (key === 'elastic') {
    return {
      'LICENSE.txt': LICENCE_TEXT.elastic,
      'rules/windows/collection_email_outlook_mailbox_via_com.toml': ELASTIC,
      'rules/_deprecated/collection_email_outlook_mailbox_via_com.toml': ELASTIC.replace(/^name = ".*"$/m, 'name = "Deprecated copy"'),
      'rules_building_block/not_a_rule_dir.toml': ELASTIC,
      'README.md': '# not a rule\n',
    };
  }
  if (key === 'splunk') {
    return {
      LICENSE: LICENCE_TEXT.splunk,
      'detections/endpoint/7zip_commandline_to_smb_share_path.yml': SPLUNK,
      'detections/deprecated/7zip_commandline_to_smb_share_path.yml': SPLUNK.replace(/^name: .*$/m, 'name: Deprecated copy'),
      'stories/not_a_detection.yml': SPLUNK,
    };
  }
  return {
    'LICENSE.md': LICENCE_TEXT.mdecrevoisier,
    [`${LONG_DIR}/win-ad-kerberoast ticket detected.yaml`]: SIGMA,
    '.github/workflows/ci.yaml': 'title: not a rule\ntags:\n  - attack.t1000\n',
    'README.md': '# rules\n',
  };
}

const FAKE_PINS = {
  elastic: { ...PINS.elastic, sha: 'a'.repeat(40) },
  splunk: { ...PINS.splunk, sha: 'b'.repeat(40) },
  mdecrevoisier: { ...PINS.mdecrevoisier, sha: 'c'.repeat(40) },
};

const keyOf = (pin) => SOURCE_KEYS.find((k) => PINS[k].repo === pin.repo);
const fakeTarball = async (pin) =>
  tarball(pin.sha, `${pin.repo}-${pin.sha}`, fixtureFiles(keyOf(pin)), { longNameVia: keyOf(pin) === 'mdecrevoisier' ? 'pax' : 'gnu' });

function tempRoot() {
  const root = mkdtempSync(join(tmpdir(), 'rule-coverage-'));
  mkdirSync(join(root, 'src/assets/data'), { recursive: true });
  return root;
}

const quiet = () => {};

// ─── tar reader ─────────────────────────────────────────────────────────────

test('reads a ustar stream: global pax comment, top-level prefix, pax and GNU long names', async () => {
  const gz = tarball('d'.repeat(40), 'repo-ddd', { [`${LONG_DIR}/x.yaml`]: 'title: x\n', 'short.txt': 'hi' });
  const { gunzipSync } = await import('node:zlib');
  const { globalPax, entries } = readTar(gunzipSync(gz));
  assert.equal(globalPax.comment, 'd'.repeat(40));
  const files = entries.filter((e) => e.type === 'file').map((e) => stripTopDir(e.path));
  assert.deepEqual(files, [`${LONG_DIR}/x.yaml`, 'short.txt']);
  assert.equal(entries[0].type, 'dir');
  assert.equal(entries[0].mtime, MTIME);

  const gnu = readTar(gunzipSync(tarball('e'.repeat(40), 'r', { [`${LONG_DIR}/y.yaml`]: 'y' }, { longNameVia: 'gnu' })));
  assert.equal(stripTopDir(gnu.entries.find((e) => e.type === 'file').path), `${LONG_DIR}/y.yaml`);
});

test('rejects a corrupt header instead of reading garbage', async () => {
  const { gunzipSync } = await import('node:zlib');
  const tar = gunzipSync(tarball('f'.repeat(40), 'r', { 'a.txt': 'a' }));
  tar[1024 + 10] ^= 0xff; // flip a byte in the directory header's name
  assert.throws(() => readTar(tar), /checksum mismatch/);
});

// ─── parsers ────────────────────────────────────────────────────────────────

test('Elastic: [rule] name and technique/subtechnique ids; tactic ids and query text are not read', () => {
  const rule = parseElasticRule(ELASTIC);
  assert.equal(rule.name, 'Suspicious Inter-Process Communication via Outlook');
  assert.deepEqual([...rule.techniques].sort(), ['T1114', 'T1114.001', 'T1559', 'T1559.001']);
  assert.ok(ELASTIC.includes('id = "TA0009"'), 'the fixture names a tactic id');
  assert.ok(ELASTIC.includes('[process where'), 'the fixture query has lines that look like TOML tables');

  const tricky = [
    '[metadata]', 'name = "not the rule name"',
    '[rule]', 'name = "Quote \\"inside\\" name"',
    'query = """', '[[rule.threat.technique]]', 'id = "T9999"', '"""',
    '[[rule.threat]]', '[rule.threat.tactic]', 'id = "TA0002"',
    '  [[rule.threat.technique]]', '  id = "T1059"',
    '    [[rule.threat.technique.subtechnique]]', "    id = 't1059.001'",
    '[[rule.required_fields]]', 'name = "process.name"',
  ].join('\n');
  const t = parseElasticRule(tricky);
  assert.equal(t.name, 'Quote "inside" name');
  assert.deepEqual([...t.techniques].sort(), ['T1059', 'T1059.001']);
  assert.equal(parseElasticRule('[metadata]\ncreation_date = "2020/01/01"\n'), null);
});

test('Splunk: name and mitre_attack_id (top level, under tags:, flow style, with comments)', () => {
  const rule = parseSplunkDetection(SPLUNK);
  assert.equal(rule.name, '7zip CommandLine To SMB Share Path');
  assert.deepEqual([...rule.techniques], ['T1560.001']);

  const older = [
    'name: "Older schema: tags"', "search: '| tstats count",
    "  name: not a key'",
    'description: |', '  name: inside a block scalar', '  mitre_attack_id:', '  - T9998',
    'tags:', '  analytic_story:', '  - Something', '  mitre_attack_id:', '  - T1003.001 # OS Credential Dumping', "  - 'T1059'", '  - TA0001',
  ].join('\n');
  const o = parseSplunkDetection(older);
  assert.equal(o.name, 'Older schema: tags');
  assert.deepEqual([...o.techniques].sort(), ['T1003.001', 'T1059']);
  assert.deepEqual([...parseSplunkDetection('name: flow\nmitre_attack_id: [T1059, "T1003.001"]\n').techniques], ['T1059', 'T1003.001']);
  assert.equal(parseSplunkDetection('mitre_attack_id: []\n'), null);
});

test('mdecrevoisier: title and attack.tNNNN tags (any case), across documents; tactics ignored', () => {
  const rule = parseSigmaRule(SIGMA);
  assert.equal(rule.name, 'Kerberoast ticket request detected');
  assert.deepEqual([...rule.techniques], ['T1558.003']);
  assert.ok(SIGMA.includes('attack.credential_access'), 'the fixture carries a tactic tag');
  assert.ok(/^---$/m.test(SIGMA), 'the fixture holds two YAML documents');

  assert.equal(sigmaTagTechnique('ATTACK.T1059.001'), 'T1059.001');
  assert.equal(sigmaTagTechnique('attack.t1098 # Account Manipulation'.split(' #')[0]), 'T1098');
  assert.equal(sigmaTagTechnique('attack.defense_evasion'), null);
  assert.equal(sigmaTagTechnique('attack.ta0001'), null);
  const flow = parseSigmaRule("title: 'It''s flow'\ntags: [attack.T1110, attack.discovery]\n");
  assert.equal(flow.name, "It's flow");
  assert.deepEqual([...flow.techniques], ['T1110']);
});

test('reads the upstream LICENSE text, never assumes it', () => {
  assert.equal(identifyLicence(LICENCE_TEXT.elastic), 'Elastic-2.0');
  assert.equal(identifyLicence(LICENCE_TEXT.splunk), 'Apache-2.0');
  assert.equal(identifyLicence(LICENCE_TEXT.mdecrevoisier), 'CC0-1.0');
  assert.equal(identifyLicence('All rights reserved.'), null);
  const files = [{ path: 'LICENSE', data: Buffer.from('All rights reserved.') }];
  assert.throws(() => buildSource('splunk', FAKE_PINS.splunk, files, '2026-10-20T23:33:59Z'), /LICENSE text not recognised/);
  assert.throws(() => buildSource('splunk', FAKE_PINS.splunk, [], '2026-10-20T23:33:59Z'), /LICENSE file not found/);
});

test('a parent technique counts each rule once, whether it names the parent, a sub-technique or both', () => {
  const rule = (name, ids) => `[rule]\nname = "${name}"\n` + ids.map((id) => `[[rule.threat.technique]]\nid = "${id}"\n`).join('');
  const files = [
    { path: 'LICENSE.txt', data: Buffer.from(LICENCE_TEXT.elastic) },
    { path: 'rules/a.toml', data: Buffer.from(rule('A', ['T1059', 'T1059.001'])) },
    { path: 'rules/b.toml', data: Buffer.from(rule('B', ['T1059.003'])) },
    { path: 'rules/c.toml', data: Buffer.from(rule('C', ['T1059'])) },
    { path: 'rules/d.toml', data: Buffer.from(rule('D', [])) },
  ];
  const { source, mapped } = buildSource('elastic', FAKE_PINS.elastic, files, '2026-10-21T07:09:07Z', 2);
  assert.equal(source.ruleCount, 4);
  assert.equal(mapped, 3);
  assert.equal(source.techniques.T1059.count, 3);
  assert.deepEqual(source.techniques.T1059.rules.map((r) => r.name), ['A', 'B'], 'sorted, capped at maxRules; the count stays whole');
  assert.equal(source.techniques['T1059.001'].count, 1);
  assert.equal(source.techniqueCount, 3);
});

// ─── the command, offline ────────────────────────────────────────────────────

test('builds all three sources from tarballs: deprecated paths excluded, pins and dates recorded', async () => {
  const root = tempRoot();
  try {
    // No committed file yet: the build starts from PINS.
    const pinsUsed = [];
    const code = await run([], { root, log: quiet, getTarball: async (pin) => { pinsUsed.push(pin.sha); return fakeTarball({ ...pin, sha: pin.sha }); } });
    assert.equal(code, 0);
    assert.deepEqual(pinsUsed, SOURCE_KEYS.map((k) => PINS[k].sha));
    const text = readFileSync(join(root, OUT), 'utf8');
    const doc = JSON.parse(text);
    assert.deepEqual(validateSnapshot(doc), []);
    assert.equal(text, serialize(doc), 'sorted keys, two-space indent, LF, trailing newline');
    assert.ok(!text.includes('\r'));
    assert.equal(doc.generated, PINNED_ON);

    const e = doc.sources.elastic;
    assert.equal(e.ruleCount, 1, 'rules/_deprecated/ and rules_building_block/ are not read');
    assert.equal(e.licence, 'Elastic-2.0');
    assert.equal(e.commitDate, '2026-10-20T23:33:59Z');
    assert.deepEqual(Object.keys(e.techniques), ['T1114', 'T1114.001', 'T1559', 'T1559.001']);
    assert.deepEqual(e.techniques.T1114.rules, [{ name: 'Suspicious Inter-Process Communication via Outlook', path: 'rules/windows/collection_email_outlook_mailbox_via_com.toml' }]);
    assert.ok(!text.includes('TA0009') && !text.includes('Deprecated copy'));

    const s = doc.sources.splunk;
    assert.equal(s.ruleCount, 1, 'detections/deprecated/ and files outside detections/ are not read');
    assert.equal(s.licence, 'Apache-2.0');
    assert.deepEqual(Object.keys(s.techniques), ['T1560', 'T1560.001']);
    assert.equal(s.branch, 'develop');

    const m = doc.sources.mdecrevoisier;
    assert.equal(m.ruleCount, 1, 'dot-directories are not read');
    assert.equal(m.licence, 'CC0-1.0');
    assert.deepEqual(Object.keys(m.techniques), ['T1558', 'T1558.003']);
    assert.equal(m.techniques['T1558.003'].rules[0].path, `${LONG_DIR}/win-ad-kerberoast ticket detected.yaml`, 'pax long path, top-level directory removed');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('--check passes on the file it wrote and fails on a tampered copy, rebuilding at the SHAs the file records', async () => {
  const root = tempRoot();
  try {
    const target = join(root, OUT);
    // Seed a file that records the fake pins: the rebuild must use them, not PINS.
    const seeded = { generated: '2026-09-01', sources: {} };
    for (const k of SOURCE_KEYS) seeded.sources[k] = { ...FAKE_PINS[k] };
    writeFileSync(target, JSON.stringify(seeded));
    const used = [];
    const getTarball = async (pin) => { used.push(pin.sha); return fakeTarball(pin); };
    assert.equal(await run([], { root, log: quiet, getTarball }), 0);
    assert.deepEqual(used, SOURCE_KEYS.map((k) => FAKE_PINS[k].sha));
    const good = readFileSync(target, 'utf8');
    assert.equal(JSON.parse(good).generated, '2026-09-01');

    assert.equal(await run(['--check'], { root, log: quiet, getTarball }), 0);
    // A Windows checkout may hold CRLF: still a match.
    writeFileSync(target, good.replace(/\n/g, '\r\n'));
    assert.equal(await run(['--check'], { root, log: quiet, getTarball }), 0);

    const errors = [];
    const origError = console.error;
    console.error = (m) => errors.push(String(m));
    try {
      writeFileSync(target, good.replace('"count": 1', '"count": 2'));
      assert.equal(await run(['--check'], { root, log: quiet, getTarball }), 1);
      assert.match(errors.join('\n'), /differs from a rebuild/);
    } finally {
      console.error = origError;
    }
    assert.notEqual(readFileSync(target, 'utf8'), good, '--check writes nothing');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('--update-pins resolves each branch head, rewrites PINS and records the date', async () => {
  const root = tempRoot();
  try {
    mkdirSync(join(root, 'scripts'), { recursive: true });
    writeFileSync(join(root, SCRIPT), read(SCRIPT));
    const asked = [];
    const resolveHead = (pin) => { asked.push(`${pin.owner}/${pin.repo}@${pin.branch}`); return FAKE_PINS[keyOf(pin)].sha; };
    assert.equal(await run(['--update-pins'], { root, log: quiet, getTarball: fakeTarball, resolveHead, today: '2026-11-03' }), 0);
    assert.deepEqual(asked, ['elastic/detection-rules@main', 'splunk/security_content@develop', 'mdecrevoisier/SIGMA-detection-rules@main']);
    const doc = JSON.parse(readFileSync(join(root, OUT), 'utf8'));
    assert.equal(doc.generated, '2026-11-03');
    assert.equal(doc.sources.splunk.sha, 'b'.repeat(40));
    const script = readFileSync(join(root, SCRIPT), 'utf8');
    assert.match(script, /export const PINNED_ON = '2026-11-03';/);
    assert.match(script, new RegExp(`sha: '${'c'.repeat(40)}'`));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rewriting PINS with the committed values leaves the script unchanged', () => {
  const script = read(SCRIPT);
  assert.equal(rewritePins(script, PINS, PINNED_ON), script);
});

// ─── the shipped file ───────────────────────────────────────────────────────

test('the shipped snapshot is sound, in its serialised form, and names its pins', () => {
  const text = read(OUT);
  const doc = JSON.parse(text);
  assert.deepEqual(validateSnapshot(doc), []);
  assert.equal(serialize(doc), text);
  assert.ok(pinsFromSnapshot(doc), 'every source records owner, repo, branch and sha');
  assert.ok(Buffer.byteLength(text) <= SIZE_LIMIT || Object.values(doc.sources).every((s) =>
    Object.values(s.techniques).every((t) => t.rules.length <= FALLBACK_MAX_RULES)));
  for (const s of Object.values(doc.sources)) {
    for (const t of Object.values(s.techniques)) assert.ok(t.rules.length <= MAX_RULES);
  }
  assert.equal(doc.sources.elastic.licence, 'Elastic-2.0');
  assert.equal(doc.sources.splunk.licence, 'Apache-2.0');
  assert.equal(doc.sources.mdecrevoisier.licence, 'CC0-1.0');
  assert.ok(doc.sources.elastic.techniques.T1059.count > 0);
  assert.ok(doc.sources.splunk.techniques.T1059.count > 0);
});

test('the monthly refresh moves the pins and rebuilds the file before it detects changes', () => {
  const wf = read('.github/workflows/refresh-data.yml');
  const step = wf.indexOf('node scripts/build-rule-coverage-snapshot.mjs --update-pins');
  assert.ok(step > 0, 'refresh-data.yml runs --update-pins');
  assert.ok(step < wf.indexOf('name: Detect changes'), 'before the change detection, so the review PR carries the file');
});

test('the verbatim upstream fixtures travel with their licence terms', () => {
  const readme = read(`${FIX}/README.md`);
  const terms = [
    // [fixture, licence file, what identifyLicence must read from it]
    ['elastic-rule.toml', 'licenses/elastic-detection-rules-LICENSE.txt', 'Elastic-2.0'],
    ['splunk-detection.yml', 'licenses/splunk-security_content-LICENSE', 'Apache-2.0'],
  ];
  for (const [fixture, licence, spdx] of terms) {
    assert.match(readme, new RegExp(`\`${fixture.replace('.', '\.')}\``), `${fixture} is listed`);
    assert.ok(readme.includes(`(${licence})`), `the README links ${licence}`);
    assert.equal(identifyLicence(read(`${FIX}/${licence}`)), spdx, `${licence} holds the ${spdx} terms`);
  }
  assert.match(read(`${FIX}/licenses/elastic-detection-rules-NOTICE.txt`), /^Detection Rules\nCopyright \d{4} Elasticsearch B\.V\./);
  assert.match(readme, /CC0 1\.0 Universal/);
});

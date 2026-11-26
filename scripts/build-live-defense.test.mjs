// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Unit tests for the Live Defense brain (scripts/build-live-defense.mjs): the
// anchor mapping is high-confidence-only and fails quiet, heat decays with
// recency and ransomware severity, and the accuracy gate catches un-sourced
// heat, a non-KEV CVE, a dead technique id and a brief that over-claims.
//
//   node --test scripts/build-live-defense.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAnchor, techniquesForKev, buildModel, buildArtifacts, gate } from './build-live-defense.mjs';
import { lintText } from './lint-truth-vocab.mjs';

const anchor = buildAnchor({
  exploitationClasses: {
    'injection-rce': { techniques: ['T1190', 'T1059'], rationale: 'Injection yields code execution.', cwes: ['78'] },
    'auth-bypass': { techniques: ['T1190', 'T1078'], rationale: 'Auth bypass gives access.', cwes: ['287'] },
  },
  rceKeywords: ['remote code execution'],
  rceTechniques: ['T1059'],
  remoteAccessApplianceKeywords: ['netscaler'],
  remoteAccessTechniques: ['T1133'],
});

const bundleById = new Map([
  ['T1190', { name: 'Exploit Public-Facing Application', tactics: ['initial-access'] }],
  ['T1059', { name: 'Command and Scripting Interpreter', tactics: ['execution'] }],
  ['T1078', { name: 'Valid Accounts', tactics: ['initial-access', 'persistence'] }],
  ['T1133', { name: 'External Remote Services', tactics: ['initial-access'] }],
]);

test('anchors a CWE to its exploitation techniques (high confidence)', () => {
  const m = techniquesForKev({ cwes: ['CWE-78'], vulnerabilityName: 'x' }, anchor);
  assert.deepEqual([...m.keys()].sort(), ['T1059', 'T1190']);
  assert.equal(m.get('T1190').confidence, 'high');
});

test('fails quiet: a CWE with no anchor maps nothing', () => {
  assert.equal(techniquesForKev({ cwes: ['CWE-999'], vulnerabilityName: 'x' }, anchor).size, 0);
});

test('a keyword alone never heats a technique (needs a weakness anchor first)', () => {
  // No CWE -> nothing, even though the text names remote code execution / NetScaler.
  assert.equal(techniquesForKev({ cwes: [], vulnerabilityName: 'remote code execution NetScaler' }, anchor).size, 0);
});

test('text hints are medium confidence and add on top of an anchor', () => {
  const m = techniquesForKev({ cwes: ['CWE-78'], vulnerabilityName: 'NetScaler remote code execution' }, anchor);
  assert.equal(m.get('T1133').confidence, 'medium'); // remote-access appliance hint
  assert.equal(m.get('T1059').confidence, 'high');   // high from CWE-78 wins over the rce keyword
});

test('heat decays with age and ransomware raises it', () => {
  const kevDoc = {
    __meta: { snapshotDate: '2026-10-16', catalogVersion: '2026.10.16' },
    vulnerabilities: [
      { cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'fresh', knownRansomwareCampaignUse: 'Known' },
      { cveID: 'CVE-2020-0002', cwes: ['CWE-78'], dateAdded: '2021-11-03', vulnerabilityName: 'old', knownRansomwareCampaignUse: 'Unknown' },
    ],
  };
  const model = buildModel(kevDoc, anchor, bundleById);
  const t1190 = model.list.find((t) => t.id === 'T1190');
  // Fresh ransomware entry weighs 1.5; a ~5-year-old entry decays to near zero.
  assert.ok(t1190.heat > 1.49 && t1190.heat < 1.6, `heat ${t1190.heat}`);
  assert.equal(t1190.ransomware, 1);
});

function soundArtifacts() {
  const kevDoc = {
    __meta: { snapshotDate: '2026-10-16', catalogVersion: '2026.10.16' },
    vulnerabilities: [{ cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'name', knownRansomwareCampaignUse: 'Known' }],
  };
  const model = buildModel(kevDoc, anchor, bundleById);
  const { layer, evidenceDoc } = buildArtifacts(model, bundleById, '19.2');
  return { kevDoc, layer, evidenceDoc };
}

test('the gate passes sound artifacts', () => {
  const { kevDoc, layer, evidenceDoc } = soundArtifacts();
  assert.deepEqual(gate(layer, evidenceDoc, kevDoc, bundleById, lintText), []);
});

test('the gate rejects a CVE that is not in the KEV snapshot', () => {
  const { kevDoc, layer, evidenceDoc } = soundArtifacts();
  evidenceDoc.techniques.T1190.items[0].cve = 'CVE-1999-9999';
  assert.ok(gate(layer, evidenceDoc, kevDoc, bundleById, lintText).some((p) => /not in the KEV snapshot/.test(p)));
});

test('the gate rejects un-sourced heat (a technique with no items)', () => {
  const { kevDoc, layer, evidenceDoc } = soundArtifacts();
  evidenceDoc.techniques.T1190.items = [];
  assert.ok(gate(layer, evidenceDoc, kevDoc, bundleById, lintText).some((p) => /no sourced items/.test(p)));
});

test('the gate rejects an over-claiming brief (truth-vocab)', () => {
  const { kevDoc, layer, evidenceDoc } = soundArtifacts();
  evidenceDoc.techniques.T1190.brief = 'This technique is fully protected and proven secure.';
  assert.ok(gate(layer, evidenceDoc, kevDoc, bundleById, lintText).some((p) => /truth-vocab/.test(p)));
});

test('a duplicate KEV row is counted once', () => {
  const kevDoc = {
    __meta: { snapshotDate: '2026-10-16', catalogVersion: '2026.10.16' },
    vulnerabilities: [
      { cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'dup', knownRansomwareCampaignUse: 'Unknown' },
      { cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'dup', knownRansomwareCampaignUse: 'Unknown' },
    ],
  };
  const t1190 = buildModel(kevDoc, anchor, bundleById).list.find((t) => t.id === 'T1190');
  assert.equal(t1190.items.length, 1);
  assert.equal(t1190.items[0].cve, 'CVE-2026-0001');
});

test('an invalid snapshotDate is refused, not silently turned into NaN heat', () => {
  const kevDoc = {
    __meta: { snapshotDate: 'not-a-date', catalogVersion: 'x' },
    vulnerabilities: [{ cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'x', knownRansomwareCampaignUse: 'Unknown' }],
  };
  assert.throws(() => buildModel(kevDoc, anchor, bundleById), /snapshotDate is not a valid/);
});

test('a malformed dateAdded heats nothing (fail quiet), it does not poison the technique', () => {
  const kevDoc = {
    __meta: { snapshotDate: '2026-10-16', catalogVersion: 'x' },
    vulnerabilities: [
      { cveID: 'CVE-2026-0001', cwes: ['CWE-78'], dateAdded: 'garbage', vulnerabilityName: 'bad', knownRansomwareCampaignUse: 'Unknown' },
      { cveID: 'CVE-2026-0002', cwes: ['CWE-78'], dateAdded: '2026-10-16', vulnerabilityName: 'good', knownRansomwareCampaignUse: 'Unknown' },
    ],
  };
  const t1190 = buildModel(kevDoc, anchor, bundleById).list.find((t) => t.id === 'T1190');
  assert.equal(t1190.items.length, 1); // only the good row
  assert.ok(Number.isFinite(t1190.heat) && t1190.heat > 0);
});

test('the gate rejects a technique id the bundle does not carry', () => {
  const { kevDoc, layer, evidenceDoc } = soundArtifacts();
  evidenceDoc.techniques.T9999 = { ...evidenceDoc.techniques.T1190, techniqueID: 'T9999' };
  layer.techniques.push({ techniqueID: 'T9999', score: 1, color: '#111', comment: 'x', enabled: true });
  assert.ok(gate(layer, evidenceDoc, kevDoc, bundleById, lintText).some((p) => /not a live Enterprise technique/.test(p)));
});

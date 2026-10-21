// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Lylat validated-detections contract consumer (P2-20). These tests pin the
// six acceptance criteria of the pure contract layer and share the same synthetic
// fixture + invalid corpus the CI check (scripts/check-lylat-contract.mjs) uses,
// so the dependency-free validator here and the JSON schema there cannot drift.
import {
  validateLylatExport,
  lylatRowsToRuns,
  statusForRow,
  LYLAT_CONTRACT_SCHEMA,
  LYLAT_PRIVACY_RE,
  LylatExportV1,
} from './lylat-validated-detections';
import { refForTechnique, techniqueRefKey } from '../models/technique-ref';

import FIXTURE from '../../testing/fixtures/lylat/validated-detections.fixture.json';
import INVALID_HOSTNAME from '../../testing/fixtures/lylat/invalid/hostname.json';
import INVALID_BAD_ENUM from '../../testing/fixtures/lylat/invalid/bad-enum.json';
import INVALID_IP from '../../testing/fixtures/lylat/invalid/ip-evidence.json';
import INVALID_MISSING_BUILD from '../../testing/fixtures/lylat/invalid/missing-build-ref.json';
import INVALID_EXTRA_REF from '../../testing/fixtures/lylat/invalid/extra-key-technique-ref.json';
import INVALID_AT_SIGN from '../../testing/fixtures/lylat/invalid/at-sign-evidence.json';

const IDENTITY = (id: string) => id;
const KNOWS_ALL = () => true;

/** A single-row export built around `ref`, otherwise valid and privacy-clean. */
function oneRow(ref: { domain: string; id: string; attack_version: string }): LylatExportV1 {
  return {
    schema: LYLAT_CONTRACT_SCHEMA,
    range_build_ref: 'abc1234',
    generated_at: '2026-10-18T00:00:00Z',
    rows: [
      {
        mission_id: 'SYNTH-MISSION-A',
        technique_ref: ref,
        detection_ref: 'wazuh:990001',
        coverage_state: 'validated',
        outcome: 'alerted',
        negative_control: 'detection-only',
        validated_at: '2026-10-18',
        evidence_ref: 'SYNTH-MISSION-A-step1',
      },
    ],
  } as unknown as LylatExportV1;
}

function allRuns(e: LylatExportV1) {
  const { bySource, skipped } = lylatRowsToRuns(e, IDENTITY, 'enterprise', '19.2', KNOWS_ALL);
  return { runs: [...bySource.values()].flat().map((t) => t.run), bySource, skipped };
}

describe('Lylat validated-detections contract (P2-20)', () => {
  // AC1: an imported run is keyed at import, exactly as a manual run of the same
  // technique is, so the two keys are indistinguishable.
  it('keys an imported run the same way a manual run of the technique is keyed', () => {
    const parsed = validateLylatExport(FIXTURE);
    expect(parsed.ok).toBeTrue();
    if (!parsed.ok) return;
    const { runs } = allRuns(parsed.value);

    const run = runs.find((r) => r.techniqueId === 'T1059.001');
    expect(run).toBeDefined();
    const manualKey = techniqueRefKey(refForTechnique({ attackId: 'T1059.001' }, 'enterprise', '19.2'));
    expect(run!.techniqueRef).toBe(manualKey);
    expect(run!.techniqueRef).toBe('attack/enterprise/T1059.001@19.2');
    expect(run!.source).toBe('lylat-range:SYNTH-MISSION-A');
    expect(run!.proofScope).toBe('range');
    expect(run!.statusFromSource).toBeTrue();
    expect(run!.id).toBe('lylat:SYNTH-MISSION-A:4');
  });

  it('maps the fixture to 8 runs over 6 techniques, a technique with two rules keeping both', () => {
    const parsed = validateLylatExport(FIXTURE);
    if (!parsed.ok) throw new Error(parsed.errors.join('; '));
    const { runs } = allRuns(parsed.value);

    expect(runs.length).toBe(8);
    expect(new Set(runs.map((r) => r.techniqueId)).size).toBe(6);
    const t1558 = runs.filter((r) => r.techniqueId === 'T1558.003');
    expect(t1558.map((r) => r.detectionsExpected[0]).sort()).toEqual(['wazuh:990001', 'wazuh:990002']);
  });

  // AC2: a row whose technique does not resolve to a parseable ref in the domain
  // is skipped at import, not kept with a null key for a renderer to resolve later.
  it('skips a row whose technique does not resolve in its domain', () => {
    const e = oneRow({ domain: 'enterprise', id: 'AML.T0051', attack_version: '19.2' });
    expect(validateLylatExport(e).ok).toBeTrue();
    const { bySource, skipped } = allRuns(e);
    expect(bySource.size).toBe(0);
    expect(skipped.length).toBe(1);
    expect(skipped[0].reason).toContain('does not resolve');
  });

  // AC2 (domain existence): a well-formed id that parses but is not a technique
  // of the loaded domain (a retired or future id) is skipped at import, never
  // stored as a run for a technique the matrix has no cell for.
  it('skips a well-formed id that is not a technique of the loaded domain', () => {
    const e = oneRow({ domain: 'enterprise', id: 'T9999.999', attack_version: '19.2' });
    expect(validateLylatExport(e).ok).toBeTrue(); // well-formed per the schema
    const known = new Set(['T1059.001']); // T9999.999 is not a technique of the domain
    const { bySource, skipped } = lylatRowsToRuns(e, IDENTITY, 'enterprise', '19.2', (id) => known.has(id));
    expect(bySource.size).toBe(0);
    expect(skipped.length).toBe(1);
    expect(skipped[0].reason).toContain('not a technique of the loaded');
  });

  // AC3 (version): an imported run is keyed with the LOADED domain version, exactly
  // like a manual run, regardless of the version the row names; the row's version
  // is kept only as provenance on the outcome.
  it('keys with the loaded domain version and keeps the row version as provenance', () => {
    const e = oneRow({ domain: 'enterprise', id: 'T1059.001', attack_version: '18.0' });
    const { bySource } = lylatRowsToRuns(e, IDENTITY, 'enterprise', '19.2', KNOWS_ALL);
    const run = [...bySource.values()].flat()[0].run;
    expect(run.techniqueRef).toBe('attack/enterprise/T1059.001@19.2'); // loaded 19.2, not the row's 18.0
    expect(run.attackVersion).toBe('19.2');
    expect(run.outcomes[0].sourceAttackVersion).toBe('18.0');
  });

  // AC5: an ATLAS technique has no ATT&CK domain in Navi today, so its row is skipped.
  it('skips an ATLAS row', () => {
    const e = oneRow({ domain: 'atlas', id: 'AML.T0051', attack_version: '19.2' });
    expect(validateLylatExport(e).ok).toBeTrue();
    const { bySource, skipped } = allRuns(e);
    expect(bySource.size).toBe(0);
    expect(skipped.length).toBe(1);
    expect(skipped[0].reason).toContain('atlas');
  });

  it('maps coverage_state and outcome to the documented status', () => {
    const passed = FIXTURE.rows[0] as unknown as Parameters<typeof statusForRow>[0];
    expect(statusForRow(passed)).toBe('passed');
    const partial = FIXTURE.rows[6] as unknown as Parameters<typeof statusForRow>[0];
    expect(partial.coverage_state).toBe('telemetry-observed');
    expect(statusForRow(partial)).toBe('partial');
    expect(statusForRow({ ...passed, negative_control: 'not-reproducible' })).toBe('not-reproducible');
    expect(statusForRow({ ...passed, coverage_state: 'deployed', outcome: 'none' })).toBe('untested');
  });

  // AC4: the privacy regex refuses a captured host, path, account, address or whitespace
  // in any of the three free-id fields, and refuses the whole export.
  it('refuses a privacy leak in a free-id field', () => {
    expect(LYLAT_PRIVACY_RE.test('wazuh:990001')).toBeFalse();
    expect(LYLAT_PRIVACY_RE.test('SYNTH-MISSION-A-step1')).toBeFalse();
    expect(LYLAT_PRIVACY_RE.test('/etc/passwd')).toBeTrue();
    expect(LYLAT_PRIVACY_RE.test('user@host')).toBeTrue();
    expect(LYLAT_PRIVACY_RE.test('a b')).toBeTrue();
    expect(LYLAT_PRIVACY_RE.test('10.0.0.5')).toBeTrue();

    const result = validateLylatExport(INVALID_IP);
    expect(result.ok).toBeFalse();
    if (!result.ok) expect(result.errors.some((e) => e.includes('privacy'))).toBeTrue();
  });

  // AC6: the validator accepts the fixture and rejects every invalid-corpus file,
  // in parity with the CI schema check that runs the same corpus.
  it('accepts the fixture and rejects every invalid-corpus file (parity with CI)', () => {
    expect(validateLylatExport(FIXTURE).ok).toBeTrue();
    for (const bad of [INVALID_HOSTNAME, INVALID_BAD_ENUM, INVALID_IP, INVALID_MISSING_BUILD, INVALID_EXTRA_REF, INVALID_AT_SIGN]) {
      expect(validateLylatExport(bad).ok).toBeFalse();
    }
  });

  it('refuses a non-contract object', () => {
    expect(validateLylatExport({ schema: 'something-else' }).ok).toBeFalse();
    expect(validateLylatExport(null).ok).toBeFalse();
    expect(validateLylatExport([]).ok).toBeFalse();
  });
});

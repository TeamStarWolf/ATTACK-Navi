// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The RP-F round-8 breaker's run shapes (g35), as stored runs: the contract rows go
// through the contract mapper (lylatRowsToRuns) and the store allowlist (sanitizeRun),
// the Import JSON shapes through sanitizeRun, exactly as "Import range results" and
// "Import JSON" store them. Specs read every surface's words from these runs.
import { lylatRowsToRuns, type LylatExportV1 } from '../contracts/lylat-validated-detections';
import { sanitizeRun, type ValidationRunV2 } from '../services/validation.service';

/** [technique, coverage_state, outcome, rule, negative_control, validated_at] */
type Row = readonly [string, string, string, string, string, string];

/** The multi-row and same-rule contract shapes of the round-8 walk (g35.cjs). */
export const RPF8_CONTRACT_ROWS: readonly Row[] = [
  ['T1082', 'telemetry-observed', 'alerted', 'wazuh:12', 'detection-only', '2026-10-21'],
  ['T1200', 'telemetry-observed', 'logged', 'wazuh:5', 'detection-only', '2026-10-21'],
  ['T1113', 'telemetry-observed', 'alerted', 'wazuh:201', 'detection-only', '2026-10-21'],
  ['T1113', 'telemetry-observed', 'logged', 'wazuh:202', 'detection-only', '2026-10-21'],
  ['T1057', 'telemetry-observed', 'logged', 'wazuh:203', 'detection-only', '2026-10-21'],
  ['T1057', 'validated', 'alerted', 'wazuh:204', 'detection-only', '2026-10-21'],
  ['T1120', 'telemetry-observed', 'blocked', 'wazuh:205', 'not-reproducible', '2026-10-21'],
  ['T1105', 'telemetry-observed', 'logged', 'wazuh:206', 'detection-only', '2026-10-20'],
  ['T1105', 'telemetry-observed', 'alerted', 'wazuh:206', 'detection-only', '2026-10-21'],
  ['T1005', 'telemetry-observed', 'alerted', 'wazuh:207', 'detection-only', '2026-10-21'],
  ['T1005', 'deployed', 'none', 'wazuh:207', 'detection-only', '2026-10-21'],
  ['T1119', 'telemetry-observed', 'blocked', 'wazuh:208', 'blocked-on-hardened', '2026-10-21'],
  ['T1119', 'telemetry-observed', 'alerted', 'wazuh:209', 'detection-only', '2026-10-21'],
  ['T1037.001', 'detection-authored', 'logged', 'wazuh:111', 'detection-only', '2026-10-21'],
  ['T1550.002', 'detection-authored', 'blocked', 'wazuh:110', 'blocked-on-hardened', '2026-10-21'],
  ['T1090.002', 'validated', 'logged', 'wazuh:103', 'detection-only', '2026-10-21'],
];

/** A contract export of `rows` (lylat-validated-detections/1). */
export function rpf8Contract(rows: readonly Row[] = RPF8_CONTRACT_ROWS, mission = 'R8-BREAK'): LylatExportV1 {
  return {
    schema: 'lylat-validated-detections/1', range_build_ref: 'abcdef1', generated_at: '2026-10-21T15:00:00Z',
    rows: rows.map(([id, cs, oc, rule, nc, d], i) => ({
      mission_id: mission, technique_ref: { domain: 'enterprise', id, attack_version: '19.2' }, detection_ref: rule,
      coverage_state: cs, outcome: oc, negative_control: nc, validated_at: d, evidence_ref: `${mission}-step${i + 1}`,
    })),
  } as unknown as LylatExportV1;
}

let jn = 0;
/** An Import JSON range run (g35.cjs J), before the store allowlist. */
function j(techniqueId: string, over: Record<string, unknown>): Record<string, unknown> {
  return {
    id: `j35-${++jn}`, techniqueId, techniqueName: '', runDate: '2026-10-21', operator: '', telemetryRequired: [], telemetryAvailable: [],
    atomicTestId: '', atomicCommand: '', attackResult: 'executed', detectionsExpected: [], detectionsFired: [], responsePlaybook: '',
    responseActions: [], evidenceLinks: [], notes: '', status: 'partial', source: 'lylat-range:J35', missionId: 'J35', ...over,
  };
}
const tel = (ref: string | null, oc: string) => ({
  detectionRef: ref, outcome: oc, coverageState: 'telemetry-observed', negativeControl: 'detection-only', evidenceRef: 'J35-x', sourceAttackVersion: '19.2',
});

/** The same-run Import JSON shapes of the round-8 walk (g35.cjs JSHAPES). */
export const RPF8_JSON_SHAPES: Readonly<Record<string, Record<string, unknown>>> = {
  T1221: j('T1221', { detectionsExpected: ['wazuh:301'], detectionsFired: ['wazuh:301'], outcomes: [tel(null, 'alerted')] }),
  T1140: j('T1140', { detectionsExpected: ['wazuh:302'], detectionsFired: ['wazuh:302'], outcomes: [tel('wazuh:302', 'logged')] }),
  T1560: j('T1560', { detectionsExpected: ['wazuh:303', 'wazuh:304'], outcomes: [tel('wazuh:303', 'logged'), { detectionRef: 'wazuh:304', outcome: 'alerted' }] }),
  T1092: j('T1092', { detectionsExpected: ['wazuh:305'], outcomes: [tel('  ', 'alerted')] }),
  T1030: j('T1030', { detectionsExpected: ['wazuh:306'], detectionsFired: ['wazuh:306'], outcomes: [tel('WAZUH:306', 'logged')] }),
  'T1027.013': j('T1027.013', { status: 'passed', attackResult: 'errored', detectionsExpected: ['wazuh:307'], detectionsFired: ['wazuh:307'], outcomes: [tel('wazuh:307', 'alerted')] }),
  T1213: j('T1213', { status: 'passed', detectionsExpected: ['wazuh:308', 'wazuh:309'], detectionsFired: ['wazuh:308'], outcomes: [tel('wazuh:309', 'logged'), { detectionRef: 'wazuh:308', outcome: 'alerted', coverageState: 'validated' }] }),
};

/**
 * Every stored run of the round-8 shapes, by technique id: the contract rows as "Import
 * range results" stores them and the Import JSON shapes as "Import JSON" stores them.
 */
export function rpf8Runs(): Map<string, ValidationRunV2[]> {
  const out = new Map<string, ValidationRunV2[]>();
  const add = (r: ValidationRunV2) => out.set(r.techniqueId, [...(out.get(r.techniqueId) ?? []), r]);
  const mapped = lylatRowsToRuns(rpf8Contract(), id => id, 'enterprise', '19.2', () => true);
  for (const [source, tagged] of mapped.bySource) {
    for (const { run } of tagged) {
      const r = sanitizeRun(run, source);
      if ('run' in r) add(r.run);
    }
  }
  for (const x of Object.values(RPF8_JSON_SHAPES)) {
    const r = sanitizeRun(x);
    if ('run' in r) add(r.run);
  }
  return out;
}

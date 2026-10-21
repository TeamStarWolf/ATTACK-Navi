// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Consumer of the Lylat range "validated-detections" contract, version
// `lylat-validated-detections/1` (Phase 2 design §3 P2-20, E2.5-a). A range
// export lists, per mission, the detection rules that fired (or blocked) against
// a technique during a validated, published range run. Navi imports it LOCALLY
// (FileReader only; never leaves the browser) as range-scoped Proven evidence.
//
// This module is the pure contract layer: the row/export types, a dependency-free
// strict validator (no ajv), the client-side privacy regex, and the mapping to
// the v2 ValidationRun store. The structure mirrors Navi's own consumer schema at
// docs/contracts/lylat-validated-detections.schema.json (a provisional structural
// pin of the producer schema; see docs/contracts/PROVENANCE.md). The privacy rule
// is enforced twice: structurally (unknown keys rejected at all three levels) and
// by a regex over the three free-id fields, so a captured hostname, path, IP,
// username or rule body is refused before anything is stored.
//
// Type-only import of the v2 run types (no runtime dependency on the service, so
// no import cycle; ValidationService imports the functions below at runtime).
import type { ValidationRunV2, ValidationOutcome, ValidationStatus } from '../services/validation.service';
// Pure ref helpers (no service dependency): an imported run is keyed at import
// through the SAME refForTechnique/techniqueRefKey a manual run uses, so its key
// is indistinguishable from a manual run's for the same technique (R6 §3).
import { refForTechnique, techniqueRefKey, parseTechniqueRef } from '../models/technique-ref';
import type { AttackDomain } from '../services/data.service';

export type LylatDomain = 'enterprise' | 'ics' | 'mobile' | 'atlas';
export type LylatCoverageState = 'validated' | 'telemetry-observed' | 'detection-authored' | 'deployed';
export type LylatOutcome = 'alerted' | 'blocked' | 'logged' | 'none';
export type LylatNegativeControl = 'blocked-on-hardened' | 'detection-only' | 'not-reproducible';

export interface LylatTechniqueRef {
  readonly domain: LylatDomain;
  readonly id: string;             // T#### / T####.### / AML.T#### / AML.T####.###
  readonly attack_version: string; // free version string, e.g. "19.2"
}

export interface LylatRowV1 {
  readonly mission_id: string;
  readonly technique_ref: LylatTechniqueRef;
  readonly detection_ref: string;  // <source>:<id>, id only, never a body
  readonly coverage_state: LylatCoverageState;
  readonly outcome: LylatOutcome;
  readonly negative_control: LylatNegativeControl;
  readonly validated_at: string;   // date only, YYYY-MM-DD
  readonly evidence_ref: string;   // opaque, e.g. <MISSION>-step<N>
}

export interface LylatExportV1 {
  readonly schema: 'lylat-validated-detections/1';
  readonly range_build_ref?: string;  // ^[0-9a-f]{7,40}$, required once rows >= 1
  readonly generated_at: string;      // date-time
  readonly rows: readonly LylatRowV1[];
}

export const LYLAT_CONTRACT_SCHEMA = 'lylat-validated-detections/1';

// --- enums and patterns (kept in step with the JSON schema; the CI check and the
//     unit spec validate the same corpus so the two implementations cannot drift) ---
const DOMAINS: readonly LylatDomain[] = ['enterprise', 'ics', 'mobile', 'atlas'];
const COVERAGE_STATES: readonly LylatCoverageState[] = ['validated', 'telemetry-observed', 'detection-authored', 'deployed'];
const OUTCOMES: readonly LylatOutcome[] = ['alerted', 'blocked', 'logged', 'none'];
const NEGATIVE_CONTROLS: readonly LylatNegativeControl[] = ['blocked-on-hardened', 'detection-only', 'not-reproducible'];
const DETECTION_SOURCES = 'wazuh|sigma|auditd|splunk|falcon|defender|elastic|car|zeek';

const PAT = {
  missionId: /^[A-Z0-9][A-Z0-9-]*$/,
  techniqueId: /^(T[0-9]{4}(\.[0-9]{3})?|AML\.T[0-9]{4}(\.[0-9]{3})?)$/,
  attackVersion: /^[0-9]+(\.[0-9]+)*$/,
  detectionRef: new RegExp(`^(${DETECTION_SOURCES}):[A-Za-z0-9._-]+$`),
  evidenceRef: /^[A-Za-z0-9][A-Za-z0-9._:-]*$/,
  rangeBuildRef: /^[0-9a-f]{7,40}$/,
  dateOnly: /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/,
  dateTime: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/,
} as const;

/**
 * The privacy regex (producer validate.py parity): a hit on a path separator,
 * `@`, any whitespace, or a dotted-quad IP. Run ONLY over the three free-id
 * fields — detection_ref, evidence_ref and mission_id — which are the only places
 * a capture could leak a host, path, user or address; every other field is
 * pattern- or format-locked, so it cannot carry one.
 */
export const LYLAT_PRIVACY_RE = /[/\\@\s]|[0-9]{1,3}(\.[0-9]{1,3}){3}/;
const PRIVACY_FIELDS = ['detection_ref', 'evidence_ref', 'mission_id'] as const;

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function extraKeys(o: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(o).filter((k) => !allowed.includes(k));
}
function isValidDateOnly(s: string): boolean {
  if (!PAT.dateOnly.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
function isValidDateTime(s: string): boolean {
  return PAT.dateTime.test(s) && !Number.isNaN(Date.parse(s));
}

const ROW_KEYS = ['mission_id', 'technique_ref', 'detection_ref', 'coverage_state', 'outcome', 'negative_control', 'validated_at', 'evidence_ref'];
const REF_KEYS = ['domain', 'id', 'attack_version'];
const TOP_KEYS = ['schema', 'range_build_ref', 'generated_at', 'rows'];

export type ValidateResult = { ok: true; value: LylatExportV1 } | { ok: false; errors: string[] };

/**
 * Strict, dependency-free validation of a parsed export against
 * `lylat-validated-detections/1`: additionalProperties:false at all three levels,
 * every enum and pattern, the date / date-time formats, the rule that a non-empty
 * export carries range_build_ref, and the privacy regex over the three free-id
 * fields. Returns every error found (not just the first), so the UI and CI can
 * name them. It never throws and never mutates the input.
 */
export function validateLylatExport(x: unknown): ValidateResult {
  const errors: string[] = [];
  if (!isObj(x)) return { ok: false, errors: ['root: not an object'] };

  if (x['schema'] !== LYLAT_CONTRACT_SCHEMA) errors.push(`schema: must be "${LYLAT_CONTRACT_SCHEMA}"`);
  if (typeof x['generated_at'] !== 'string' || !isValidDateTime(x['generated_at'])) errors.push('generated_at: must be an ISO date-time');
  for (const k of extraKeys(x, TOP_KEYS)) errors.push(`root: unexpected field "${k}"`);

  const rows = x['rows'];
  if (!Array.isArray(rows)) {
    errors.push('rows: must be an array');
    return { ok: false, errors };
  }

  if (x['range_build_ref'] !== undefined) {
    if (typeof x['range_build_ref'] !== 'string' || !PAT.rangeBuildRef.test(x['range_build_ref'])) {
      errors.push('range_build_ref: must match ^[0-9a-f]{7,40}$');
    }
  } else if (rows.length >= 1) {
    errors.push('range_build_ref: required when rows is non-empty');
  }

  rows.forEach((row, i) => {
    const at = `rows[${i}]`;
    if (!isObj(row)) { errors.push(`${at}: not an object`); return; }
    for (const k of extraKeys(row, ROW_KEYS)) errors.push(`${at}: unexpected field "${k}"`);

    const mission = row['mission_id'];
    if (typeof mission !== 'string' || !PAT.missionId.test(mission)) errors.push(`${at}.mission_id: must match ^[A-Z0-9][A-Z0-9-]*$`);

    const ref = row['technique_ref'];
    if (!isObj(ref)) {
      errors.push(`${at}.technique_ref: not an object`);
    } else {
      for (const k of extraKeys(ref, REF_KEYS)) errors.push(`${at}.technique_ref: unexpected field "${k}"`);
      if (!DOMAINS.includes(ref['domain'] as LylatDomain)) errors.push(`${at}.technique_ref.domain: not one of ${DOMAINS.join(', ')}`);
      if (typeof ref['id'] !== 'string' || !PAT.techniqueId.test(ref['id'])) errors.push(`${at}.technique_ref.id: not a technique id`);
      if (typeof ref['attack_version'] !== 'string' || !PAT.attackVersion.test(ref['attack_version'])) errors.push(`${at}.technique_ref.attack_version: not a version`);
    }

    const det = row['detection_ref'];
    if (typeof det !== 'string' || !PAT.detectionRef.test(det)) errors.push(`${at}.detection_ref: not <source>:<id>`);
    if (!COVERAGE_STATES.includes(row['coverage_state'] as LylatCoverageState)) errors.push(`${at}.coverage_state: not an allowed state`);
    if (!OUTCOMES.includes(row['outcome'] as LylatOutcome)) errors.push(`${at}.outcome: not an allowed outcome`);
    if (!NEGATIVE_CONTROLS.includes(row['negative_control'] as LylatNegativeControl)) errors.push(`${at}.negative_control: not an allowed value`);
    if (typeof row['validated_at'] !== 'string' || !isValidDateOnly(row['validated_at'])) errors.push(`${at}.validated_at: must be a YYYY-MM-DD date`);
    const ev = row['evidence_ref'];
    if (typeof ev !== 'string' || !PAT.evidenceRef.test(ev)) errors.push(`${at}.evidence_ref: not an opaque reference`);

    // Privacy regex over the three free-id fields only.
    for (const f of PRIVACY_FIELDS) {
      const v = row[f];
      if (typeof v === 'string' && LYLAT_PRIVACY_RE.test(v)) errors.push(`${at}.${f}: refused by the privacy check (host, path, address or whitespace)`);
    }
  });

  return errors.length === 0 ? { ok: true, value: x as unknown as LylatExportV1 } : { ok: false, errors };
}

/** The ValidationStatus a row maps to (design §3; plan:670-674). */
export function statusForRow(row: LylatRowV1): ValidationStatus {
  if (row.negative_control === 'not-reproducible') return 'not-reproducible';
  if (row.coverage_state === 'validated' && (row.outcome === 'alerted' || row.outcome === 'blocked')) return 'passed';
  if (row.coverage_state === 'telemetry-observed') return 'partial';
  if (row.coverage_state === 'detection-authored' || row.coverage_state === 'deployed') return 'untested';
  return 'untested';
}

export interface LylatMapResult {
  /** Runs grouped by their v2 source (`lylat-range:<mission_id>`), one group per mission. */
  readonly bySource: Map<`lylat-range:${string}`, ValidationRunV2[]>;
  /** Rows not mapped (e.g. an atlas technique with no Navi domain), with the reason. */
  readonly skipped: { readonly row: number; readonly reason: string }[];
}

/**
 * Map a validated export to v2 runs grouped by mission source. Status is SET here
 * (ValidationService.importRows stores it under a `lylat-range:` source, which
 * forces proofScope 'range' and statusFromSource true, so update() never
 * recomputes it). Each row's technique is RESOLVED and KEYED at import through the
 * same refForTechnique/techniqueRefKey a manual run uses (keyed by the row's own
 * domain + attack_version), so an imported run is indistinguishable from a manual
 * run in key shape; version mismatches are reconciled at read time, not dropped
 * (R6 §3). `resolve` maps a retired id to its live one; `domainVersion` is the
 * loaded bundle's version, a fallback when the row omits a usable one. Rows are
 * skipped (with a reason) when the technique is atlas (no Navi domain today) or
 * does not resolve to a parseable technique ref.
 *
 * This builds plain v2-shaped objects; ValidationService.importRows re-sanitises
 * them through the same allowlist, so a field this misses is dropped, not trusted.
 */
export function lylatRowsToRuns(
  e: LylatExportV1,
  resolve: (id: string) => string,
  domainVersion: string,
): LylatMapResult {
  const bySource = new Map<`lylat-range:${string}`, ValidationRunV2[]>();
  const skipped: { row: number; reason: string }[] = [];

  e.rows.forEach((row, i) => {
    if (row.technique_ref.domain === 'atlas') {
      skipped.push({ row: i, reason: `atlas technique ${row.technique_ref.id}: no ATT&CK domain in Navi today` });
      return;
    }
    const source = `lylat-range:${row.mission_id}` as const;
    const techniqueId = resolve(row.technique_ref.id);
    const version = row.technique_ref.attack_version || domainVersion || 'unknown';
    const refKey = techniqueRefKey(refForTechnique({ attackId: techniqueId }, row.technique_ref.domain as AttackDomain, version));
    if (parseTechniqueRef(refKey) === null) {
      skipped.push({ row: i, reason: `technique ${row.technique_ref.id} does not resolve to a known technique ref (${row.technique_ref.domain})` });
      return;
    }
    const fired = row.outcome === 'alerted' || row.outcome === 'blocked';
    const outcome: ValidationOutcome = {
      detectionRef: row.detection_ref,
      outcome: row.outcome,
      coverageState: row.coverage_state,
      negativeControl: row.negative_control,
      evidenceRef: row.evidence_ref,
    };
    const run: ValidationRunV2 = {
      id: `lylat:${row.mission_id}:${i}`,
      techniqueId,
      techniqueName: '',
      runDate: row.validated_at,
      operator: '',
      telemetryRequired: [],
      telemetryAvailable: [],
      atomicTestId: '',
      atomicCommand: '',
      attackResult: row.outcome === 'blocked' ? 'blocked' : 'executed',
      detectionsExpected: [row.detection_ref],
      detectionsFired: fired ? [row.detection_ref] : [],
      responsePlaybook: '',
      responseActions: [],
      evidenceLinks: [],
      notes: '',
      status: statusForRow(row),
      // v2 envelope + proof fields (importRows re-derives source/proofScope/statusFromSource):
      domain: row.technique_ref.domain,
      attackVersion: version,
      source,
      createdAt: e.generated_at,
      updatedAt: e.generated_at,
      techniqueRef: refKey,
      proofScope: 'range',
      outcomes: [outcome],
      statusFromSource: true,
      missionId: row.mission_id,
    };
    const group = bySource.get(source) ?? [];
    group.push(run);
    bySource.set(source, group);
  });

  return { bySource, skipped };
}

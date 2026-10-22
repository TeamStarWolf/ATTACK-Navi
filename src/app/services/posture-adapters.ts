// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Store adapters for PostureService (Phase 2 design §3 P2-05). Each adapter
// turns one owner-data store into the CoveredMarks, ProofRecords and
// RunVerdicts derivePosture reads. They are pure functions over the store
// values and the loaded Domain, so PostureService is only the glue (signals in,
// one derivePosture per technique out).
//
// - Implementation (mitre-nav-impl-v1): 'course-of-action--*' keys are
//   mitigations, rolled up with the D16 breadth guard (rollupMitigations);
//   'attack-pattern--*' keys are wizard technique ratings
//   (assessment-wizard.component.ts), marks with basis 'technique-confirmed'
//   and source 'wizard'; anything else is unmatched: listed, never deleted.
// - Controls (mitre-nav-controls-v1): ControlsService.computeCoverage's hop
//   (control → mitigation → techniques), with the same breadth guard per
//   mitigation.
// - Telemetry (attacknavi.telemetry-coverage.v1): self-attested
//   'telemetry-configured' only when the technique has at least one mapping
//   and every required key is configured. An unmapped technique is n/a.
// - Validation (navi.v2.validation-runs): §3 P2-05 (S4) and §7; runs are
//   matched to the loaded domain's techniques by runMatches (§8).
// - Technique marks (navi.v2.technique-marks): 'technique-confirmed' marks.
import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import type { SecurityControl } from '../models/security-control';
import type { CoveredMark, CoveredStrength, ProofRecord, RunSummary, RunVerdict } from '../models/posture/posture.types';
import { rollupMitigations } from '../models/posture/mitigation-rollup';
import { runMatches } from '../models/posture/run-match';
import { type TechniqueRefKey, parseTechniqueRef } from '../models/technique-ref';
import type { AttackDomain } from './data.service';
import type { ImplStatus } from './implementation.service';
import type { TechniqueMarkRecord } from './technique-marks.service';
import type { ValidationRunV2 } from './validation.service';

/** An implementation-map key PostureService cannot place (listed by `unmatched()`, never deleted). */
export interface UnmatchedKey {
  readonly key: string;
  readonly store: 'impl';
  readonly reason: string;
}

export type ImplKeyKind = 'mitigation' | 'technique' | 'unmatched';

const MITIGATION_KEY = /^course-of-action--\S+$/;
const TECHNIQUE_KEY = /^attack-pattern--\S+$/;

/** What a v1 implementation-map key names. */
export function classifyImplKey(key: string): ImplKeyKind {
  if (MITIGATION_KEY.test(key)) return 'mitigation';
  if (TECHNIQUE_KEY.test(key)) return 'technique';
  return 'unmatched';
}

/** The reason an unmatched key is listed: bare ATT&CK ids (the pre-P2-06 CSV import) are named as such. */
function unmatchedReason(key: string): string {
  return /^(?:M|T)\d{4}(?:\.\d{3})?$/.test(key)
    ? 'a bare ATT&CK id, not a STIX id; it is kept and not counted'
    : 'not a mitigation or technique STIX id; it is kept and not counted';
}

/** A technique-level statement's mark strength: implemented → full, in progress or planned → planned. */
function techniqueStrength(status: ImplStatus): CoveredStrength | null {
  switch (status) {
    case 'implemented': return 'full';
    case 'in-progress':
    case 'planned': return 'planned';
    default: return null;
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

/** ATT&CK id of a mitigation STIX id in the loaded domain (the STIX id when it is not there). */
export function mitigationAttackIds(domain: Pick<Domain, 'mitigations'>): (stix: string) => string {
  const ids = new Map(domain.mitigations.map(m => [m.id, m.attackId]));
  return (stix: string) => ids.get(stix) ?? stix;
}

/**
 * Implementation adapter. Returns the self-attested marks keyed by technique
 * STIX id, and the keys it could not place.
 */
export function implementationAdapter(
  impl: ReadonlyMap<string, ImplStatus>,
  domain: Pick<Domain, 'techniquesByMitigation' | 'mitigations'>,
  threshold: number,
): { marks: ReadonlyMap<string, readonly CoveredMark[]>; unmatched: readonly UnmatchedKey[] } {
  const mitigations = new Map<string, ImplStatus>();
  const marks = new Map<string, CoveredMark[]>();
  const unmatched: UnmatchedKey[] = [];
  for (const [key, status] of impl) {
    switch (classifyImplKey(key)) {
      case 'mitigation':
        mitigations.set(key, status);
        break;
      case 'technique': {
        const strength = techniqueStrength(status);
        if (strength !== null) {
          push(marks, key, { qualifier: 'self-attested', basis: 'technique-confirmed', strength, source: 'wizard' });
        }
        break;
      }
      default:
        unmatched.push({ key, store: 'impl', reason: unmatchedReason(key) });
    }
  }
  const rolled = rollupMitigations(mitigations, domain.techniquesByMitigation, mitigationAttackIds(domain), threshold);
  for (const [techId, list] of rolled) for (const m of list) push(marks, techId, m);
  return { marks, unmatched };
}

/**
 * Controls adapter: computeCoverage's hop (controls.service.ts), control →
 * mitigation → every technique the mitigation maps to in the loaded domain,
 * with the D16 breadth guard per mitigation. An implemented control gives full
 * marks through a mitigation mapped to at most `threshold` techniques and
 * partial marks through a broader one; a planned control gives planned marks.
 * Each mark names the mitigation it came through in `via`.
 */
export function controlsAdapter(
  controls: readonly SecurityControl[],
  domain: Pick<Domain, 'techniquesByMitigation' | 'mitigations'>,
  threshold: number,
): ReadonlyMap<string, readonly CoveredMark[]> {
  const marks = new Map<string, CoveredMark[]>();
  const attackId = mitigationAttackIds(domain);
  for (const ctrl of controls) {
    for (const mitId of ctrl.mitigationIds ?? []) {
      const techniques = domain.techniquesByMitigation.get(mitId) ?? [];
      const strength: CoveredStrength = ctrl.status !== 'implemented'
        ? 'planned'
        : techniques.length <= threshold ? 'full' : 'partial';
      const mark: CoveredMark = {
        qualifier: 'self-attested', basis: 'control-implemented', strength, via: attackId(mitId), source: 'manual',
      };
      for (const t of techniques) push(marks, t.id, mark);
    }
  }
  return marks;
}

/**
 * Telemetry adapter for one technique: a full self-attested
 * 'telemetry-configured' mark when the technique has at least one required
 * (source, event) key and every one is configured. null otherwise, and null
 * for an unmapped technique: TelemetryCoverageService.techniqueCoverage calls
 * that 100% ("vacuously"), which is n/a here, never a mark.
 */
export function telemetryMark(
  requiredKeys: readonly string[],
  configured: ReadonlySet<string>,
): CoveredMark | null {
  if (requiredKeys.length === 0) return null;
  if (!requiredKeys.every(k => configured.has(k))) return null;
  return {
    qualifier: 'self-attested', basis: 'telemetry-configured', strength: 'full',
    via: [...new Set(requiredKeys)].join(', '), source: 'manual',
  };
}

/** What one validation run says about its technique. */
export interface RunInputs {
  readonly proof: readonly ProofRecord[];
  readonly covered: readonly CoveredMark[];
  readonly verdicts: readonly RunVerdict[];
  /** The run itself, so derivePosture can name a run that yields no proof (RP-F decision 9). */
  readonly summary: RunSummary;
}

const RANGE_STATES = {
  deployed: { basis: 'range-deployed', strength: 'full' },
  'detection-authored': { basis: 'range-detection-authored', strength: 'full' },
  'telemetry-observed': { basis: 'range-telemetry-observed', strength: 'partial' },
} as const;

/**
 * Validation adapter for one run (S4; §7):
 * - every named detection (an 'alerted' or 'blocked' outcome with a non-empty
 *   detectionRef, or an entry of detectionsFired) is one ProofRecord with the
 *   run's proofScope; its outcome is 'blocked' when that outcome or the run
 *   (attackResult 'blocked') was blocked, else 'alerted';
 * - a blocked run with no named detection is a CoveredMark (self-attested,
 *   'own-run-blocked', full), never proof: only a named detection reaches the
 *   top rung (D10);
 * - status 'failed' is a failed RunVerdict; status 'not-reproducible' (or a
 *   'not-reproducible' negative control) is a notReproducible one;
 * - range rows (proofScope 'range') with coverageState 'deployed' or
 *   'detection-authored' are range full marks, 'telemetry-observed' a range
 *   partial mark. Own runs never carry range marks.
 */
export function runInputs(run: ValidationRunV2): RunInputs {
  const runBlocked = run.attackResult === 'blocked';
  const named = new Map<string, 'alerted' | 'blocked'>();
  for (const o of run.outcomes) {
    const ref = o.detectionRef?.trim() ?? '';
    if (ref === '' || (o.outcome !== 'alerted' && o.outcome !== 'blocked')) continue;
    const outcome = o.outcome === 'blocked' || runBlocked ? 'blocked' : 'alerted';
    if (named.get(ref) !== 'blocked') named.set(ref, outcome);
  }
  for (const d of run.detectionsFired) {
    const ref = d.trim();
    if (ref !== '' && !named.has(ref)) named.set(ref, runBlocked ? 'blocked' : 'alerted');
  }
  const blocked = runBlocked || run.outcomes.some(o => o.outcome === 'blocked');

  const proof: ProofRecord[] = [...named].map(([detectionRef, outcome]) => ({
    scope: run.proofScope, detectionRef, outcome, date: run.runDate, source: run.source, runId: run.id,
    ...(run.missionId !== undefined ? { missionId: run.missionId } : {}),
  }));

  const covered: CoveredMark[] = [];
  if (blocked && named.size === 0) {
    covered.push({ qualifier: 'self-attested', basis: 'own-run-blocked', strength: 'full', source: run.source, at: run.runDate });
  }
  if (run.proofScope === 'range') {
    for (const o of run.outcomes) {
      const state = o.coverageState && o.coverageState !== 'validated' ? RANGE_STATES[o.coverageState] : null;
      if (state === null) continue;
      const via = o.detectionRef?.trim();
      covered.push({
        qualifier: 'range', basis: state.basis, strength: state.strength, source: run.source, at: run.runDate,
        ...(via ? { via } : {}),
      });
    }
  }

  const failed = run.status === 'failed';
  const notReproducible = run.status === 'not-reproducible' || run.outcomes.some(o => o.negativeControl === 'not-reproducible');
  const verdicts: RunVerdict[] = failed || notReproducible
    ? [{ date: run.runDate, failed, notReproducible, source: run.source }]
    : [];
  const summary: RunSummary = { runId: run.id, status: run.status, date: run.runDate, source: run.source };
  return { proof, covered, verdicts, summary };
}

/** A technique-marks record as a CoveredMark: implemented → full, in progress or planned → planned. */
export function techniqueMarkToCovered(m: TechniqueMarkRecord): CoveredMark | null {
  const strength = techniqueStrength(m.status);
  if (strength === null) return null;
  return {
    qualifier: 'self-attested', basis: 'technique-confirmed', strength, source: m.source, at: m.updatedAt,
    ...(m.via !== undefined ? { via: m.via } : {}),
  };
}

/**
 * Group items that name a technique (runs, technique marks) by the STIX id of
 * every loaded technique they match, through runMatches (§8): the one matcher
 * PostureService and the drawer pill share. Candidates are found by resolved
 * id first, and runMatches decides, so the answer is runMatches' answer.
 */
export function matchToTechniques<T>(
  items: readonly T[],
  keyOf: (item: T) => { techniqueRef: TechniqueRefKey | null; techniqueId: string },
  techniques: readonly Technique[],
  domainId: AttackDomain,
  resolve: (id: string) => string,
): ReadonlyMap<string, readonly T[]> {
  const byId = new Map<string, Technique[]>();
  for (const t of techniques) push(byId, resolve(t.attackId), t);
  const out = new Map<string, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    const ref = key.techniqueRef === null ? null : parseTechniqueRef(key.techniqueRef);
    const candidates = byId.get(resolve(ref?.id ?? key.techniqueId)) ?? [];
    for (const t of candidates) {
      if (runMatches(key, t, domainId, resolve)) push(out, t.id, item);
    }
  }
  return out;
}

/** The technique key of a technique mark, for matchToTechniques. */
export function markKey(m: Pick<TechniqueMarkRecord, 'ref'>): { techniqueRef: TechniqueRefKey; techniqueId: string } {
  return { techniqueRef: m.ref, techniqueId: parseTechniqueRef(m.ref)?.id ?? '' };
}

const STATUS_RANK: Readonly<Record<ImplStatus, number>> = { implemented: 4, 'in-progress': 3, planned: 2, 'not-started': 1 };

/** The guarded mitigation-implementation view of one technique (the status lens and impl=, P2-14). */
export interface ImplView {
  readonly status: ImplStatus | null;
  readonly partialVia: string | null;
}

/**
 * The status fold of matrix.component.ts (best status over every mapped
 * mitigation) with the D16 breadth guard (§1.13, R1) and the technique-level
 * statements (wizard ratings, technique marks):
 * - 'implemented' with partialVia null when a technique-level statement is
 *   implemented, or an implemented mitigation maps to at most `threshold`
 *   techniques;
 * - 'implemented' with partialVia naming the broad mitigation(s) when every
 *   implemented mitigation is broader than the threshold;
 * - otherwise the best of the remaining statuses, partialVia null.
 */
export function implView(
  t: Pick<Technique, 'id'>,
  impl: ReadonlyMap<string, ImplStatus>,
  domain: Pick<Domain, 'mitigationsByTechnique' | 'techniquesByMitigation'>,
  threshold: number,
  techniqueStatuses: readonly ImplStatus[],
): ImplView {
  let best: ImplStatus | null = null;
  const consider = (s: ImplStatus | undefined): void => {
    if (s && (best === null || STATUS_RANK[s] > STATUS_RANK[best])) best = s;
  };
  let fullImplemented = false;
  const broad: string[] = [];
  for (const s of [...techniqueStatuses, impl.get(t.id)]) {
    if (s === 'implemented') fullImplemented = true;
    else consider(s);
  }
  for (const rel of domain.mitigationsByTechnique.get(t.id) ?? []) {
    const s = impl.get(rel.mitigation.id);
    if (s !== 'implemented') {
      consider(s);
      continue;
    }
    const breadth = domain.techniquesByMitigation.get(rel.mitigation.id)?.length ?? 0;
    if (breadth <= threshold) fullImplemented = true;
    else if (!broad.includes(rel.mitigation.attackId)) broad.push(rel.mitigation.attackId);
  }
  if (fullImplemented) return { status: 'implemented', partialVia: null };
  if (broad.length > 0) return { status: 'implemented', partialVia: broad.sort().join(', ') };
  return { status: best, partialVia: null };
}

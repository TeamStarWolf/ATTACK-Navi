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
import { provesStatus } from '../models/posture/derive-posture';
import { runMatches } from '../models/posture/run-match';
import { attackDidNotExecute, firedRuleCount, firedRules, ruleKey } from '../models/posture/fired-rules';
import { compareRunsNewestFirst, sortRunsNewestFirst, storedRunKey } from '../models/posture/latest-run';
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
        // RP-F decision 31: the cause of a partial mark is set where the mark is produced.
        ...(strength === 'partial' ? { partialCause: 'breadth' as const } : {}),
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
  // RP-F decision 31: a telemetry-observed row is partial because the range saw the
  // technique's telemetry and no detection alerted, never because of breadth.
  'telemetry-observed': { basis: 'range-telemetry-observed', strength: 'partial', partialCause: 'telemetry' },
} as const;

/** One rule a run fired: its id (the first spelling firedRules kept) and how it fired. */
interface FiredRule {
  readonly rule: string;
  readonly outcome: 'alerted' | 'blocked';
}

/**
 * The rules a run fired, keyed by ruleKey (trimmed, case-insensitive, RP-F decision 40),
 * each 'alerted' or 'blocked': firedRules(run) (the set the Validation pill and the
 * Proven block count, RP-F decision 30b; empty for a run whose attack did not execute,
 * RP-F decision 44), 'blocked' when the run (attackResult 'blocked') or an outcome of
 * that rule was blocked; the rules of alerted or blocked outcome rows first, then the
 * rest of detectionsFired. The run's proof records (runInputsFor) and the range marks'
 * firings (techniqueFirings) are both read from it, so neither re-implements the fired
 * set or the non-executed rule (PR #241 round 1).
 */
function firedOutcomes(run: ValidationRunV2): Map<string, FiredRule> {
  const runBlocked = run.attackResult === 'blocked';
  const fired = new Map(firedRules(run).map(rule => [ruleKey(rule), rule] as const));
  const out = new Map<string, FiredRule>();
  // The rules of the alerted or blocked outcome rows first, then the rest of detectionsFired.
  for (const o of run.outcomes) {
    const key = ruleKey(o.detectionRef ?? '');
    const rule = fired.get(key);
    if (rule === undefined || (o.outcome !== 'alerted' && o.outcome !== 'blocked')) continue;
    const blocked = runBlocked || o.outcome === 'blocked' || out.get(key)?.outcome === 'blocked';
    out.set(key, { rule, outcome: blocked ? 'blocked' : 'alerted' });
  }
  for (const [key, rule] of fired) if (!out.has(key)) out.set(key, { rule, outcome: runBlocked ? 'blocked' : 'alerted' });
  return out;
}

/** One rule's firing across a technique's evidence: how it fired, and the run it fired that way in. */
interface RuleFiring {
  readonly outcome: 'alerted' | 'blocked';
  readonly run: ValidationRunV2;
}

/**
 * Every rule fired anywhere in a technique's evidence (RP-F decision 40), keyed by
 * ruleKey: 'blocked' with the newest run that blocked it when any run did, else
 * 'alerted' with the newest run that fired it (newest by the one latest-run comparator,
 * RP-F decision 24). The outcome and the run always come from the same run, so the
 * clause names the date of the run the rule fired that way in (decision 40). PR #241
 * round 1: wazuh:1 blocked on 10/20 and alerted on 10/21 read "the rule blocked in this
 * run" on the 10/21 run, where it only alerted.
 */
function techniqueFirings(runs: readonly ValidationRunV2[]): Map<string, RuleFiring> {
  const out = new Map<string, RuleFiring>();
  for (const run of sortRunsNewestFirst(runs, storedRunKey)) {
    for (const [key, { outcome }] of firedOutcomes(run)) {
      const seen = out.get(key);
      if (seen === undefined || (outcome === 'blocked' && seen.outcome !== 'blocked')) out.set(key, { outcome, run });
    }
  }
  return out;
}

/** One range row as decision 40 reads it: its run (and index), the row, and the rule it is a row of (null: none). */
interface RangeRow {
  readonly runIndex: number;
  readonly run: ValidationRunV2;
  readonly row: ValidationRunV2['outcomes'][number];
  readonly rule: string | null;
}

/**
 * The rules a range row is a row of (RP-F decision 40): its own trimmed detectionRef;
 * a row with no detectionRef resolves against its run's fired set (firedRules): the
 * fired rules no other row of the run names, or every fired rule when the other rows
 * name them all; [null] when the run fired nothing (the row names no rule).
 *   T1221: a telemetry row with no rule, in a run that fired wazuh:301 -> ['wazuh:301']
 */
function rowRules(run: ValidationRunV2, row: ValidationRunV2['outcomes'][number]): (string | null)[] {
  const own = row.detectionRef?.trim() ?? '';
  if (own !== '') return [own];
  const fired = firedRules(run);
  const named = new Set(run.outcomes.map(o => ruleKey(o.detectionRef ?? '')));
  const unnamed = fired.filter(r => !named.has(ruleKey(r)));
  const rules = unnamed.length > 0 ? unnamed : fired;
  return rules.length > 0 ? rules : [null];
}

/**
 * The range marks of one technique's runs, worded per rule, never per row (RP-F
 * decision 40), as a list per run (by its index in `runs`):
 * - decision-29 per-rule supersession: of the range rows of one rule (rule ids matched
 *   case-insensitively; a row with no rule resolved by rowRules), only the rows of the
 *   rule's latest run by the one latest-run comparator (RP-F decision 24: on the same
 *   instant the run that proves less, then by id) give marks, one per rule and basis; a
 *   'validated' row gives none (derivePosture reads its rule as proof, or as a run
 *   without proof) and supersedes its rule's older rows all the same; a row that names
 *   no rule supersedes nothing and gives its own mark;
 * - a 'deployed' or 'detection-authored' row is a range full mark, a 'telemetry-observed'
 *   row a range partial mark with partialCause 'telemetry' (RP-F decision 31) whose
 *   cause carries an outcome (RP-F decision 35): 'alerted' or 'blocked' when ANY run in
 *   the technique's evidence fired the rule (techniqueFirings, the fired set the pill and
 *   the Proven block count), with telemetryFiredAt naming that run's date when it is not
 *   the row's own run; otherwise 'none' for a 'none' row and 'logged' for the rest, with
 *   techniqueFired set when another rule fired, so the words never say "no detection
 *   alerted" beside a fired rule the pill or the Proven block counts;
 * - each mark is dated by its row's run (`at`), so its clause names the run date.
 * Round 8 found the words built per row from the row's own detectionRef: T1105 (the
 * same rule logged on 10/20, alerted on 10/21) read both "no detection alerted" and
 * "the rule alerted"; T1113, T1057, T1560, T1213, T1221 and T1030 read "no detection
 * alerted" beside a pill or a Proven block that counted a fired rule.
 */
function rangeMarks(runs: readonly ValidationRunV2[]): CoveredMark[][] {
  const firings = techniqueFirings(runs);
  const rows: RangeRow[] = [];
  runs.forEach((run, runIndex) => {
    // RP-F decision 44: a range run whose attack did not execute credits nothing and
    // supersedes nothing; the card names it as not credited (notCreditedWords).
    if (run.proofScope !== 'range' || attackDidNotExecute(run.attackResult)) return;
    for (const row of run.outcomes) {
      if (row.coverageState) for (const rule of rowRules(run, row)) rows.push({ runIndex, run, row, rule });
    }
  });
  // The run of each rule's latest row; a row that names no rule supersedes nothing.
  const latest = new Map<string, ValidationRunV2>();
  for (const { run, rule } of rows) {
    if (rule === null) continue;
    const held = latest.get(ruleKey(rule));
    if (held === undefined || compareRunsNewestFirst(storedRunKey(run), storedRunKey(held)) < 0) latest.set(ruleKey(rule), run);
  }
  const out: CoveredMark[][] = runs.map(() => []);
  const seen = new Set<string>();
  for (const { runIndex, run, row, rule } of rows) {
    const key = rule === null ? '' : ruleKey(rule);
    if (row.coverageState === 'validated' || row.coverageState === undefined) continue;
    if (rule !== null && latest.get(key) !== run) continue;
    const state = RANGE_STATES[row.coverageState];
    const firing = rule === null ? undefined : firings.get(key);
    const mark: CoveredMark = {
      qualifier: 'range', basis: state.basis, strength: state.strength, source: run.source, at: run.runDate,
      ...(rule !== null ? { via: rule } : {}),
      ...('partialCause' in state ? {
        partialCause: state.partialCause,
        telemetryOutcome: firing ? firing.outcome : row.outcome === 'none' ? 'none' as const : 'logged' as const,
        ...(firing && firing.run !== run ? { telemetryFiredAt: firing.run.runDate } : {}),
        ...(!firing && firings.size > 0 ? { techniqueFired: true } : {}),
      } : {}),
    };
    // One mark per rule and basis in a run: two rows of one rule in one run are one mark.
    const id = rule === null ? null : `${runIndex}|${key}|${mark.basis}|${mark.telemetryOutcome ?? ''}`;
    if (id !== null && seen.has(id)) continue;
    if (id !== null) seen.add(id);
    out[runIndex].push(mark);
  }
  return out;
}

/** Validation adapter for one run (S4; §7), as its technique's only run: runInputsFor([run])[0]. */
export function runInputs(run: ValidationRunV2): RunInputs {
  return runInputsFor([run])[0];
}

/**
 * Validation adapter for the runs of one technique (S4; §7), one RunInputs per run:
 * - every named detection (an 'alerted' or 'blocked' outcome with a non-empty
 *   detectionRef, or an entry of detectionsFired) is one ProofRecord with the
 *   run's proofScope; its outcome is 'blocked' when that outcome or the run
 *   (attackResult 'blocked') was blocked, else 'alerted';
 * - a blocked run with no named detection is a CoveredMark (self-attested,
 *   'own-run-blocked', full), never proof: only a named detection reaches the
 *   top rung (D10). The mark is gated on the proof allow-list (PROVING_STATUSES,
 *   RP-F decision 23): a blocked outcome in an untested, partial, failed,
 *   no-telemetry or not-reproducible run attests nothing (Record Run's "Blocked
 *   by control" with no expected rule stores 'untested', and read Covered beside
 *   an UNTESTED pill);
 * - status 'failed' is a failed RunVerdict; status 'not-reproducible' (or a
 *   'not-reproducible' negative control) is a notReproducible one;
 * - the range rows (proofScope 'range') give range marks per rule across all the
 *   technique's runs (rangeMarks, RP-F decision 40), each on the run of its rule's
 *   latest row. Own runs never carry range marks.
 * PostureService passes the runs runMatches matched to one technique.
 */
export function runInputsFor(runs: readonly ValidationRunV2[]): RunInputs[] {
  const range = rangeMarks(runs);
  return runs.map((run, i) => {
    const runBlocked = run.attackResult === 'blocked';
    const executed = !attackDidNotExecute(run.attackResult);
    // The run's fired rules, one per rule id compared case-insensitively (firedOutcomes
    // over firedRules: an attack that did not execute named no detection that fired,
    // RP-F decision 44). PR #241 round 1: this map was rebuilt here with its own
    // non-executed filter and case-sensitive keys, so 'wazuh:306' and 'WAZUH:306' were
    // two proof records.
    const named = firedOutcomes(run);
    const blocked = runBlocked || run.outcomes.some(o => o.outcome === 'blocked');
    // The one fired-rule count (firedRules, RP-F decision 30b): the distinct union of
    // detectionsFired and the rules of alerted or blocked outcomes, which the Validation
    // pill's "N of M detection rules fired" counts too. Round 5: a passed run whose only
    // rule was a blocked outcome read "1 rule fired" on the card beside a pill "0 of 0".
    // Every proof record carries it (runRulesFired), so the card's Proven line counts the
    // run, not the records of it that a later run of one rule left standing.
    const rulesFired = firedRuleCount(run);

    const proof: ProofRecord[] = [...named.values()].map(({ rule: detectionRef, outcome }) => ({
      scope: run.proofScope, detectionRef, outcome, date: run.runDate, source: run.source, runId: run.id, runRulesFired: rulesFired,
      ...(run.missionId !== undefined ? { missionId: run.missionId } : {}),
    }));

    const covered: CoveredMark[] = [];
    if (blocked && named.size === 0 && provesStatus(run.status)) {
      covered.push({ qualifier: 'self-attested', basis: 'own-run-blocked', strength: 'full', source: run.source, at: run.runDate });
    }
    covered.push(...range[i]);

    const failed = run.status === 'failed';
    const notReproducible = run.status === 'not-reproducible' || run.outcomes.some(o => o.negativeControl === 'not-reproducible');
    const verdicts: RunVerdict[] = failed || notReproducible
      ? [{ date: run.runDate, failed, notReproducible, source: run.source }]
      : [];
    // Every rule the run names, so derivePosture supersedes proof per rule (RP-F decision 29).
    const rules = [...new Set(
      [...run.outcomes.map(o => o.detectionRef ?? ''), ...run.detectionsExpected, ...run.detectionsFired]
        .map(d => d.trim()).filter(d => d !== ''),
    )];
    const summary: RunSummary = {
      runId: run.id, status: run.status, date: run.runDate, source: run.source, rulesFired, rules,
      ...(executed ? {} : { notExecuted: run.attackResult }),
    };
    return { proof, covered, verdicts, summary };
  });
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

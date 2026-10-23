// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Pure rung derivation (Phase 2 design §2.2). One PostureState per technique,
// derived in this order:
//   1. Qualifying proof (outcome 'alerted' or 'blocked', a non-empty
//      detectionRef, a parseable date) makes the rung 'proven'. The best record
//      is the highest scope among the fresh ones (production, range, own-run),
//      newest first, and the bucket is 'proven'; with no fresh record the best
//      is the newest one and the bucket is 'stale'. A run's STATUS governs its
//      proof (RP-F decisions 16 and 23): only a run whose status is on the
//      allow-list PROVING_STATUSES ('passed') yields proof; an untested,
//      partial, not-reproducible, failed or no-telemetry run yields none even
//      when it lists a fired rule. Supersession is PER RULE (RP-F decision 29):
//      the latest run of the SAME detection rule governs, so a proof record
//      stands unless a later failed or not-reproducible run names its rule (a
//      run that names no rule is the same rule as every record of its own
//      source); later by the one latest-run comparator, latest-run.ts, RP-F
//      decision 24 (on the same instant the run that proves less is the later
//      one). A later untested, partial or no-telemetry run, or a later run of
//      another rule, never removes proof: the state lists it (laterRuns) for the
//      why line. When no proof is left, the state names the run that outranked
//      the newest record (supersededProof) and, when that run failed and no
//      newer full marks hold Covered, is 'contradicted', as a full mark a later
//      failed run outranks is.
//   2. Otherwise a not-reproducible verdict sets `excluded` (out of the
//      Covered/Proven denominator only) and falls through for display.
//   3. Otherwise full marks give 'covered', unless a failed verdict contradicts
//      them (newer than the newest dated full mark, or any failed verdict when a
//      full mark is undated); then partial marks give 'partial'.
//   4. Otherwise 'known' when there is a Known reference signal, else 'none'.
// 'planned' and 'telemetry-observed' sub-states are set from the marks in every
// branch, and so are the partial causes (partialCauses, RP-F decision 31: each
// partial mark's own partialCause, set by its producer, never inferred). Every
// branch also lists the runs that yield no qualifying proof record
// (runsWithoutProof, RP-F decision 9), newest first. CI fails unless this file
// has 100% branch coverage (scripts/check-branch-coverage.mjs).
import type { CoveredQualifier } from '../heatmap-modes';
import type { TechniqueRefKey } from '../technique-ref';
import type {
  CoveredMark, PartialCause, PostureBucket, PostureInputs, PostureRules, PostureRung, PostureState, PostureSubState,
  PostureTally, ProofRecord, ProofScope, RunSummary, RunVerdict, SupersededProof,
} from './posture.types';
import { runTime } from '../local-date';
import { sortRunsNewestFirst, summaryRunKey } from './latest-run';
import { ruleKey } from './fired-rules';

/** D16 threshold 15 (dec:364-380); D10 windows range 90, production 180, own-run 90 (own-run is §10.4 item 2). */
export const DEFAULT_POSTURE_RULES: PostureRules = {
  mitigationBreadthThreshold: 15,
  decayDays: { production: 180, range: 90, 'own-run': 90 },
};

const DAY_MS = 86_400_000;

/** Production outranks range, range outranks an own run (§7). */
const SCOPE_RANK: Readonly<Record<ProofScope, number>> = { production: 3, range: 2, 'own-run': 1 };

const QUALIFIER_ORDER: readonly CoveredQualifier[] = ['self-attested', 'range'];

/**
 * The run statuses that can yield proof: an ALLOW-list (RP-F decision 23). Only a
 * passed run's named rule reaches Proven. Every other status the store accepts
 * (untested, partial, not-reproducible, failed, no-telemetry) never does, whatever
 * rules the run lists: round 4 found untested (T1018) and not-reproducible (T1082)
 * runs with a fired rule reading Proven beside an UNTESTED and a Not reproducible
 * pill, because the old deny-list named failed and no-telemetry only. 'partial' is
 * left out: the design's one status table (Phase 2 design §P2-20, plan:670-674)
 * maps a range row's 'telemetry-observed' to partial, a Covered-level state, and an
 * own run is partial when some expected rule did not fire.
 */
export const PROVING_STATUSES: ReadonlySet<string> = new Set(['passed']);

/** True when a run of `status` can yield proof (PROVING_STATUSES). */
export function provesStatus(status: string): boolean {
  return PROVING_STATUSES.has(status);
}

/**
 * Milliseconds since the epoch, or null when absent or not a date: runTime
 * (local-date.ts), the reading the latest-run comparator and the pill's day share,
 * so a date-only date is its local day (RP-F decision 24).
 */
function time(iso: string | undefined): number | null {
  return runTime(iso);
}

interface DatedProof {
  readonly record: ProofRecord;
  readonly t: number;
  readonly age: number;
  readonly fresh: boolean;
}

/** Fresh before stale; among fresh, higher scope first; then newest; then runId for a stable order. */
function byBest(a: DatedProof, b: DatedProof): number {
  const freshness = Number(b.fresh) - Number(a.fresh);
  if (freshness !== 0) return freshness;
  const scope = a.fresh ? SCOPE_RANK[b.record.scope] - SCOPE_RANK[a.record.scope] : 0;
  if (scope !== 0) return scope;
  return b.t - a.t || a.record.runId.localeCompare(b.record.runId);
}

function qualifyingProof(proof: readonly ProofRecord[], rules: PostureRules, now: Date): DatedProof[] {
  const out: DatedProof[] = [];
  for (const record of proof) {
    if (record.outcome !== 'alerted' && record.outcome !== 'blocked') continue;
    if (typeof record.detectionRef !== 'string' || record.detectionRef.trim() === '') continue;
    const t = time(record.date);
    if (t === null) continue;
    const age = Math.max(0, Math.floor((now.getTime() - t) / DAY_MS));
    out.push({ record, t, age, fresh: age <= rules.decayDays[record.scope] });
  }
  return out.sort(byBest);
}

/**
 * A failed verdict contradicts the full marks when it is newer than the newest
 * dated mark, or when any mark is undated (its date cannot outrank the run).
 * A failed verdict without a parseable date is older than every dated mark.
 */
function isContradicted(full: readonly CoveredMark[], verdicts: readonly RunVerdict[]): boolean {
  if (full.length === 0) return false;
  const failed = verdicts.filter(v => v.failed);
  if (failed.length === 0) return false;
  if (full.some(m => time(m.at) === null)) return true;
  const latestFailed = Math.max(...failed.map(v => time(v.date) ?? -Infinity));
  const newestMark = Math.max(...full.map(m => time(m.at) as number));
  return latestFailed > newestMark;
}

/**
 * The run statuses that REMOVE an earlier proof record of the same rule (RP-F
 * decision 29): a later failed or not-reproducible run of that rule. An untested,
 * partial or no-telemetry run says nothing against the rule that fired, so it
 * never removes proof (it is named in the why line instead).
 */
const REMOVING_STATUSES: ReadonlySet<string> = new Set(['failed', 'not-reproducible']);

/**
 * True when `run` is a run of the record's detection rule (RP-F decision 29): it
 * names the record's detectionRef, compared by ruleKey (trimmed, case-insensitive, RP-F
 * decision 40, as the range marks supersede; PR #241 round 1: a failed run naming
 * 'WAZUH:306' did not remove proof of 'wazuh:306'), or it names no rule and has the record's source
 * (a manual run without a rule id keys on source plus technique; every input here
 * is one technique's).
 */
function sameRule(run: RunSummary, record: ProofRecord): boolean {
  const named = run.rules ?? [];
  const key = ruleKey(record.detectionRef);
  return named.length > 0 ? named.some(r => ruleKey(r) === key) : run.source === record.source;
}

/**
 * The proof that stands once each run's status is applied (RP-F decisions 16, 23
 * and 29): a record counts only when its run's status is on PROVING_STATUSES (a
 * record whose run is not listed, in inputs built without runs, stands as it is),
 * and the latest run of the SAME rule governs: a record is removed by a run of its
 * rule (sameRule) that failed or was not reproducible and is later than it. Later
 * is the one latest-run comparator's order (RP-F decision 24: an undated run sorts
 * oldest and never outranks a record; on the same instant the run that proves less
 * is the later one, so a tie never reads as a pass); a record whose run is not
 * listed is outranked by a strictly newer dated run.
 * `superseded` names the newest record and the newest run that removed it, when no
 * proof is left (the why line: "latest run of the rule failed on <date>; an earlier
 * run passed on <date>"), with that earlier run's own status, looked up among the runs; null
 * otherwise. `laterRuns` lists, newest first, the runs that do not prove and are
 * later than every standing record (an untested, partial or no-telemetry run, or a
 * failed or not-reproducible run of another rule); when no proof is left and a run
 * removed it, every run newer than that remover (RP-F round 4 repair: the why line
 * names the newest, so it never calls the remover the latest run while the
 * Detection Validation pill shows a newer one); empty otherwise.
 */
function standingProof(
  input: PostureInputs, rules: PostureRules, now: Date,
): { readonly proof: DatedProof[]; readonly superseded: SupersededProof | null; readonly laterRuns: RunSummary[] } {
  const runs = input.runs ?? [];
  const noProofRuns = new Set(runs.filter(r => !provesStatus(r.status)).map(r => r.runId));
  const qualifying = qualifyingProof(input.proof.filter(p => !noProofRuns.has(p.runId)), rules, now);
  const ordered = sortRunsNewestFirst(runs, summaryRunKey);
  const order = new Map(ordered.map((r, i) => [r.runId, i]));
  const later = (run: RunSummary, p: DatedProof): boolean => {
    const at = order.get(p.record.runId);
    if (at !== undefined) return (order.get(run.runId) as number) < at;
    const t = time(run.date);
    return t !== null && t > p.t;
  };
  const removers = (p: DatedProof): RunSummary[] =>
    ordered.filter(r => REMOVING_STATUSES.has(r.status) && sameRule(r, p.record) && later(r, p));
  const proof = qualifying.filter(p => removers(p).length === 0);
  if (proof.length > 0) {
    return { proof, superseded: null, laterRuns: ordered.filter(r => !provesStatus(r.status) && proof.every(p => later(r, p))) };
  }
  if (qualifying.length === 0) return { proof, superseded: null, laterRuns: [] };
  const newest = [...qualifying].sort((a, b) => b.t - a.t)[0];
  const earlierStatus = runs.find(r => r.runId === newest.record.runId)?.status ?? null;
  const latest = removers(newest)[0];
  // Every run newer than the remover, whatever its status: none holds proof (the
  // newest qualifying record is older than its remover), and the pill may show one.
  const newerThanRemover = ordered.slice(0, order.get(latest.runId) as number);
  return { proof, superseded: { latest, earlier: newest.record, earlierStatus }, laterRuns: newerThanRemover };
}

/**
 * The causes of the partial marks (RP-F decision 31), sorted and unique: 'breadth'
 * for a mark reached only through a mitigation or control broader than the D16
 * threshold, 'telemetry' for a range telemetry-observed row. Read from the marks'
 * own partialCause; a partial mark that names none adds nothing.
 */
function partialCausesOf(marks: readonly CoveredMark[]): PartialCause[] {
  const causes = new Set<PartialCause>();
  for (const m of marks) if (m.strength === 'partial' && m.partialCause) causes.add(m.partialCause);
  return [...causes].sort();
}

function qualifiersOf(marks: readonly CoveredMark[]): CoveredQualifier[] {
  return QUALIFIER_ORDER.filter(q => marks.some(m => m.qualifier === q));
}

/**
 * The runs that produced no qualifying proof record (RP-F decision 9): an
 * untested run, a failed run, a passed run with no named rule, a run whose
 * named rule has no parseable date. A run with one qualifying record is out.
 * Newest first by the one latest-run comparator (RP-F decision 24): an undated
 * run sorts last; equal instants put the run that proves less first, then runId.
 */
function runsWithoutProof(runs: readonly RunSummary[], proof: readonly DatedProof[]): RunSummary[] {
  const proved = new Set(proof.map(p => p.record.runId));
  return sortRunsNewestFirst(runs.filter(r => !proved.has(r.runId)), summaryRunKey);
}

export function derivePosture(ref: TechniqueRefKey, input: PostureInputs, rules: PostureRules, now: Date): PostureState {
  const sub = new Set<PostureSubState>();
  if (input.covered.some(m => m.strength === 'planned')) sub.add('planned');
  if (input.covered.some(m => m.basis === 'range-telemetry-observed')) sub.add('telemetry-observed');
  const { proof, superseded, laterRuns } = standingProof(input, rules, now);
  const base = {
    ref,
    covered: input.covered,
    knownSignals: input.knownSignals,
    threatWeight: input.threatWeight,
    exposureWeight: input.exposureWeight,
    runsWithoutProof: runsWithoutProof(input.runs ?? [], proof),
    supersededProof: superseded,
    laterRuns,
    partialCauses: partialCausesOf(input.covered),
  };

  // 1. Proof.
  if (proof.length > 0) {
    const best = proof[0];
    const bucket: PostureBucket = best.fresh ? 'proven' : 'stale';
    if (bucket === 'stale') sub.add('stale');
    return {
      ...base, rung: 'proven', bucket, qualifiers: [], subStates: [...sub].sort(),
      proof: proof.map(p => p.record), proofScope: best.record.scope, proofAge: best.age, excluded: false,
    };
  }

  // 2. Not reproducible, with no proof: out of the Covered/Proven denominator.
  const excluded = input.verdicts.some(v => v.notReproducible);
  if (excluded) sub.add('not-reproducible');

  // 3. Covered marks.
  let full = input.covered.filter(m => m.strength === 'full');
  const partial = input.covered.filter(m => m.strength === 'partial');
  if (isContradicted(full, input.verdicts)) {
    sub.add('contradicted');
    full = [];
  }

  let rung: PostureRung;
  let bucket: PostureBucket;
  let qualifiers: CoveredQualifier[] = [];
  if (full.length > 0) {
    rung = 'covered';
    bucket = 'covered';
    qualifiers = qualifiersOf(full);
  } else if (partial.length > 0) {
    rung = 'covered';
    bucket = 'partial';
    qualifiers = qualifiersOf(partial);
    sub.add('partial');
  } else if (input.knownSignals > 0) {
    // 4. Known.
    rung = 'known';
    bucket = 'known';
  } else {
    rung = 'none';
    bucket = 'none';
  }
  // A failed run that outranked every proof record contradicts the technique's
  // evidence, unless newer full marks still hold Covered (RP-F decision 16). A
  // not-reproducible run of the rule outranks the proof too but contradicts nothing.
  if (superseded?.latest.status === 'failed' && bucket !== 'covered') sub.add('contradicted');

  return {
    ...base, rung, bucket, qualifiers, subStates: [...sub].sort(),
    proof: [], proofScope: null, proofAge: null, excluded,
  };
}

/** One count per bucket (they sum to `total`), plus the sub-state counts the legend needs. */
export function tallyPosture(states: Iterable<PostureState>): PostureTally {
  const t = { total: 0, assessable: 0, none: 0, known: 0, partial: 0, covered: 0, proven: 0, stale: 0, contradicted: 0, notReproducible: 0 };
  for (const s of states) {
    t.total++;
    if (!s.excluded) t.assessable++;
    t[s.bucket]++;
    if (s.subStates.includes('contradicted')) t.contradicted++;
    if (s.subStates.includes('not-reproducible')) t.notReproducible++;
  }
  return t;
}

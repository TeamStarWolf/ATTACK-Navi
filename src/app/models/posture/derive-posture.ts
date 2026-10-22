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
//      when it lists a fired rule. The latest run governs, so a proof record
//      older than the newest dated run that does not prove does not count
//      (strictly older, as a failed run outranks a mark only when strictly newer).
//      When that leaves no proof, the state names the run that outranked it
//      (supersededProof) and, when that run failed and no newer full marks
//      hold Covered, is 'contradicted', as a full mark a later failed run
//      outranks is.
//   2. Otherwise a not-reproducible verdict sets `excluded` (out of the
//      Covered/Proven denominator only) and falls through for display.
//   3. Otherwise full marks give 'covered', unless a failed verdict contradicts
//      them (newer than the newest dated full mark, or any failed verdict when a
//      full mark is undated); then partial marks give 'partial'.
//   4. Otherwise 'known' when there is a Known reference signal, else 'none'.
// 'planned' and 'telemetry-observed' sub-states are set from the marks in every
// branch. Every branch also lists the runs that yield no qualifying proof
// record (runsWithoutProof, RP-F decision 9), newest first. CI fails unless this file has 100% branch coverage
// (scripts/check-branch-coverage.mjs).
import type { CoveredQualifier } from '../heatmap-modes';
import type { TechniqueRefKey } from '../technique-ref';
import type {
  CoveredMark, PostureBucket, PostureInputs, PostureRules, PostureRung, PostureState, PostureSubState,
  PostureTally, ProofRecord, ProofScope, RunSummary, RunVerdict, SupersededProof,
} from './posture.types';

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

/** Milliseconds since the epoch, or null when absent or not a date. */
function time(iso: string | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
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
 * The newest dated run whose status yields no proof (not on PROVING_STATUSES), or null.
 * An undated one never outranks a proof record, as an undated failed verdict
 * never outranks a dated mark; of two on the same instant the first is kept.
 */
function latestNoProofRun(runs: readonly RunSummary[]): { readonly run: RunSummary; readonly t: number } | null {
  let latest: { run: RunSummary; t: number } | null = null;
  for (const run of runs) {
    if (provesStatus(run.status)) continue;
    const t = time(run.date);
    if (t === null) continue;
    if (latest === null || t > latest.t) latest = { run, t };
  }
  return latest;
}

/**
 * The proof that stands once each run's status is applied (RP-F decisions 16 and
 * 23): a record counts only when its run's status is on PROVING_STATUSES (a record
 * whose run is not listed, in inputs built without runs, stands as it is), and the
 * latest run governs, so a record strictly older than the newest run that does not
 * prove is outranked: a newer untested run after a pass names both runs.
 * `superseded` names that run and the newest record it outranked, when it
 * leaves no proof standing (the why line: "latest run failed on <date>; an
 * earlier run passed on <date>"), with that earlier run's own status, looked up
 * among the runs; null otherwise, a newer passing run included.
 */
function standingProof(
  input: PostureInputs, rules: PostureRules, now: Date,
): { readonly proof: DatedProof[]; readonly superseded: SupersededProof | null } {
  const runs = input.runs ?? [];
  const noProofRuns = new Set(runs.filter(r => !provesStatus(r.status)).map(r => r.runId));
  const qualifying = qualifyingProof(input.proof.filter(p => !noProofRuns.has(p.runId)), rules, now);
  const latest = latestNoProofRun(runs);
  if (latest === null) return { proof: qualifying, superseded: null };
  const proof = qualifying.filter(p => p.t >= latest.t);
  if (proof.length > 0 || qualifying.length === 0) return { proof, superseded: null };
  const earlier = [...qualifying].sort((a, b) => b.t - a.t)[0].record;
  const earlierStatus = runs.find(r => r.runId === earlier.runId)?.status ?? null;
  return { proof, superseded: { latest: latest.run, earlier, earlierStatus } };
}

function qualifiersOf(marks: readonly CoveredMark[]): CoveredQualifier[] {
  return QUALIFIER_ORDER.filter(q => marks.some(m => m.qualifier === q));
}

/**
 * The runs that produced no qualifying proof record (RP-F decision 9): an
 * untested run, a failed run, a passed run with no named rule, a run whose
 * named rule has no parseable date. A run with one qualifying record is out.
 * Newest first; an undated run sorts last (two undated runs subtract to NaN,
 * which falls through to the runId order, as equal dates do).
 */
function runsWithoutProof(runs: readonly RunSummary[], proof: readonly DatedProof[]): RunSummary[] {
  const proved = new Set(proof.map(p => p.record.runId));
  return runs.filter(r => !proved.has(r.runId))
    .sort((a, b) => (time(b.date) ?? -Infinity) - (time(a.date) ?? -Infinity) || a.runId.localeCompare(b.runId));
}

export function derivePosture(ref: TechniqueRefKey, input: PostureInputs, rules: PostureRules, now: Date): PostureState {
  const sub = new Set<PostureSubState>();
  if (input.covered.some(m => m.strength === 'planned')) sub.add('planned');
  if (input.covered.some(m => m.basis === 'range-telemetry-observed')) sub.add('telemetry-observed');
  const { proof, superseded } = standingProof(input, rules, now);
  const base = {
    ref,
    covered: input.covered,
    knownSignals: input.knownSignals,
    threatWeight: input.threatWeight,
    exposureWeight: input.exposureWeight,
    runsWithoutProof: runsWithoutProof(input.runs ?? [], proof),
    supersededProof: superseded,
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
  // evidence, unless newer full marks still hold Covered (RP-F decision 16). A run
  // with no telemetry outranks the proof too but contradicts nothing: it saw nothing.
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

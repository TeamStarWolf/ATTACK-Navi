// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Pure rung derivation (Phase 2 design §2.2). One PostureState per technique,
// derived in this order:
//   1. Qualifying proof (outcome 'alerted' or 'blocked', a non-empty
//      detectionRef, a parseable date) makes the rung 'proven'. The best record
//      is the highest scope among the fresh ones (production, range, own-run),
//      newest first, and the bucket is 'proven'; with no fresh record the best
//      is the newest one and the bucket is 'stale'.
//   2. Otherwise a not-reproducible verdict sets `excluded` (out of the
//      Covered/Proven denominator only) and falls through for display.
//   3. Otherwise full marks give 'covered', unless a failed verdict contradicts
//      them (newer than the newest dated full mark, or any failed verdict when a
//      full mark is undated); then partial marks give 'partial'.
//   4. Otherwise 'known' when there is a Known reference signal, else 'none'.
// 'planned' and 'telemetry-observed' sub-states are set from the marks in every
// branch. CI fails unless this file has 100% branch coverage
// (scripts/check-branch-coverage.mjs).
import type { CoveredQualifier } from '../heatmap-modes';
import type { TechniqueRefKey } from '../technique-ref';
import type {
  CoveredMark, PostureBucket, PostureInputs, PostureRules, PostureRung, PostureState, PostureSubState,
  PostureTally, ProofRecord, ProofScope, RunVerdict,
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

function qualifiersOf(marks: readonly CoveredMark[]): CoveredQualifier[] {
  return QUALIFIER_ORDER.filter(q => marks.some(m => m.qualifier === q));
}

export function derivePosture(ref: TechniqueRefKey, input: PostureInputs, rules: PostureRules, now: Date): PostureState {
  const sub = new Set<PostureSubState>();
  if (input.covered.some(m => m.strength === 'planned')) sub.add('planned');
  if (input.covered.some(m => m.basis === 'range-telemetry-observed')) sub.add('telemetry-observed');
  const base = {
    ref,
    covered: input.covered,
    knownSignals: input.knownSignals,
    threatWeight: input.threatWeight,
    exposureWeight: input.exposureWeight,
  };

  // 1. Proof.
  const proof = qualifyingProof(input.proof, rules, now);
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

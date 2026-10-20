// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// A PostureService stand-in for component and report specs whose TestBed
// holds stub services (P2-07). It answers stateFor / tallyFor / rollup /
// ownerWords from a per-technique bucket table, with the same tally and badge
// rules as the real service (tallyPosture, hasOwnerWords), so a spec can set
// "T1 is covered, T2 partial" without building marks. The equality spec
// (posture-count-equality.spec.ts) uses the REAL PostureService instead.
import { Provider, Signal, computed, signal } from '@angular/core';
import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import type { CoveredMark, PostureBucket, PostureState, ProofRecord } from '../models/posture/posture.types';
import { tallyPosture } from '../models/posture/derive-posture';
import { hasOwnerWords } from '../models/posture/posture-vocabulary';
import { PostureService, type PostureRollup } from '../services/posture.service';

type StubDomain = Pick<Domain, 'techniques' | 'tacticColumns'>;

const FULL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1', source: 'manual' };
const PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1', source: 'manual' };
const PROOF: ProofRecord = {
  scope: 'own-run', detectionRef: 'sigma:stub', outcome: 'alerted', date: '2026-10-01T00:00:00.000Z', source: 'manual', runId: 'stub',
};

/**
 * A PostureState in `bucket`, with the marks or proof that bucket needs.
 * `mapped` sets knownSignals; `excluded` takes the technique out of
 * `assessable` (R16: a not-reproducible run with no proof).
 */
export function stubState(attackId: string, bucket: PostureBucket, mapped = bucket !== 'none', excluded = false): PostureState {
  const proof = bucket === 'proven' || bucket === 'stale';
  return {
    ref: `attack/enterprise/${attackId}@stub`,
    rung: proof ? 'proven' : bucket === 'partial' ? 'covered' : bucket,
    bucket,
    qualifiers: bucket === 'covered' || bucket === 'partial' ? ['self-attested'] : [],
    subStates: bucket === 'partial' ? ['partial'] : bucket === 'stale' ? ['stale'] : [],
    covered: bucket === 'covered' ? [FULL] : bucket === 'partial' ? [PARTIAL] : [],
    proof: proof ? [PROOF] : [],
    proofScope: proof ? 'own-run' : null,
    proofAge: proof ? (bucket === 'stale' ? 120 : 1) : null,
    knownSignals: mapped ? 1 : 0,
    threatWeight: 1,
    exposureWeight: 0,
    excluded,
  };
}

export interface PostureStub {
  /** Replace the bucket table (attackId to bucket); techniques not named are 'none' or 'known'. */
  set(buckets: Readonly<Record<string, PostureBucket>>): void;
  /** Mark these attackIds excluded (out of `assessable` only). */
  exclude(attackIds: readonly string[]): void;
  readonly ownerWords: Signal<boolean>;
  readonly states: Signal<ReadonlyMap<string, PostureState>>;
  stateFor(t: Pick<Technique, 'attackId' | 'mitigationCount'>): PostureState;
  tallyFor(ts: readonly Pick<Technique, 'attackId' | 'mitigationCount'>[]): ReturnType<typeof tallyPosture>;
  rollup(opts?: { includeSubtechniques?: boolean }): PostureRollup;
}

/**
 * A stub over `domain` (null: no domain loaded). A technique not in the table
 * is 'known' when it has a mapped mitigation, else 'none', so Known 'mapped'
 * follows mitigationCount.
 */
export function makePostureStub(domain: () => StubDomain | null, buckets: Readonly<Record<string, PostureBucket>> = {}): PostureStub {
  const table = signal<Readonly<Record<string, PostureBucket>>>(buckets);
  const excluded = signal<ReadonlySet<string>>(new Set());
  const stateFor = (t: Pick<Technique, 'attackId' | 'mitigationCount'>): PostureState => {
    const mapped = (t.mitigationCount ?? 0) > 0;
    return stubState(t.attackId, table()[t.attackId] ?? (mapped ? 'known' : 'none'), mapped || table()[t.attackId] !== undefined,
      excluded().has(t.attackId));
  };
  const states = computed(() => new Map((domain()?.techniques ?? []).map(t => [t.attackId, stateFor(t)] as const)));
  const tallyFor = (ts: readonly Pick<Technique, 'attackId' | 'mitigationCount'>[]) => tallyPosture(ts.map(stateFor));
  const known = (ts: readonly Pick<Technique, 'attackId' | 'mitigationCount'>[]) => {
    const mapped = ts.map(stateFor).filter(s => s.knownSignals > 0).length;
    return { mapped, pct: ts.length > 0 ? Math.round((mapped / ts.length) * 100) : 0 };
  };
  return {
    set: b => table.set(b),
    exclude: ids => excluded.set(new Set(ids)),
    ownerWords: computed(() => hasOwnerWords(states().values())),
    states,
    stateFor,
    tallyFor,
    rollup(opts = {}): PostureRollup {
      const d = domain();
      if (!d) return { overall: { ...tallyPosture([]), mapped: 0, pct: 0 }, byTactic: [] };
      const techs = opts.includeSubtechniques ? d.techniques : d.techniques.filter(t => !t.isSubtechnique);
      return {
        overall: { ...tallyFor(techs), ...known(techs) },
        byTactic: d.tacticColumns.map(col => {
          const parents = col.techniques.filter(t => !t.isSubtechnique);
          return {
            ...tallyFor(parents), ...known(parents),
            tacticId: col.tactic.id ?? col.tactic.shortname, tacticName: col.tactic.name, shortname: col.tactic.shortname,
          };
        }),
      };
    },
  };
}

/** Provide a stub as PostureService. */
export function postureStubProvider(stub: PostureStub): Provider {
  return { provide: PostureService, useValue: stub };
}

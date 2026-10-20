// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The posture model (Phase 2 design §2.2): one PostureState per technique, on
// the Known / Covered / Proven rungs of plan 4.1. Types only; the derivation is
// derive-posture.ts, the D16 breadth guard mitigation-rollup.ts and the display
// words posture-vocabulary.ts.
import type { CoveredQualifier } from '../heatmap-modes';
import type { SourceId } from '../storage-envelope';
import type { TechniqueRefKey } from '../technique-ref';

export type PostureRung = 'none' | 'known' | 'covered' | 'proven';

/** Exactly one per technique. The partition the tallies and the lens use. */
export type PostureBucket = 'none' | 'known' | 'partial' | 'covered' | 'proven' | 'stale';

export type CoveredBasis =
  // self-attested
  | 'capability-confirmed' | 'rule-deployed' | 'mitigation-implemented' | 'control-implemented'
  | 'technique-confirmed' | 'telemetry-configured'
  | 'own-run-blocked'                                  // S4: a blocked own run with no named rule
  // range
  | 'range-deployed' | 'range-detection-authored' | 'range-telemetry-observed';

export type CoveredStrength = 'full' | 'partial' | 'planned';

export interface CoveredMark {
  readonly qualifier: CoveredQualifier;
  readonly basis: CoveredBasis;
  readonly strength: CoveredStrength;
  readonly via?: string;          // 'M1038', control uuid, 'Sysmon::1', 'wazuh:990003'
  readonly source: SourceId;      // §2.3
  readonly at?: string;           // ISO date when known
}

export type ProofScope = 'production' | 'range' | 'own-run';

export interface ProofRecord {
  readonly scope: ProofScope;
  /** Required (S4; D10, dec:234; plan:637): only a named detection reaches Proven. */
  readonly detectionRef: string;
  readonly outcome: 'alerted' | 'blocked';
  readonly date: string;                  // runDate (ISO timestamp) or validated_at (YYYY-MM-DD)
  readonly source: SourceId;
  readonly runId: string;
  readonly missionId?: string;
}

export interface RunVerdict {
  readonly date: string;
  readonly failed: boolean;
  readonly notReproducible: boolean;
  readonly source: SourceId;
}

export type PostureSubState = 'partial' | 'planned' | 'stale' | 'contradicted' | 'not-reproducible' | 'telemetry-observed';

export interface PostureState {
  readonly ref: TechniqueRefKey;
  readonly rung: PostureRung;
  readonly bucket: PostureBucket;
  /** Non-empty exactly when bucket is 'partial' or 'covered' (D5: every Covered badge names its qualifier). */
  readonly qualifiers: readonly CoveredQualifier[];
  readonly subStates: readonly PostureSubState[];     // sorted, unique
  readonly covered: readonly CoveredMark[];
  readonly proof: readonly ProofRecord[];             // qualifying, best first
  readonly proofScope: ProofScope | null;             // scope of the best record
  readonly proofAge: number | null;                   // whole days, best record
  readonly knownSignals: number;                      // 0-5, EnrichmentService.referenceSignalCount
  readonly threatWeight: number;
  readonly exposureWeight: number;                    // always 0 outside Enterprise (§1.16)
  readonly excluded: boolean;                         // not reproducible and no proof: out of the Covered/Proven denominator only
}

export interface PostureTally {
  /** Every parent technique in scope. The Known denominator; equal to today's mappedRollup total (R16). */
  readonly total: number;
  /** total minus excluded. The Covered and Proven denominator. */
  readonly assessable: number;
  readonly none: number;
  readonly known: number;
  readonly partial: number;
  readonly covered: number;
  readonly proven: number;
  readonly stale: number;  // none + known + partial + covered + proven + stale === total
  readonly contradicted: number;
  readonly notReproducible: number;
}

export interface PostureRules {
  readonly mitigationBreadthThreshold: number;                    // D16, default 15
  readonly decayDays: Readonly<Record<ProofScope, number>>;       // D10: range 90, production 180, own-run 90
}

export interface PostureInputs {
  readonly knownSignals: number;
  readonly covered: readonly CoveredMark[];
  readonly proof: readonly ProofRecord[];
  readonly verdicts: readonly RunVerdict[];
  readonly threatWeight: number;
  readonly exposureWeight: number;
}

/** Weight seam: E2.1 ships an all-groups default; P2-10 binds ThreatProfileService. */
export interface ThreatWeightProvider {
  weight(techniqueStixId: string): number;
}

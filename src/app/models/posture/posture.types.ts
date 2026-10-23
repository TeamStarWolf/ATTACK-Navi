// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The posture model (Phase 2 design §2.2): one PostureState per technique, on
// the Known / Covered / Proven rungs of plan 4.1. Types only; the derivation is
// derive-posture.ts, the D16 breadth guard mitigation-rollup.ts and the display
// words posture-vocabulary.ts.
import type { Signal } from '@angular/core';
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

/**
 * Why a mark is partial (RP-F decision 31). Set where the partial mark is produced,
 * never inferred from wording:
 * - 'breadth': the mark reaches the technique only through a mitigation or control
 *   mapped to more techniques than the D16 breadth threshold (mitigation-rollup.ts,
 *   posture-adapters controlsAdapter). The why line says so and the card offers Confirm.
 * - 'telemetry': a range row whose coverage_state is telemetry-observed (posture-adapters
 *   runInputs): the range saw the technique's telemetry and no detection alerted. The
 *   why line says "range telemetry observed via <rule>: partial, no detection alerted",
 *   and the card offers "Record a run", never Confirm.
 */
export type PartialCause = 'breadth' | 'telemetry';

/**
 * The outcome of the range row behind a telemetry partial (RP-F decision 35): part of
 * the cause, set by runInputs where the mark is produced, never inferred from wording.
 * 'logged' or 'none': the range saw telemetry and no detection alerted. 'alerted' or
 * 'blocked': the row's rule fired in that run, but the range reports telemetry-only
 * coverage (coverage_state telemetry-observed), so the run is not proof. Round 7 read
 * "partial, no detection alerted" on T1082 (alerted via wazuh:12) beside a pill that
 * said the rule fired.
 */
export type TelemetryOutcome = 'logged' | 'none' | 'alerted' | 'blocked';

export interface CoveredMark {
  readonly qualifier: CoveredQualifier;
  readonly basis: CoveredBasis;
  readonly strength: CoveredStrength;
  readonly via?: string;          // 'M1038', control uuid, 'Sysmon::1', 'wazuh:990003'
  readonly source: SourceId;      // §2.3
  readonly at?: string;           // ISO date when known
  /** On a partial mark: why it is partial (RP-F decision 31), set by the mark's producer. */
  readonly partialCause?: PartialCause;
  /**
   * On a range telemetry partial (partialCause 'telemetry'): the outcome of its range
   * row (RP-F decision 35), which partial-cause.ts words. Absent on every other mark
   * (and on a hand-built telemetry mark, which then reads as no detection alerted).
   */
  readonly telemetryOutcome?: TelemetryOutcome;
  /**
   * On a range telemetry partial whose rule fired (telemetryOutcome 'alerted' or
   * 'blocked'): the date of the newest run that fired the rule, when that is not the
   * run of the mark's own row (RP-F decision 40: a rule counts as fired when any run in
   * the technique's evidence fired it). Absent when the mark's own run fired it.
   */
  readonly telemetryFiredAt?: string;
  /**
   * On a quiet range telemetry partial (telemetryOutcome 'logged' or 'none', or absent):
   * true when another rule fired in the technique's evidence (RP-F decision 40), so the
   * words name this rule as quiet ("this rule did not alert") and never say "no
   * detection alerted" beside a pill or a Proven block that counts a fired rule.
   */
  readonly techniqueFired?: boolean;
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
  /**
   * How many rules the record's run fired, counted by firedRules over the run itself
   * (RP-F decision 30b; the run's RunSummary.rulesFired), so the card's Proven line
   * names the run's own count even when a later run of one rule removed some of the
   * run's records (decision 29) and others stand. Set by runInputs; absent on a
   * hand-built record.
   */
  readonly runRulesFired?: number;
}

export interface RunVerdict {
  readonly date: string;
  readonly failed: boolean;
  readonly notReproducible: boolean;
  readonly source: SourceId;
}

/**
 * One run of yours on the technique, as derivePosture reads it (RP-F decision 9):
 * enough to say on the card that a run is recorded when it yields no proof.
 */
export interface RunSummary {
  readonly runId: string;
  /** The run's ValidationStatus: 'untested', 'failed', 'passed', 'partial', 'no-telemetry', 'not-reproducible'. */
  readonly status: string;
  readonly date: string;                  // runDate (ISO timestamp) or validated_at (YYYY-MM-DD)
  readonly source: SourceId;
  /**
   * The rules the run fired, whatever its status, counted by firedRules (RP-F
   * decision 30b): the distinct, trimmed, non-empty union of detectionsFired and the
   * rules of its alerted or blocked outcomes, which the Validation pill's "N of M
   * detection rules fired" counts too, so the pill and this count read the same
   * rules. Absent reads as 0. A run that fired a rule but yields no proof
   * (untested, failed, ...) is named with its status wherever the card would
   * otherwise say "No recorded detection" (RP-F decision 28).
   */
  readonly rulesFired?: number;
  /**
   * The detection rules the run names (RP-F decision 29): the distinct trimmed,
   * non-empty rule ids of its outcomes' detectionRefs, detectionsExpected and
   * detectionsFired. Proof supersession is per rule: a later failed or
   * not-reproducible run removes a proof record only when it names that record's
   * detectionRef. A run that names no rule (absent or empty) is the same rule as
   * every record of its own source on the technique (a manual run without a rule id
   * keys on source plus technique).
   */
  readonly rules?: readonly string[];
}

/**
 * A run of yours that outranked every proof record on the technique (RP-F
 * decisions 16, 23 and 29): a failed or not-reproducible run of the SAME detection
 * rule, newer by the one latest-run comparator than the newest record it removed.
 * Proof supersession is per rule (decision 29): an untested, partial or no-telemetry
 * run, or a run of another rule, never removes proof (PostureState.laterRuns names
 * it instead). The why line names both runs by their own status: "latest run of the
 * rule failed on <date>; an earlier run passed on <date>" (or "latest run of the rule
 * was not reproducible on <date>; ..."), then the newest run after it, if any
 * (PostureState.laterRuns).
 */
export interface SupersededProof {
  /**
   * The newest failed or not-reproducible run of the removed record's rule that is
   * later than it (RP-F decision 29); it governs the rung.
   */
  readonly latest: RunSummary;
  /** The newest proof record it outranked (its date is the earlier run's date). */
  readonly earlier: ProofRecord;
  /**
   * The earlier run's own status (its RunSummary, looked up by earlier.runId), so the
   * why line names what that run was ('passed', 'partial', ...) and never says a run
   * passed that did not; null when no run of that id is listed.
   */
  readonly earlierStatus: string | null;
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
  /**
   * The runs of yours on the technique that yield no qualifying proof record
   * (untested; failed; passed or partial with no named rule), newest first
   * (RP-F decision 9). Never a rung: the card only says they are recorded.
   */
  readonly runsWithoutProof: readonly RunSummary[];
  /**
   * The run that outranked every proof record, and the newest record it outranked
   * (RP-F decision 16); null (or absent, in a hand-built state) when no proof was
   * outranked or newer proof still stands. Never a rung: the state is then
   * Covered, partial, Known or None, and 'contradicted' when the latest run
   * failed and no newer full marks hold Covered.
   */
  readonly supersededProof?: SupersededProof | null;
  /**
   * On a Proven or stale state, the runs of yours newer (by the one latest-run
   * comparator) than every standing proof record that left the proof standing (RP-F
   * decision 29): an untested, partial or no-telemetry run, or a failed or
   * not-reproducible run of another rule. Newest first. Never a rung: the why line
   * names the newest ("a later run on <date> observed telemetry only"). On a state
   * whose proof a run removed (supersededProof), every run newer than that remover,
   * whatever its status, so the why line names the newest after "latest run of the
   * rule ..." (the Detection Validation pill shows it). Empty on every other state
   * (absent in a hand-built state).
   */
  readonly laterRuns?: readonly RunSummary[];
  /**
   * The causes of the technique's partial marks (RP-F decision 31), sorted and unique,
   * read from each partial mark's partialCause in every branch (a Proven state may
   * still hold a range telemetry partial, which the Covered lens paints). Empty with
   * no partial mark, or when no partial mark names its cause (a hand-built mark): the
   * why line then names no cause rather than guess one. Absent in a hand-built state.
   */
  readonly partialCauses?: readonly PartialCause[];
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
  /** Every run of yours matched to the technique (RP-F decision 9); absent means none. */
  readonly runs?: readonly RunSummary[];
}

/**
 * Why the threat profile holds no parent technique (RP-F item 6, round 1):
 * - 'names-nothing': the stored source names no groups or campaigns;
 * - 'resolving': no domain is loaded yet, or a library layer is still loading;
 * - 'none-in-domain': the source names some, but none uses a technique in the
 *   loaded domain (APT29 on dom=ics, or groups with no technique use in this release).
 */
export type ThreatProfileEmptyReason = 'names-nothing' | 'resolving' | 'none-in-domain';

/** Weight seam: E2.1 ships an all-groups default; P2-10 binds ThreatProfileService. */
export interface ThreatWeightProvider {
  weight(techniqueStixId: string): number;
  /** Changes whenever weight() answers may change, so PostureService.states can track it. */
  readonly revision: Signal<number>;
  /** The profile's parent technique STIX ids — the threat-relevant denominator (§2.6). */
  readonly parents: Signal<ReadonlySet<string>>;
  /**
   * Why parents() is empty, or null while it is not. Optional: a provider without it
   * gets no Threat gaps profile note (the legend never guesses the reason).
   */
  readonly emptyReason?: Signal<ThreatProfileEmptyReason | null>;
  /**
   * The cross-domain notice ("1 of 2 groups present in ICS: FIN7; APT29 has no ICS
   * use"), or null when every stored group is present in the loaded domain. Optional:
   * a provider without it shows no notice. Read by <app-profile-domain-notice>.
   */
  readonly domainNotice?: Signal<string | null>;
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Report's Known / Covered / partial / Proven split (plan E1.1, rungs in
// plan 4.1; Phase 2 design P2-07, E2.1-d1).
//
//  - Known: mapped is the Known-rung number every summary surface shows
//    (PostureService.rollup, which keeps EnrichmentService.mappedRollup's Known
//    numbers): at least one defensive reference is mapped. "Theoretical:
//    mitigation mapped" stays as a labelled Known sub-line: ATT&CK maps at
//    least one mitigation to the technique. Both come from reference data only
//    and say nothing about the reader's environment.
//  - Covered (self-attested), partial, Proven and stale come from the same
//    posture rollup the posture card, the Validation summary and the stats-bar
//    read, so the report cannot disagree with them. A partial technique is
//    counted by its typed cause (RP-F decision 36, partial-cause.ts): a broad
//    mitigation not confirmed per technique, or range telemetry with no alert
//    credited; the partial card lists a count per cause.
//  - Denominators (design §2.2, R16): Known shares divide by every parent
//    technique (`total`); Covered shares divide by `assessable`, every parent
//    technique minus those excluded by a not-reproducible run with no proof.
//    The rollup carries `assessable` overall and on each tactic row.
//
// The Report Builder panel, the exported HTML report and the printable PDF
// report all read this one function, so the three surfaces give the same
// numbers for the same data. This file reads no owner store: the posture
// numbers come in as a rollup, and the count of mitigations the owner marked
// implemented comes in as a number.

import type { Domain } from './domain';
import type { PostureRollup } from '../services/posture.service';
import { PARTIAL_CAUSES_NOTE, type PartialCauseTally, partialCauseLines } from './posture/partial-cause';
import { COVERED_SOURCE_ORDER, type CoveredSourceTally, coveredSourceLines } from './posture/covered-source';
import { coveredCountLabel, lensLabel } from './posture/posture-vocabulary';

/** The words every Report surface uses for the halves of the split. */
export const REPORT_SPLIT_LABELS = {
  known: 'Known: mapped',
  knownNote: 'At least one defensive reference (mitigation, detection content, control, D3FEND or Atomic test) is mapped. Reference data only; no claim about your environment.',
  theoretical: 'Theoretical: mitigation mapped',
  theoreticalShort: 'Theoretical',
  theoreticalNote: 'ATT&CK reference mapping only. No claim about your environment.',
  /** The report-builder CSV column header (unchanged); its cells come from the posture bucket. */
  implemented: 'Implemented (self-attested)',
  /** The Covered words when no range source is counted; coveredSplitLabels picks them (RP-F decision 43). */
  covered: 'Covered (self-attested)',
  coveredNote: 'A technique you recorded: a narrow mitigation you marked implemented, a control, a confirmation or a run. Not validated.',
  /**
   * The Covered card's label in the Report Builder and the HTML and PDF reports; its
   * lines name each source with its count (coveredCardLines, RP-F decision 43), so a
   * range-only Covered technique is never counted under a self-attested label.
   */
  coveredCard: `${lensLabel('covered')}, by source`,
  /** The word after a Covered share's denominator: `N of A assessable`. */
  assessable: 'assessable',
  assessableNote: 'Covered (self-attested) shares divide by assessable parent techniques: every parent technique except those a not-reproducible run with no proof excludes.',
  partial: 'partial',
  /** The partial card's label; its lines name each cause with its count (partialCardLines, RP-F decision 36). */
  partialCard: 'partial, by cause',
  /** What counts as partial, in the report's note (partial-cause.ts). */
  partialNote: PARTIAL_CAUSES_NOTE,
  stale: 'stale',
  fresh: 'No data of yours recorded yet: the report shows reference mapping only.',
  unmapped: 'No mitigation mapped',
} as const;

export interface TacticSplit {
  name: string;
  shortname: string;
  /** Parent techniques in the tactic column: the Known denominator. */
  total: number;
  /** total minus excluded techniques (R16): the Covered denominator. */
  assessable: number;
  /** Known: mapped (the posture rollup's tactic row). */
  known: number;
  knownPct: number;
  /** Known sub-line: parent techniques with at least one mitigation mapped. */
  theoretical: number;
  theoreticalPct: number;
  covered: number;
  /** covered over assessable, not over total. */
  coveredPct: number;
  partial: number;
  proven: number;
  stale: number;
  /** attackIds of parent techniques with no mitigation mapped, in column order. */
  unmappedIds: string[];
}

export interface ReportSplit {
  /** Parent techniques in the domain: the Known denominator. */
  total: number;
  /** total minus excluded techniques (R16): the Covered denominator. */
  assessable: number;
  /** Known: mapped. */
  known: number;
  knownPct: number;
  /** Known sub-line: Theoretical, mitigation mapped. */
  theoretical: number;
  theoreticalPct: number;
  covered: number;
  /** covered over assessable, not over total. */
  coveredPct: number;
  /** Partial, by either cause (a broad mitigation not confirmed per technique, or range telemetry with no alert credited). */
  partial: number;
  /** The partial techniques by typed cause (RP-F decision 36); null when the rollup carries no count by cause. */
  partialByCause: PartialCauseTally | null;
  /** The Covered techniques by source (RP-F decision 43); null when the rollup carries no count by source. */
  coveredBySource: CoveredSourceTally | null;
  proven: number;
  stale: number;
  /** Parent techniques with no mitigation mapped (total - theoretical). */
  unmapped: number;
  /** Mitigations the owner marked implemented (self-attested). */
  implementedMitigations: number;
  byTactic: TacticSplit[];
}

/**
 * The partial card's lines, one per cause with a count (RP-F decision 36):
 * 'partial (broad mitigation, not confirmed per technique): 3',
 * 'partial (range telemetry, no alert credited): 2'. Every Report surface (the Report
 * Builder panel, the HTML report, the PDF report) prints these under the card.
 */
export function partialCardLines(split: Pick<ReportSplit, 'partialByCause'>): string[] {
  return split.partialByCause ? partialCauseLines(split.partialByCause) : [];
}

/**
 * The Covered card's lines, one per source with a count (RP-F decision 43):
 * 'Covered (self-attested: mitigation, control, confirmation or your run): 3',
 * 'Covered (range: lab-validated detection): 2'. Every Report surface (the Report
 * Builder panel, the HTML report, the PDF report) prints these under the card.
 */
export function coveredCardLines(split: Pick<ReportSplit, 'coveredBySource'>): string[] {
  return split.coveredBySource ? coveredSourceLines(split.coveredBySource) : [];
}

/** The Covered words of a split (coveredSplitLabels): the count's label and its two notes. */
export interface CoveredSplitLabels {
  /** The Covered heading, per-tactic bar key and column header. */
  readonly covered: string;
  /** What the Covered count counts. */
  readonly coveredNote: string;
  /** What a Covered share divides by. */
  readonly assessableNote: string;
}

const RANGE_COVERED_NOTE = 'A technique the range reports a deployed or authored detection for: a lab detection row, not a proof.';
const BOTH_COVERED_NOTE = 'A technique you recorded (a narrow mitigation you marked implemented, a control, a confirmation or a run: self-attested, not validated) or one the range reports a deployed or authored detection for (range: a lab detection row, not a proof).';
const ASSESSABLE_TAIL = 'shares divide by assessable parent techniques: every parent technique except those a not-reproducible run with no proof excludes.';

/**
 * The Covered words every Report surface prints around the split's Covered numbers
 * (the HTML report's split heading, note, per-tactic bars and section subtitle; the PDF
 * report's note and Tactic Breakdown column; the Report Builder's Covered card sub-line,
 * tactic note and column header), by the sources the count includes (RP-F decision 43):
 * with no range source, REPORT_SPLIT_LABELS' self-attested words; with a range source,
 * 'Covered (range)' or 'Covered (self-attested or range)' (coveredCountLabel) and notes
 * that name the range. PR #241 round 1: a range-only profile (T1005, T1105, T1059
 * deployed; T1550.002, T1037.001 detection-authored) read 'Covered (self-attested) 3 of
 * 222' and 'A technique you recorded ... Not validated.' around its range counts.
 */
export function coveredSplitLabels(split: Pick<ReportSplit, 'coveredBySource'>): CoveredSplitLabels {
  const tally = split.coveredBySource;
  const sources = COVERED_SOURCE_ORDER.filter(q => (tally?.[q] ?? 0) > 0);
  if (!sources.includes('range')) {
    return { covered: REPORT_SPLIT_LABELS.covered, coveredNote: REPORT_SPLIT_LABELS.coveredNote, assessableNote: REPORT_SPLIT_LABELS.assessableNote };
  }
  const covered = coveredCountLabel(sources);
  return {
    covered,
    coveredNote: sources.includes('self-attested') ? BOTH_COVERED_NOTE : RANGE_COVERED_NOTE,
    assessableNote: `${covered} ${ASSESSABLE_TAIL}`,
  };
}

type SplitDomain = Pick<Domain, 'techniques' | 'tacticColumns'>;
type SplitTechnique = Domain['techniques'][number];

function pct(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

/** Theoretical (Known sub-line): ATT&CK maps at least one mitigation to the technique. */
export function isTechniqueMapped(t: SplitTechnique): boolean {
  return (t.mitigationCount ?? 0) > 0;
}

/**
 * Split parent techniques into Known (reference mapping, with the Theoretical
 * sub-line) and the posture buckets of the rollup. `rollup` is
 * PostureService.rollup() over parents (subs off); `implementedMitigations` is
 * the owner's count of mitigations marked implemented.
 */
export function computeReportSplit(domain: SplitDomain, rollup: PostureRollup, implementedMitigations: number): ReportSplit {
  const parents = domain.techniques.filter(t => !t.isSubtechnique);
  const total = parents.length;
  const theoretical = parents.filter(isTechniqueMapped).length;
  const o = rollup.overall;

  const byTactic = domain.tacticColumns.map((col, i) => {
    const colParents = col.techniques.filter(t => !t.isSubtechnique);
    const n = colParents.length;
    const colTheoretical = colParents.filter(isTechniqueMapped).length;
    const row = rollup.byTactic.find(r => r.shortname === col.tactic.shortname) ?? rollup.byTactic[i];
    const covered = row?.covered ?? 0;
    const assessable = row?.assessable ?? n;
    return {
      name: col.tactic.name,
      shortname: col.tactic.shortname,
      total: n,
      assessable,
      known: row?.mapped ?? 0,
      knownPct: row?.pct ?? 0,
      theoretical: colTheoretical,
      theoreticalPct: pct(colTheoretical, n),
      covered,
      coveredPct: pct(covered, assessable),
      partial: row?.partial ?? 0,
      proven: row?.proven ?? 0,
      stale: row?.stale ?? 0,
      unmappedIds: colParents.filter(t => !isTechniqueMapped(t)).map(t => t.attackId),
    };
  });

  return {
    total,
    assessable: o.assessable,
    known: o.mapped,
    knownPct: o.pct,
    theoretical,
    theoreticalPct: pct(theoretical, total),
    covered: o.covered,
    coveredPct: pct(o.covered, o.assessable),
    partial: o.partial,
    partialByCause: o.partialByCause ?? null,
    coveredBySource: o.coveredBySource ?? null,
    proven: o.proven,
    stale: o.stale,
    unmapped: total - theoretical,
    implementedMitigations,
    byTactic,
  };
}

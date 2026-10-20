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
//    read, so the report cannot disagree with them. A mitigation that maps
//    more techniques than the breadth threshold (D16) makes its techniques
//    partial, never Covered, until each is confirmed per technique.
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

/** The words every Report surface uses for the halves of the split. */
export const REPORT_SPLIT_LABELS = {
  known: 'Known: mapped',
  knownNote: 'At least one defensive reference (mitigation, detection content, control, D3FEND or Atomic test) is mapped. Reference data only; no claim about your environment.',
  theoretical: 'Theoretical: mitigation mapped',
  theoreticalShort: 'Theoretical',
  theoreticalNote: 'ATT&CK reference mapping only. No claim about your environment.',
  /** The report-builder CSV column header (unchanged); its cells come from the posture bucket. */
  implemented: 'Implemented (self-attested)',
  covered: 'Covered (self-attested)',
  coveredNote: 'A technique you recorded: a narrow mitigation you marked implemented, a control, a confirmation or a run. Not validated.',
  /** The word after a Covered share's denominator: `N of A assessable`. */
  assessable: 'assessable',
  assessableNote: 'Covered (self-attested) shares divide by assessable parent techniques: every parent technique except those a not-reproducible run with no proof excludes.',
  partial: 'partial',
  partialCard: 'partial (broad mitigation, not confirmed per technique)',
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
  /** Covered through a broad mitigation only, not confirmed per technique (D16). */
  partial: number;
  proven: number;
  stale: number;
  /** Parent techniques with no mitigation mapped (total - theoretical). */
  unmapped: number;
  /** Mitigations the owner marked implemented (self-attested). */
  implementedMitigations: number;
  byTactic: TacticSplit[];
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
    proven: o.proven,
    stale: o.stale,
    unmapped: total - theoretical,
    implementedMitigations,
    byTactic,
  };
}

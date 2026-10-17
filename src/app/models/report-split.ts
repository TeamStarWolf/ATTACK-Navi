// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Report's Theoretical / Implemented split (plan E1.1, rungs in plan 4.1).
//
//  - Theoretical is a Known-rung number: ATT&CK maps at least one mitigation
//    to the technique. It comes from reference data only and says nothing
//    about the reader's environment, so it is never worded or coloured as
//    something implemented.
//  - Implemented is a Covered (self-attested) number: at least one mitigation
//    mapped to the technique is one the owner marked 'implemented' in the
//    Implementation Status tracker. Planned, in-progress and not-started
//    mitigations do not count, and nothing reference-only can reach it.
//
// The Report Builder panel, the exported HTML report and the printable PDF
// report all read this one function, so the three surfaces give the same
// numbers for the same data.

import type { Domain } from './domain';
import type { ImplStatus } from '../services/implementation.service';

/** The words every Report surface uses for the two halves of the split. */
export const REPORT_SPLIT_LABELS = {
  theoretical: 'Theoretical: mitigation mapped',
  theoreticalShort: 'Theoretical',
  theoreticalNote: 'ATT&CK reference mapping only. No claim about your environment.',
  implemented: 'Implemented (self-attested)',
  implementedShort: 'Implemented',
  implementedNote: 'A mapped mitigation you marked implemented. Not validated.',
  unmapped: 'No mitigation mapped',
} as const;

export interface TacticSplit {
  name: string;
  /** Parent techniques in the tactic column. */
  total: number;
  /** Known: parent techniques with at least one mitigation mapped. */
  theoretical: number;
  theoreticalPct: number;
  /** Covered (self-attested): parent techniques with a mapped mitigation marked implemented. */
  implemented: number;
  implementedPct: number;
  /** attackIds of parent techniques with no mitigation mapped, in column order. */
  unmappedIds: string[];
}

export interface ReportSplit {
  /** Parent techniques in the domain. */
  total: number;
  theoretical: number;
  theoreticalPct: number;
  implemented: number;
  implementedPct: number;
  /** Parent techniques where EVERY mapped mitigation is marked implemented (self-attested). */
  allMappedImplemented: number;
  /** Parent techniques with no mitigation mapped (total - theoretical). */
  unmapped: number;
  /** Mitigations the owner marked implemented (self-attested). */
  implementedMitigations: number;
  byTactic: TacticSplit[];
}

type SplitDomain = Pick<Domain, 'techniques' | 'tacticColumns' | 'mitigationsByTechnique'>;
type SplitTechnique = Domain['techniques'][number];

function pct(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

function isMapped(t: SplitTechnique): boolean {
  return (t.mitigationCount ?? 0) > 0;
}

/** Theoretical (Known): ATT&CK maps at least one mitigation to the technique. */
export function isTechniqueMapped(t: SplitTechnique): boolean {
  return isMapped(t);
}

/**
 * Implemented (Covered, self-attested): the technique has a mapped mitigation
 * the owner marked 'implemented'. False for every unmapped technique.
 */
export function isTechniqueImplemented(
  domain: Pick<Domain, 'mitigationsByTechnique'>,
  t: SplitTechnique,
  statusMap: ReadonlyMap<string, ImplStatus>,
): boolean {
  if (!isMapped(t)) return false;
  const rels = domain.mitigationsByTechnique.get(t.id) ?? [];
  return rels.some(r => statusMap.get(r.mitigation.id) === 'implemented');
}

/**
 * Split parent techniques into Theoretical (reference mapping) and Implemented
 * (owner-attested). Implemented is always a subset of Theoretical: a technique
 * with no mapped mitigation can never count as implemented.
 */
export function computeReportSplit(domain: SplitDomain, statusMap: ReadonlyMap<string, ImplStatus>): ReportSplit {
  const isImplemented = (t: SplitTechnique): boolean => isTechniqueImplemented(domain, t, statusMap);

  const parents = domain.techniques.filter(t => !t.isSubtechnique);
  const theoretical = parents.filter(isMapped).length;
  const implemented = parents.filter(isImplemented).length;
  const allMappedImplemented = parents.filter(t => {
    if (!isMapped(t)) return false;
    const rels = domain.mitigationsByTechnique.get(t.id) ?? [];
    return rels.length > 0 && rels.every(r => statusMap.get(r.mitigation.id) === 'implemented');
  }).length;

  let implementedMitigations = 0;
  for (const status of statusMap.values()) {
    if (status === 'implemented') implementedMitigations++;
  }

  const byTactic = domain.tacticColumns.map(col => {
    const colParents = col.techniques.filter(t => !t.isSubtechnique);
    const colTheoretical = colParents.filter(isMapped).length;
    const colImplemented = colParents.filter(isImplemented).length;
    return {
      name: col.tactic.name,
      total: colParents.length,
      theoretical: colTheoretical,
      theoreticalPct: pct(colTheoretical, colParents.length),
      implemented: colImplemented,
      implementedPct: pct(colImplemented, colParents.length),
      unmappedIds: colParents.filter(t => !isMapped(t)).map(t => t.attackId),
    };
  });

  return {
    total: parents.length,
    theoretical,
    theoreticalPct: pct(theoretical, parents.length),
    implemented,
    implementedPct: pct(implemented, parents.length),
    allMappedImplemented,
    unmapped: parents.length - theoretical,
    implementedMitigations,
    byTactic,
  };
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The D16 breadth guard as a pure function (Phase 2 design §6): an implemented
// mitigation marks the techniques it is mapped to. A mitigation mapped to at
// most `threshold` techniques in the loaded domain (parents and sub-techniques
// together, Domain.techniquesByMitigation) gives full marks; a broader one gives
// partial marks only, rendered "Covered (self-attested, partial via M1038)",
// each carrying partialCause 'breadth' (RP-F decision 31).
// CI fails unless this file has 100% branch coverage
// (scripts/check-branch-coverage.mjs).
import type { ImplStatus } from '../../services/implementation.service';
import type { Technique } from '../technique';
import type { CoveredMark, CoveredStrength } from './posture.types';

/**
 * Strength for one mitigation status:
 * - 'implemented' → 'full' when the mitigation maps to ≤ threshold techniques, else 'partial';
 * - 'in-progress' and 'planned' → 'planned';
 * - 'not-started' (or anything else) → no mark.
 */
function strengthFor(status: ImplStatus, breadth: number, threshold: number): CoveredStrength | null {
  switch (status) {
    case 'implemented': return breadth <= threshold ? 'full' : 'partial';
    case 'in-progress':
    case 'planned': return 'planned';
    default: return null;
  }
}

/**
 * Roll the v1 mitigation statuses up to self-attested technique marks, keyed
 * by technique STIX id. Each mark names its mitigation in `via` (its ATT&CK id),
 * so a technique reached by two implemented mitigations carries two marks.
 */
export function rollupMitigations(
  impl: ReadonlyMap<string /* mitigation STIX id */, ImplStatus>,
  techniquesByMitigation: ReadonlyMap<string, readonly Technique[]>,
  mitAttackId: (stix: string) => string,
  threshold: number,
): ReadonlyMap<string /* technique STIX id */, CoveredMark[]> {
  const out = new Map<string, CoveredMark[]>();
  for (const [mitId, status] of impl) {
    const techniques = techniquesByMitigation.get(mitId) ?? [];
    const strength = strengthFor(status, techniques.length, threshold);
    if (strength === null) continue;
    const via = mitAttackId(mitId);
    for (const t of techniques) {
      // RP-F decision 31: a partial mark carries its cause where it is produced.
      const mark: CoveredMark = strength === 'partial'
        ? { qualifier: 'self-attested', basis: 'mitigation-implemented', strength, via, source: 'manual', partialCause: 'breadth' }
        : { qualifier: 'self-attested', basis: 'mitigation-implemented', strength, via, source: 'manual' };
      const marks = out.get(t.id);
      if (marks) marks.push(mark);
      else out.set(t.id, [mark]);
    }
  }
  return out;
}

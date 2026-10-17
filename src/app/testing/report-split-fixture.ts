// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// A tiny domain for the Report's Theoretical / Implemented split specs
// (models/report-split.spec.ts and the report surfaces' specs).

import { Domain } from '../models/domain';

interface FixtureTech {
  id: string;
  attackId: string;
  name: string;
  tacticShortnames: string[];
  isSubtechnique: boolean;
  mitigationCount: number;
}

/**
 * Two tactics, five parent techniques and one sub-technique.
 *   T1 execution       M1, M2
 *   T2 execution       M1
 *   T3 execution       (none)
 *   T4 persistence     M3
 *   T5 persistence     (none)
 *   T1.001 (sub)       M1  (sub-techniques never count)
 */
export function makeSplitDomain(): Domain {
  const tech = (n: string, tactic: string, mits: string[], sub = false): FixtureTech & { mits: string[] } => ({
    id: `attack-pattern--${n}`,
    attackId: n,
    name: `Technique ${n}`,
    tacticShortnames: [tactic],
    isSubtechnique: sub,
    mitigationCount: mits.length,
    mits,
  });
  const techs = [
    tech('T1', 'execution', ['M1', 'M2']),
    tech('T2', 'execution', ['M1']),
    tech('T3', 'execution', []),
    tech('T4', 'persistence', ['M3']),
    tech('T5', 'persistence', []),
    tech('T1.001', 'execution', ['M1'], true),
  ];
  const mitigationsByTechnique = new Map<string, unknown[]>();
  for (const t of techs) {
    if (t.mits.length) {
      mitigationsByTechnique.set(t.id, t.mits.map(m => ({ mitigation: { id: `course-of-action--${m}`, attackId: m } })));
    }
  }
  const col = (name: string, shortname: string) => ({
    tactic: { name, shortname },
    techniques: techs.filter(t => t.tacticShortnames[0] === shortname),
  });
  return {
    techniques: techs,
    tacticColumns: [col('Execution', 'execution'), col('Persistence', 'persistence')],
    mitigationsByTechnique,
  } as unknown as Domain;
}

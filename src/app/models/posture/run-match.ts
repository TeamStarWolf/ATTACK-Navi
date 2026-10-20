// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The one matcher between a validation run and a technique of the loaded
// domain (Phase 2 design §8). PostureService and ValidationService.forTechnique
// (the drawer pill) both call it, so they cannot disagree.
//
// Type-only imports: this file has no runtime dependency beyond technique-ref.
import type { AttackDomain } from '../../services/data.service';
import type { Technique } from '../technique';
import { parseTechniqueRef, refForTechnique, sameTechnique, type TechniqueRefKey } from '../technique-ref';

/** The two fields of a run that name its technique. */
export interface RunTechniqueKey {
  /** null for runs migrated from v1 and for runs recorded before any domain loaded (R6). */
  readonly techniqueRef: TechniqueRefKey | null;
  readonly techniqueId: string;
}

/**
 * Whether `run` is a run of technique `t` in the loaded domain `domainId`.
 *
 * - With a ref: `sameTechnique(ref, refForTechnique(t, domainId, v), resolve)`.
 *   The version is ignored (a version mismatch resolves and remaps, never drops),
 *   and F3's T-ids equal Enterprise's (§1.12).
 * - Without a ref (or with one that does not parse): the run's bare id, resolved,
 *   is the technique's id in the loaded domain. The match is made lazily per
 *   loaded domain; the run is never re-keyed to the first domain that loads (§5.3).
 */
export function runMatches(
  run: RunTechniqueKey,
  t: Pick<Technique, 'attackId'>,
  domainId: AttackDomain,
  resolve: (id: string) => string,
): boolean {
  const ref = run.techniqueRef === null ? null : parseTechniqueRef(run.techniqueRef);
  if (ref !== null) {
    return sameTechnique(ref, refForTechnique(t, domainId, ref.version), resolve);
  }
  return resolve(run.techniqueId) === resolve(t.attackId);
}

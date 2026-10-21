// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The seeded posture profiles of the P2-09 before/after specs (Phase 2 design
// §3 P2-09, E2.1-d3), written through the real stores on the lens fixture
// (lens-harness.ts). Both share P2-07's composition:
//   - M1047 implemented (13 techniques, narrow: full marks),
//   - M1026 implemented (16 techniques, broad: partial marks, D16),
//   - one technique confirmed through TechniqueMarksService.confirm,
//   - one passed own run with a fired detection (Proven),
//   - one failed run after a mark (contradicted),
//   - one not-reproducible run (out of `assessable` only).
//
// 'seeded' is P2-07's seed EXACTLY (posture-count-equality.spec.ts picks()):
// proof = only1047[0], failed = only1047[1], confirmed = only1026[0],
// notReproducible = untouched[0] (T1021, T1578, T1003, T1001 on the fixture).
// Its confirmation and passed run sit on M1047/M1026 parents, which already
// carry a defensive reference (a mapped mitigation), so they can never move a
// P2-09 number: risk doubling and the dashboard counters only read techniques
// with no defensive reference. Its after values equal the fresh after values.
//
// 'gapSeeded' is a separate, third profile: P2-07's composition with the
// confirmation and the passed run moved to the two highest-risk unrecorded gaps
// (used by a group, no defensive reference: T1007, T1082 on the fixture), so the
// covered and proven techniques visibly leave the counters and drop in the risk
// order. Its failed and not-reproducible picks are P2-07's (T1578, T1001). This
// profile is a recorded deviation from the design text "Seeded profile (P2-07's
// seed)", which cannot show the movement it asks for (see the PR body).
//
// Picks are derived from the loaded fixture, never hard-coded. Call inside a
// TestBed that provides POSTURE_TODAY as `postureSeedToday()` and has the
// fixture domain loaded into DataService.
import { Provider, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';

import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import { hasDefensiveReference } from '../models/known-signals';
import { POSTURE_TODAY } from '../models/posture/posture-today';
import { refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { EnrichmentService } from '../services/enrichment.service';
import { ImplementationService } from '../services/implementation.service';
import { PostureService } from '../services/posture.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { ValidationService } from '../services/validation.service';

/** The day the seeded runs are dated against (P2-07's TODAY). */
export const POSTURE_SEED_TODAY = new Date('2026-10-01T00:00:00.000Z');
export const daysBeforeSeedToday = (n: number): string => new Date(POSTURE_SEED_TODAY.getTime() - n * 86_400_000).toISOString();

/** Pins PostureService's day, so a run's proof age is fixed. */
export function postureSeedToday(): Provider {
  return { provide: POSTURE_TODAY, useValue: signal(POSTURE_SEED_TODAY) };
}

/** The seeded profiles: P2-07's exact seed, and the unrecorded-gap variant. */
export type SeedProfile = 'seeded' | 'gapSeeded';

export interface PostureSeedPicks {
  /** Confirmed through TechniqueMarksService (bucket covered). */
  readonly confirmed: Technique;
  /** Passed own run with a fired detection (bucket proven). */
  readonly proof: Technique;
  /** M1047-only parent with a failed run after its mark (contradicted). P2-07's only1047[1]. */
  readonly failed: Technique;
  /** First parent mapped by neither mitigation, given a not-reproducible run (excluded). P2-07's untouched[0]. */
  readonly notReproducible: Technique;
}

const byId = (a: Technique, b: Technique) => a.attackId.localeCompare(b.attackId);

/**
 * Unrecorded gaps before any owner data: parent techniques used by at least one
 * group with no defensive reference, highest pre-posture risk first.
 */
export function unrecordedGapsByRisk(domain: Domain): Technique[] {
  const enrichment = TestBed.inject(EnrichmentService);
  return domain.techniques
    .filter(t => !t.isSubtechnique && (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0)
    .filter(t => !hasDefensiveReference(enrichment.signals(t, domain)))
    .sort((a, b) => enrichment.riskScore(b, domain) - enrichment.riskScore(a, domain) || byId(a, b));
}

/**
 * P2-07's pick lists (posture-count-equality.spec.ts picks()), read back through
 * PostureService once M1047 and M1026 are implemented: a parent is "mapped by
 * Mxxxx" when it carries that mitigation's implemented mark. The specs pin the
 * resulting picks to P2-07's (T1003, T1021, T1578, T1001), so the lists match
 * P2-07's map-derived ones on the fixture.
 */
function p207Lists(domain: Domain) {
  const posture = TestBed.inject(PostureService);
  const via = (t: Technique, attackId: string) =>
    posture.stateFor(t).covered.some(c => c.basis === 'mitigation-implemented' && c.via === attackId);
  const parents = domain.techniques.filter(t => !t.isSubtechnique).sort(byId);
  return {
    only1047: parents.filter(t => via(t, 'M1047') && !via(t, 'M1026')),
    only1026: parents.filter(t => via(t, 'M1026') && !via(t, 'M1047')),
    untouched: parents.filter(t => !via(t, 'M1047') && !via(t, 'M1026')),
  };
}

/** Writes one seeded profile through the real stores and returns its picks. */
export function seedPostureProfile(domain: Domain, profile: SeedProfile): PostureSeedPicks {
  const impl = TestBed.inject(ImplementationService);
  for (const id of ['M1047', 'M1026']) impl.setStatus(domain.mitigations.find(m => m.attackId === id)!.id, 'implemented');

  const { only1047, only1026, untouched } = p207Lists(domain);
  const failed = only1047[1];
  const notReproducible = untouched[0];
  let picks: PostureSeedPicks;
  if (profile === 'seeded') {
    picks = { confirmed: only1026[0], proof: only1047[0], failed, notReproducible };
  } else {
    const [confirmed, proof] = unrecordedGapsByRisk(domain);
    if ([failed, notReproducible].some(t => t === confirmed || t === proof)) throw new Error('gapSeeded picks collide');
    picks = { confirmed, proof, failed, notReproducible };
  }

  const key = techniqueRefKey(refForTechnique(picks.confirmed, 'enterprise', domain.attackVersion));
  if (!TestBed.inject(TechniqueMarksService).confirm(key)) throw new Error(`confirm ${picks.confirmed.attackId} failed`);
  const tag = profile === 'seeded' ? 'p207' : 'p209';
  const result = TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
    { id: `${tag}-pass`, techniqueId: picks.proof.attackId, runDate: daysBeforeSeedToday(10), status: 'passed',
      attackResult: 'executed', detectionsFired: [profile === 'seeded' ? 'sigma:p2-07' : 'sigma:p2-09'] },
    { id: `${tag}-fail`, techniqueId: picks.failed.attackId, runDate: daysBeforeSeedToday(5), status: 'failed', attackResult: 'executed' },
    { id: `${tag}-nr`, techniqueId: picks.notReproducible.attackId, runDate: daysBeforeSeedToday(3), status: 'not-reproducible',
      attackResult: 'executed' },
  ] }));
  if (!result.ok) throw new Error('seed runs not imported');
  return picks;
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The seeded posture profile of the P2-09 before/after specs (Phase 2 design
// §3 P2-09, E2.1-d3): P2-07's seed composition (posture-count-equality.spec.ts)
// written through the real stores, on the lens fixture (lens-harness.ts):
//   - M1047 implemented (13 techniques, narrow: full marks),
//   - M1026 implemented (16 techniques, broad: partial marks, D16),
//   - one technique confirmed through TechniqueMarksService.confirm,
//   - one passed own run with a fired detection (Proven),
//   - one failed run after a mark (contradicted),
//   - one not-reproducible run (out of `assessable` only).
// P2-07 places the confirmation and the passed run on M1047/M1026 parents.
// Those already carry a defensive reference (a mapped mitigation), so they can
// never move a P2-09 number: risk doubling and the threat-gap counters only
// ever read techniques with no defensive reference. Here the confirmed and the
// proven technique are the two highest-risk threat gaps instead (used by a
// group, no defensive reference), so the change is visible; the failed and the
// not-reproducible picks follow P2-07. The specs also show that P2-07's own
// picks move nothing.
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

export interface PostureSeedPicks {
  /** Threat gap confirmed through TechniqueMarksService (bucket covered). */
  readonly confirmed: Technique;
  /** Threat gap with a passed own run and a fired detection (bucket proven). */
  readonly proof: Technique;
  /** M1047-only parent with a failed run after its mark (contradicted). */
  readonly failed: Technique;
  /** First parent mapped by neither mitigation, given a not-reproducible run (excluded). */
  readonly notReproducible: Technique;
}

const byId = (a: Technique, b: Technique) => a.attackId.localeCompare(b.attackId);

/**
 * Threat gaps before any owner data: parent techniques used by at least one
 * group with no defensive reference, highest pre-posture risk first.
 */
export function threatGaps(domain: Domain): Technique[] {
  const enrichment = TestBed.inject(EnrichmentService);
  return domain.techniques
    .filter(t => !t.isSubtechnique && (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0)
    .filter(t => !hasDefensiveReference(enrichment.signals(t, domain)))
    .sort((a, b) => enrichment.riskScore(b, domain) - enrichment.riskScore(a, domain) || byId(a, b));
}

/** Writes the seed through the real stores and returns its picks. */
export function seedPostureProfile(domain: Domain): PostureSeedPicks {
  const posture = TestBed.inject(PostureService);
  const impl = TestBed.inject(ImplementationService);
  for (const id of ['M1047', 'M1026']) impl.setStatus(domain.mitigations.find(m => m.attackId === id)!.id, 'implemented');

  const parents = domain.techniques.filter(t => !t.isSubtechnique).sort(byId);
  const [confirmed, proof] = threatGaps(domain);
  const viaMitigation = (t: Technique, attackId: string) =>
    posture.stateFor(t).covered.some(c => c.basis === 'mitigation-implemented' && c.via === attackId);
  const failed = parents.find(t => viaMitigation(t, 'M1047') && !viaMitigation(t, 'M1026'))!;
  const notReproducible = parents.find(t =>
    !viaMitigation(t, 'M1047') && !viaMitigation(t, 'M1026') && t !== confirmed && t !== proof)!;

  const key = techniqueRefKey(refForTechnique(confirmed, 'enterprise', domain.attackVersion));
  if (!TestBed.inject(TechniqueMarksService).confirm(key)) throw new Error(`confirm ${confirmed.attackId} failed`);
  const result = TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
    { id: 'p209-pass', techniqueId: proof.attackId, runDate: daysBeforeSeedToday(10), status: 'passed', attackResult: 'executed',
      detectionsFired: ['sigma:p2-09'] },
    { id: 'p209-fail', techniqueId: failed.attackId, runDate: daysBeforeSeedToday(5), status: 'failed', attackResult: 'executed' },
    { id: 'p209-nr', techniqueId: notReproducible.attackId, runDate: daysBeforeSeedToday(3), status: 'not-reproducible',
      attackResult: 'executed' },
  ] }));
  if (!result.ok) throw new Error('seed runs not imported');
  return { confirmed, proof, failed, notReproducible };
}

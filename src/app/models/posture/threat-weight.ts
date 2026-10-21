// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The threat-weight seam (Phase 2 design §2.2, P2-05; Addendum note 2).
// PostureService reads a technique's threat weight only through
// THREAT_WEIGHT_PROVIDER and never imports ThreatProfileService: E2.1 ships
// the all-groups default below, and P2-10 binds the shared threat profile.
import { InjectionToken, inject, signal } from '@angular/core';
import type { Domain } from '../domain';
import { DataService } from '../../services/data.service';
import type { ThreatWeightProvider } from './posture.types';

/**
 * The all-groups weight: how many ATT&CK groups of the domain use the
 * technique (Domain.groupsByTechnique, keyed by technique STIX id). 0 when no
 * domain is loaded or no group uses it.
 */
export function allGroupsWeight(domain: Pick<Domain, 'groupsByTechnique'> | null, techniqueStixId: string): number {
  return domain?.groupsByTechnique.get(techniqueStixId)?.length ?? 0;
}

/** Reads the loaded domain at call time; PostureService recomputes whenever the domain changes. */
export const THREAT_WEIGHT_PROVIDER = new InjectionToken<ThreatWeightProvider>('THREAT_WEIGHT_PROVIDER', {
  providedIn: 'root',
  factory: (): ThreatWeightProvider => {
    const data = inject(DataService);
    // The all-groups weight only changes with the loaded domain, which PostureService
    // already tracks, so revision is constant here (P2-10 binds the reactive profile).
    // `parents` is empty: the default is not a profile, so a card mounted without the
    // bound token shows a threat-relevant count of 0 (only ctem mounts that scope).
    return {
      weight: (techniqueStixId: string) => allGroupsWeight(data.getCurrentDomain(), techniqueStixId),
      revision: signal(0),
      parents: signal<ReadonlySet<string>>(new Set()),
    };
  },
});

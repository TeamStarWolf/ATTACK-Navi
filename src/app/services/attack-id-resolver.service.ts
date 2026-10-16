// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

/**
 * Translates retired ATT&CK technique ids to the technique that replaced them
 * in the loaded release (Domain.supersededBy, built from MITRE's `revoked-by`
 * chain — e.g. ATT&CK v19 retired T1562.001 in favour of T1685).
 *
 * DataService publishes the map of every domain it loads here. It lives in its
 * own dependency-free service so that the hand-curated lookup tables (YARA,
 * Wazuh, event logging) can translate their keys without pulling HttpClient
 * and the whole data layer into their dependency graph.
 *
 * Until a domain has loaded, `resolve` is the identity function.
 */
@Injectable({ providedIn: 'root' })
export class AttackIdResolverService {
  private supersededBy: ReadonlyMap<string, string> = new Map();
  private revision = 0;

  /**
   * Increments whenever the translation map changes, so callers that keep an
   * index derived from `resolve` know when to rebuild it.
   */
  get version(): number {
    return this.revision;
  }

  setSupersededBy(map: ReadonlyMap<string, string> | null | undefined): void {
    const next = map ?? new Map<string, string>();
    if (next === this.supersededBy) return;
    this.supersededBy = next;
    this.revision++;
  }

  /** The live id for `attackId`: its replacement when retired, otherwise unchanged. */
  resolve(attackId: string): string {
    return this.supersededBy.get(attackId) ?? attackId;
  }
}

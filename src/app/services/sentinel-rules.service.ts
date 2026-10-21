// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface SentinelRule {
  filename: string;
  url: string;
}

/**
 * Withdrawn source: the upstream rule repository this read (a community collection of
 * Azure Sentinel ATT&CK rules) removed every rule on 2024-11-28 and now holds a handful
 * of non-rule files, so there is nothing to fetch. Like CisControlsService, the service
 * makes no request: the registry shows the source as withdrawn upstream (status
 * 'archived-upstream', no rows) and loaded$ stays false. The technique drawer no longer
 * reads it (its Sentinel section was removed); the service stays as the owner the source
 * inventory's withdrawn row names.
 */
@Injectable({ providedIn: 'root' })
export class SentinelRulesService {
  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  /** Nothing to load: the upstream withdrew its rules. */
  loadOnDemand(): void {
    // Intentionally empty (withdrawn upstream on 2024-11-28).
  }

  getRuleCount(_attackId: string): number {
    return 0;
  }

  getRulesForTechnique(_attackId: string): SentinelRule[] {
    return [];
  }
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { Observable, combineLatest, distinctUntilChanged, map, shareReplay } from 'rxjs';
import { HeatmapMode } from './filter.service';
import { ImplementationService } from './implementation.service';
import { ValidationService } from './validation.service';

/** How many records of each owner-data kind the user's stores hold. */
export interface OwnerDataCounts {
  /** Mitigation implementation records (ImplementationService). */
  implementation: number;
  /** Validation runs (ValidationService). */
  validation: number;
  /**
   * Stack declarations. No stack store exists yet (the stack catalog arrives in
   * a later phase), so this is 0 today; the rule below already counts it.
   */
  stack: number;
}

/**
 * Decision D4: owner data exists when the user's stores hold any
 * Implementation, Validation or stack record.
 */
export function hasOwnerData(c: OwnerDataCounts): boolean {
  return c.implementation > 0 || c.validation > 0 || c.stack > 0;
}

/** The one-line first-glance banner shown over the Prevalence lens (plan E1.5, D4). */
export const PREVALENCE_BANNER_TEXT =
  'Showing adversary prevalence: reference data on how many ATT&CK groups use each technique, not a view of your environment. ' +
  'Tell Navi about your environment to see your posture.';

/**
 * The banner shows while the Prevalence lens ('frequency') is on screen and no
 * owner data exists. On any other lens its first words would be untrue, and
 * once owner data exists the lens is no longer standing in for a posture view.
 */
export function showPrevalenceBanner(mode: HeatmapMode, ownerDataExists: boolean): boolean {
  return mode === 'frequency' && !ownerDataExists;
}

/**
 * Whether the user has told Navi anything about their own environment. Reads
 * the existing stores; owns no state of its own.
 */
@Injectable({ providedIn: 'root' })
export class OwnerDataService {
  private readonly implementation = inject(ImplementationService);
  private readonly validation = inject(ValidationService);

  readonly counts$: Observable<OwnerDataCounts> = combineLatest([
    this.implementation.status$,
    this.validation.runs$,
  ]).pipe(
    map(([statuses, runs]) => ({ implementation: statuses.size, validation: runs.length, stack: 0 })),
  );

  readonly hasOwnerData$: Observable<boolean> = this.counts$.pipe(
    map(hasOwnerData),
    distinctUntilChanged(),
    shareReplay({ bufferSize: 1, refCount: true }),
  );
}

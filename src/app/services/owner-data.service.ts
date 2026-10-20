// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { Observable, combineLatest, distinctUntilChanged, map, shareReplay } from 'rxjs';
import { HeatmapMode } from './filter.service';
import { ImplStatus, ImplementationService } from './implementation.service';
import { TechniqueMarksService } from './technique-marks.service';
import { ValidationService } from './validation.service';

/** How many records of each owner-data kind the user's stores hold. */
export interface OwnerDataCounts {
  /** Mitigation implementation records (ImplementationService). */
  implementation: number;
  /** Validation runs (ValidationService). */
  validation: number;
  /**
   * Stack declarations. No stack store exists yet (the stack catalog arrives in
   * a later phase), so this is 0 today. The D4 predicate reads the raw stores,
   * not these counts.
   */
  stack: number;
}

/** The raw store values the D4 predicate reads. All three are synchronous and domain-free. */
export interface OwnerDataInputs {
  /** The v1 implementation map (mitre-nav-impl-v1): key → status. */
  readonly statuses: ReadonlyMap<string, ImplStatus>;
  /** Validation runs in the v2 store (navi.v2.validation-runs), any source. */
  readonly runs: number;
  /** Technique marks (navi.v2.technique-marks), any source. */
  readonly marks: readonly { readonly status: ImplStatus }[];
}

const MITIGATION_KEY = /^course-of-action--\S+$/;
const TECHNIQUE_KEY = /^attack-pattern--\S+$/;

/**
 * Decision D4, exact (Phase 2 design §3 P2-05 and §10.4 item 3, widened in
 * Revision 3): owner data exists when any one of these holds:
 * - at least one validation run (any source, v2 store);
 * - at least one 'course-of-action--*' key whose status is 'implemented' in
 *   the v1 map (an implemented mitigation);
 * - at least one 'attack-pattern--*' key whose status is 'implemented' in the
 *   v1 map (a wizard technique rating);
 * - at least one technique mark whose status is 'implemented', from any
 *   source (Confirm, bulk set or a 'layer:' import, from P2-16 on).
 * 'planned', 'in-progress' and 'not-started' do not count, nor do keys that are
 * neither STIX id (a bare 'M1036' from the CSV import). Controls and telemetry
 * do not count: they do not switch the default lens (the owner's decision,
 * §10.4 item 3); they do make Covered words show (PostureService.ownerWords).
 */
export function hasOwnerData(i: OwnerDataInputs): boolean {
  if (i.runs > 0) return true;
  for (const [key, status] of i.statuses) {
    if (status === 'implemented' && (MITIGATION_KEY.test(key) || TECHNIQUE_KEY.test(key))) return true;
  }
  return i.marks.some(m => m.status === 'implemented');
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
 * the existing stores; owns no state of its own. It must not inject
 * PostureService: PostureService reads this service, so the banner's
 * owner-words half is combined in matrix-page instead.
 */
@Injectable({ providedIn: 'root' })
export class OwnerDataService {
  private readonly implementation = inject(ImplementationService);
  private readonly validation = inject(ValidationService);
  private readonly marks = inject(TechniqueMarksService);

  /** Display counts; their shape is unchanged. D4 does not read them (`implementation` counts every status). */
  readonly counts$: Observable<OwnerDataCounts> = combineLatest([
    this.implementation.status$,
    this.validation.runs$,
  ]).pipe(
    map(([statuses, runs]) => ({ implementation: statuses.size, validation: runs.length, stack: 0 })),
  );

  /** Exact D4. The first emission is synchronous: every input is a BehaviorSubject read before any domain loads. */
  readonly hasOwnerData$: Observable<boolean> = combineLatest([
    this.implementation.status$,
    this.validation.runs$,
    this.marks.marks$,
  ]).pipe(
    map(([statuses, runs, marks]) => hasOwnerData({ statuses, runs: runs.length, marks })),
    distinctUntilChanged(),
    shareReplay({ bufferSize: 1, refCount: true }),
  );
}

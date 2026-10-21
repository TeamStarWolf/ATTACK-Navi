// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { BehaviorSubject, Observable, map, of } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';
import {
  RuleCoverageLink, RuleCoverageSection, RuleCoverageSnapshotService, ruleLinks, snapshotVersion,
} from './rule-coverage-snapshot.service';

/**
 * Elastic detection-rules, as reference data: how many rules in elastic/detection-rules
 * name each ATT&CK technique, read from the rule bodies ([[rule.threat.technique]] ids)
 * at a pinned commit by scripts/build-rule-coverage-snapshot.mjs and shipped in
 * src/assets/data/rule-coverage-snapshot.json. A count says what the public repository
 * holds at that commit, not what runs in any environment.
 */
@Injectable({ providedIn: 'root' })
export class ElasticService {
  private readonly snapshot = inject(RuleCoverageSnapshotService);
  private readonly sources = inject(SourceRegistryService);

  private counts = new Map<string, number>();
  private section: RuleCoverageSection | null = null;

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  /** Rules parsed from the repository at the pinned commit. */
  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  /** Techniques named by at least one rule. */
  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor() {
    this.load();
  }

  private load(): void {
    this.sources.begin('elastic-tree');
    this.snapshot.section('elastic').subscribe({
      next: section => {
        try {
          this.ingest(section);
        } catch (err) {
          this.sources.fail('elastic-tree', err);
        }
      },
      error: err => this.sources.fail('elastic-tree', err),
    });
  }

  private ingest(section: RuleCoverageSection): void {
    // Everything that can throw runs before any state changes, so a bad section leaves nothing behind.
    const version = snapshotVersion(section);
    const counts = new Map<string, number>();
    for (const [id, t] of Object.entries(section.techniques)) {
      if (t.count > 0) counts.set(id, t.count);
    }
    this.counts = counts;
    this.section = section;
    this.totalSubject.next(section.ruleCount);
    this.coveredSubject.next(counts.size);
    this.sources.succeed('elastic-tree', counts.size, { version });
    if (counts.size > 0) this.loadedSubject.next(true);
  }

  /**
   * Rules naming a technique. A parent's count is already the distinct rules naming it
   * or any of its sub-techniques (the snapshot rolls them up), so nothing is added here.
   */
  getRuleCount(attackId: string): number {
    return this.counts.get(attackId) ?? 0;
  }

  /** Alias used by matrix heatmap. */
  getHeatScore(attackId: string): number {
    return this.getRuleCount(attackId);
  }

  /** Every technique with its rule count (techniqueId to count). */
  getCounts(): ReadonlyMap<string, number> {
    return this.counts;
  }

  /** Up to ten rule names for a technique, each with its permalink at the pinned commit. */
  fetchRulesForTechnique(attackId: string): Observable<RuleCoverageLink[]> {
    if (this.section) return of(ruleLinks(this.section, attackId));
    return this.snapshot.section('elastic').pipe(map(section => ruleLinks(section, attackId)));
  }
}

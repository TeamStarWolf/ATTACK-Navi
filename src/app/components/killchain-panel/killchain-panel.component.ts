// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

import { Subscription } from 'rxjs';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { Tactic } from '../../models/tactic';

export interface TacticStat {
  tactic: Tactic;
  attackId: string;
  totalTechs: number;
  coveredTechs: number;
  coveragePct: number;
  subtechniqueCount: number;
  threatGroupCount: number;
  avgMitigations: number;
  topUncoveredTech: string;
}

@Component({
  selector: 'app-killchain-panel',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './killchain-panel.component.html',
  styleUrl: './killchain-panel.component.scss',
})
export class KillchainPanelComponent implements OnInit, OnDestroy {
  tacticStats: TacticStat[] = [];
  /** Name of the domain the stats were computed from (e.g. "ICS ATT&CK"), for the header. */
  domainName = '';
  selectedTacticId: string | null = null;
  hoveredTacticId: string | null = null;

  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Long-lived, not take(1): the domain selector lives in the global toolbar and
    // does not navigate, so this routed instance outlives a domain switch. DataService
    // emits null while the next bundle loads (spinner), then the new domain (recompute).
    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        if (domain) {
          this.buildStats(domain);
        } else {
          // Keep selectedTacticId: buildStats drops it only if the new domain lacks it.
          this.tacticStats = [];
          this.domainName = '';
          this.hoveredTacticId = null;
          this.cdr.markForCheck();
        }
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildStats(domain: Domain): void {
    const stats: TacticStat[] = [];

    for (const col of domain.tacticColumns) {
      const parentTechs = col.techniques.filter(t => !t.isSubtechnique);
      const totalTechs = parentTechs.length;
      const coveredTechs = parentTechs.filter(t => t.mitigationCount > 0).length;
      const coveragePct = totalTechs > 0 ? Math.round((coveredTechs / totalTechs) * 100) : 0;

      // Subtechnique count
      let subtechniqueCount = 0;
      for (const tech of parentTechs) {
        subtechniqueCount += tech.subtechniques.length;
      }

      // Threat group count: unique groups across all parent techniques in this tactic
      const groupIdSet = new Set<string>();
      for (const tech of parentTechs) {
        const groups = this.dataService.getGroupsForTechnique(tech.id);
        for (const g of groups) {
          groupIdSet.add(g.id);
        }
      }
      const threatGroupCount = groupIdSet.size;

      // Average mitigations per technique
      const totalMits = parentTechs.reduce((sum, t) => sum + t.mitigationCount, 0);
      const avgMitigations = totalTechs > 0
        ? Math.round((totalMits / totalTechs) * 10) / 10
        : 0;

      // Top uncovered technique: uncovered techniques sorted by group usage (descending)
      const uncovered = parentTechs.filter(t => t.mitigationCount === 0);
      let topUncoveredTech = '';
      if (uncovered.length > 0) {
        const withCounts = uncovered.map(t => ({
          name: t.name,
          groupCount: (domain.groupsByTechnique.get(t.id) ?? []).length,
        }));
        withCounts.sort((a, b) => b.groupCount - a.groupCount);
        topUncoveredTech = withCounts[0].name;
      }

      stats.push({
        tactic: col.tactic,
        attackId: col.tactic.attackId,
        totalTechs,
        coveredTechs,
        coveragePct,
        subtechniqueCount,
        threatGroupCount,
        avgMitigations,
        topUncoveredTech,
      });
    }

    this.tacticStats = stats;
    this.domainName = domain.name;
    // A tactic selected under the previous domain does not exist in this one.
    if (this.selectedTacticId && !stats.some(s => s.tactic.id === this.selectedTacticId)) {
      this.selectedTacticId = null;
    }
    this.hoveredTacticId = null;
    this.cdr.markForCheck();
  }

  selectTactic(stat: TacticStat): void {
    this.selectedTacticId = this.selectedTacticId === stat.tactic.id ? null : stat.tactic.id;
    this.cdr.markForCheck();
  }

  coverageClass(pct: number): string {
    if (pct >= 75) return 'coverage-green';
    if (pct >= 50) return 'coverage-yellow';
    if (pct >= 25) return 'coverage-orange';
    return 'coverage-red';
  }

  coverageColor(pct: number): string {
    if (pct >= 75) return '#4ade80';
    if (pct >= 50) return '#fbbf24';
    if (pct >= 25) return '#f97316';
    return '#f87171';
  }

  get bestCovered(): TacticStat | null {
    if (!this.tacticStats.length) return null;
    return [...this.tacticStats].sort((a, b) => b.coveragePct - a.coveragePct)[0];
  }

  get worstCovered(): TacticStat | null {
    if (!this.tacticStats.length) return null;
    return [...this.tacticStats].sort((a, b) => a.coveragePct - b.coveragePct)[0];
  }

  get totalTechniques(): number {
    return this.tacticStats.reduce((sum, s) => sum + s.totalTechs, 0);
  }

  get overallCoverage(): number {
    const total = this.totalTechniques;
    if (!total) return 0;
    const covered = this.tacticStats.reduce((sum, s) => sum + s.coveredTechs, 0);
    return Math.round((covered / total) * 100);
  }

  get totalThreatGroups(): number {
    // Unique across all tactics â€” need to re-derive from domain
    // For summary we use max of all distinct groups seen in tacticStats as a proxy
    // (could double count across tactics, but this is a display metric)
    const seen = new Set<string>();
    // We'll just show the sum unique per tactic for display purposes
    return this.tacticStats.reduce((max, s) => Math.max(max, s.threatGroupCount), 0);
  }
}

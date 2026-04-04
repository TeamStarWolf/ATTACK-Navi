import { Component, Input, Output, EventEmitter, OnInit, OnDestroy, OnChanges, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { Domain } from '../../models/domain';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { FilterService } from '../../services/filter.service';

interface TacticStat {
  name: string;
  shortname: string;
  covered: number;
  total: number;
  pct: number;
}

@Component({
  selector: 'app-stats-bar',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './stats-bar.component.html',
  styleUrl: './stats-bar.component.scss',
})
export class StatsBarComponent implements OnInit, OnChanges, OnDestroy {
  @Input() domain!: Domain;
  @Output() tacticClicked = new EventEmitter<string>();

  totalTechniques = 0;
  coveredTechniques = 0;
  coveragePct = 0;
  implementedPct = 0;
  implementedCount = 0;
  totalMitigations = 0;
  totalRelationships = 0;
  tacticStats: TacticStat[] = [];
  includeSubtechniques = false;
  showTacticBars = true;

  private subs = new Subscription();

  constructor(
    private implService: ImplementationService,
    private cdr: ChangeDetectorRef,
    private timelineService: TimelineService,
    private filterService: FilterService,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.implService.status$.subscribe(() => {
        this.recompute();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.timelineService.snapshots$.subscribe(() => {
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnChanges(): void {
    this.recompute();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  toggleTacticBars(): void {
    this.showTacticBars = !this.showTacticBars;
    this.cdr.markForCheck();
  }

  toggleSubtechniques(): void {
    this.includeSubtechniques = !this.includeSubtechniques;
    this.recompute();
    this.cdr.markForCheck();
  }

  openTimeline(): void {
    this.filterService.setActivePanel('timeline');
  }

  get sparklineData(): number[] {
    const snapshots = this.timelineService.getAll();
    if (snapshots.length < 2) return [];
    return snapshots
      .slice()
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .slice(-10)
      .map(s => s.coveragePct);
  }

  get hasTrend(): boolean {
    return this.sparklineData.length >= 2;
  }

  get coverageTrend(): number {
    const data = this.sparklineData;
    if (data.length < 2) return 0;
    return Math.round((data[data.length - 1] - data[0]) * 10) / 10;
  }

  get sparklinePoints(): Array<{ x: number; y: number; w: number; h: number; color: string }> {
    const data = this.sparklineData;
    if (data.length < 2) return [];
    const barWidth = Math.floor(58 / data.length) - 1;
    return data.map((val, i) => ({
      x: i * (barWidth + 1),
      y: 20 - Math.round((val / 100) * 18),
      w: barWidth,
      h: Math.round((val / 100) * 18),
      color: val >= 70 ? '#4ade80' : val >= 50 ? '#fbbf24' : '#f87171',
    }));
  }

  private recompute(): void {
    if (!this.domain) return;

    const parentTechs = this.includeSubtechniques
      ? this.domain.techniques
      : this.domain.techniques.filter((t) => !t.isSubtechnique);
    this.totalTechniques = parentTechs.length;
    this.coveredTechniques = parentTechs.filter((t) => t.mitigationCount > 0).length;
    this.coveragePct = this.totalTechniques > 0 ? Math.round((this.coveredTechniques / this.totalTechniques) * 100) : 0;
    this.totalMitigations = this.domain.mitigations.length;

    let relCount = 0;
    this.domain.mitigationsByTechnique.forEach((rels) => (relCount += rels.length));
    this.totalRelationships = relCount;

    // Implemented coverage
    const statusMap = this.implService.getStatusMap();
    const implementedTechIds = new Set<string>();
    for (const [mitId, status] of statusMap.entries()) {
      if (status === 'implemented') {
        const techs = this.domain.techniquesByMitigation.get(mitId) ?? [];
        for (const t of techs) {
          if (!t.isSubtechnique) implementedTechIds.add(t.id);
        }
      }
    }
    this.implementedCount = implementedTechIds.size;
    this.implementedPct = this.totalTechniques > 0 ? Math.round((this.implementedCount / this.totalTechniques) * 100) : 0;

    this.tacticStats = this.domain.tacticColumns.map((col) => {
      const total = col.techniques.length;
      const covered = col.techniques.filter((t) => t.mitigationCount > 0).length;
      return {
        name: col.tactic.name,
        shortname: col.tactic.shortname,
        covered,
        total,
        pct: total > 0 ? Math.round((covered / total) * 100) : 0,
      };
    });
  }
}

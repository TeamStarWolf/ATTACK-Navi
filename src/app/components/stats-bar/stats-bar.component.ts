// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component, Input, Output, EventEmitter, OnInit, OnDestroy, OnChanges, ChangeDetectionStrategy, ChangeDetectorRef,
  Signal, computed, inject, signal,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { Domain } from '../../models/domain';
import { TimelineService } from '../../services/timeline.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { EnrichmentService } from '../../services/enrichment.service';
import { PostureService } from '../../services/posture.service';
import { PROVEN } from '../../models/posture/posture-vocabulary';

/** The posture numbers the bar shows: parents only, plus the Covered count with sub-techniques. */
export interface StatsBarPosture {
  /** Parent techniques: the denominator of the parents-only tally. */
  total: number;
  covered: number;
  partial: number;
  proven: number;
  stale: number;
  /** Covered over parents and sub-techniques; shown only while includeSubtechniques is on. */
  coveredWithSubs: number;
}

/** Snapshots on another count basis (mitigations only, before E1.7) stay out of the trend. */
const TREND_BASIS = 'reference-mapped';

interface TacticStat {
  name: string;
  shortname: string;
  mapped: number;
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
  /** Known tier: techniques with >=1 defensive reference input mapped (EnrichmentService.mappedRollup). */
  mappedTechniques = 0;
  mappedPct = 0;
  totalMitigations = 0;
  totalRelationships = 0;
  tacticStats: TacticStat[] = [];
  includeSubtechniques = false;
  showTacticBars = true;

  readonly provenLabel = PROVEN;

  private readonly posture = inject(PostureService);
  /** Covered and Proven words render only when the owner has recorded data (§2.4). */
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;
  private readonly subsOn = signal(false);
  /**
   * The Covered/partial tally, refreshed from PostureService.states (S12):
   * parents only, the same numbers as the posture card and the report. With
   * sub-techniques on, the Covered count over every technique is a second,
   * labelled number.
   */
  readonly postureTally: Signal<StatsBarPosture> = computed(() => {
    const o = this.posture.rollup().overall;
    const coveredWithSubs = this.subsOn() ? this.posture.rollup({ includeSubtechniques: true }).overall.covered : o.covered;
    return { total: o.total, covered: o.covered, partial: o.partial, proven: o.proven, stale: o.stale, coveredWithSubs };
  });

  private subs = new Subscription();

  constructor(
    private cdr: ChangeDetectorRef,
    private timelineService: TimelineService,
    private panelNav: PanelNavService,
    private enrichment: EnrichmentService,
  ) {}

  ngOnInit(): void {
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
    this.subsOn.set(this.includeSubtechniques);
    this.recompute();
    this.cdr.markForCheck();
  }

  openTimeline(): void {
    this.panelNav.open('timeline');
  }

  get sparklineData(): number[] {
    const snapshots = this.timelineService.getAll().filter(s => s.basis === TREND_BASIS);
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

    // Known tier ('mapped'): defensive reference inputs only, never threat-intel
    // or CVE links (E1.7). The same rollup feeds the per-tactic bars below.
    const rollup = this.enrichment.mappedRollup(this.domain, { includeSubtechniques: this.includeSubtechniques });
    this.totalTechniques = rollup.overall.total;
    this.mappedTechniques = rollup.overall.mapped;
    this.mappedPct = rollup.overall.pct;
    this.totalMitigations = this.domain.mitigations.length;

    let relCount = 0;
    this.domain.mitigationsByTechnique.forEach((rels) => (relCount += rels.length));
    this.totalRelationships = relCount;

    this.tacticStats = rollup.byTactic.map((t) => ({
      name: t.tacticName,
      shortname: t.shortname,
      mapped: t.mapped,
      total: t.total,
      pct: t.pct,
    }));
  }
}

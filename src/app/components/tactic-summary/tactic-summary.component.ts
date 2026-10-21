// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  OnInit,
  OnDestroy,
  Signal,
  computed,
  inject,
  signal,
} from '@angular/core';

import { Subscription } from 'rxjs';
import { Tactic } from '../../models/tactic';
import { Technique } from '../../models/technique';
import { ImplementationService, ImplStatus } from '../../services/implementation.service';
import { EnrichmentService, MappedCount } from '../../services/enrichment.service';
import { PostureService, type PostureRollup } from '../../services/posture.service';
import { Domain } from '../../models/domain';
import { POSTURE_LINE_LABELS } from '../posture-card/posture-card.component';

export interface TacticSummaryData {
  tactic: Tactic;
  techniques: Technique[];        // all techniques (parents + subs) in this tactic
  parentTechniques: Technique[];  // only parent techniques
  domain: Domain;                 // for mitigationsByTechnique lookups
}

@Component({
  selector: 'app-tactic-summary',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './tactic-summary.component.html',
  styleUrl: './tactic-summary.component.scss',
})
export class TacticSummaryComponent implements OnInit, OnDestroy {
  data: TacticSummaryData | null = null;
  position: { top: number; left: number } = { top: 0, left: 0 };
  visible = false;
  /**
   * Known tier ('mapped', E1.7): this tactic's parent techniques with >=1
   * defensive reference input, from this tactic's row of
   * PostureService.rollup() (P2-08), whose Known numbers are mappedRollup's.
   * Never counts threat-intel or CVE links.
   */
  mappedStats: MappedCount = { total: 0, mapped: 0, pct: 0 };
  private readonly posture = inject(PostureService);
  private readonly tacticId = signal<string | null>(null);
  /** The same rollup row's Covered / partial / Proven / stale, shown only under ownerWords(). */
  readonly postureStats: Signal<PostureRollup['byTactic'][number] | null> = computed(() => {
    const id = this.tacticId();
    return id === null ? null : this.posture.rollup().byTactic.find((r) => r.tacticId === id) ?? null;
  });
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;
  readonly labels = POSTURE_LINE_LABELS;
  /** Most-mapped techniques, ranked by how many of the five reference inputs they have. */
  topMapped: Array<Technique & { referenceCount: number }> = [];

  private latestStatusMap = new Map<string, ImplStatus>();
  private subs = new Subscription();

  constructor(
    private implService: ImplementationService,
    private enrichment: EnrichmentService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.implService.status$.subscribe((map) => {
        this.latestStatusMap = map;
        if (this.visible) this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  show(data: TacticSummaryData, event: MouseEvent): void {
    this.data = data;
    this.tacticId.set(data.tactic.id);
    const row = this.postureStats();
    // The tactic column of the loaded domain; before PostureService sees that
    // domain, the Known count comes from the same oracle the rollup reads.
    this.mappedStats = row
      ? { total: row.total, mapped: row.mapped, pct: row.pct }
      : this.enrichment.mappedCount(data.parentTechniques, data.domain);
    this.topMapped = [...data.parentTechniques]
      .map((t) => ({ ...t, referenceCount: this.enrichment.referenceSignalCount(t, data.domain) }))
      .filter((t) => t.referenceCount > 0)
      .sort((a, b) => b.referenceCount - a.referenceCount || b.mitigationCount - a.mitigationCount)
      .slice(0, 3);
    this.visible = true;
    this.positionNear(event);
    this.cdr.markForCheck();
  }

  hide(): void {
    this.visible = false;
    this.data = null;
    this.mappedStats = { total: 0, mapped: 0, pct: 0 };
    this.tacticId.set(null);
    this.topMapped = [];
    this.cdr.markForCheck();
  }

  private positionNear(event: MouseEvent): void {
    const POPUP_W = 288;  // width + border
    const POPUP_H = 320;  // estimated height
    const margin = 12;
    let left = event.clientX + margin;
    let top = event.clientY + margin;

    if (left + POPUP_W > window.innerWidth) {
      left = event.clientX - POPUP_W - margin;
    }
    if (top + POPUP_H > window.innerHeight) {
      top = event.clientY - POPUP_H - margin;
    }
    // Clamp to viewport edges
    left = Math.max(8, left);
    top = Math.max(8, top);

    this.position = { top, left };
  }

  /** Mitigation-only coverage, kept as an explicit secondary line. */
  get mitigationStats(): { covered: number; total: number; pct: number } {
    if (!this.data) return { covered: 0, total: 0, pct: 0 };
    const total = this.data.parentTechniques.length;
    const covered = this.data.parentTechniques.filter((t) => t.mitigationCount > 0).length;
    return { covered, total, pct: total > 0 ? Math.round((covered / total) * 100) : 0 };
  }

  /** Parent techniques in this tactic with no defensive reference input mapped. */
  get unmappedCount(): number {
    return this.mappedStats.total - this.mappedStats.mapped;
  }

  get implStats(): { implemented: number; inProgress: number; planned: number; notStarted: number } {
    if (!this.data) return { implemented: 0, inProgress: 0, planned: 0, notStarted: 0 };

    // Collect all unique mitigation IDs across all techniques in this tactic
    const mitigationIds = new Set<string>();
    for (const tech of this.data.techniques) {
      const rels = this.data.domain.mitigationsByTechnique.get(tech.id) ?? [];
      for (const rel of rels) {
        mitigationIds.add(rel.mitigation.id);
      }
    }

    let implemented = 0;
    let inProgress = 0;
    let planned = 0;
    let notStarted = 0;

    for (const mitId of mitigationIds) {
      const status = this.latestStatusMap.get(mitId);
      if (status === 'implemented') implemented++;
      else if (status === 'in-progress') inProgress++;
      else if (status === 'planned') planned++;
      else if (status === 'not-started') notStarted++;
    }

    return { implemented, inProgress, planned, notStarted };
  }

  get hasAnyImpl(): boolean {
    const s = this.implStats;
    return s.implemented + s.inProgress + s.planned + s.notStarted > 0;
  }
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  OnInit,
  OnDestroy,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { Tactic } from '../../models/tactic';
import { Technique } from '../../models/technique';
import { ImplementationService, ImplStatus } from '../../services/implementation.service';
import { Domain } from '../../models/domain';

export interface TacticSummaryData {
  tactic: Tactic;
  techniques: Technique[];        // all techniques (parents + subs) in this tactic
  parentTechniques: Technique[];  // only parent techniques
  domain: Domain;                 // for mitigationsByTechnique lookups
}

@Component({
  selector: 'app-tactic-summary',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './tactic-summary.component.html',
  styleUrl: './tactic-summary.component.scss',
})
export class TacticSummaryComponent implements OnInit, OnDestroy {
  data: TacticSummaryData | null = null;
  position: { top: number; left: number } = { top: 0, left: 0 };
  visible = false;

  private latestStatusMap = new Map<string, ImplStatus>();
  private subs = new Subscription();

  constructor(
    private implService: ImplementationService,
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
    this.visible = true;
    this.positionNear(event);
    this.cdr.markForCheck();
  }

  hide(): void {
    this.visible = false;
    this.data = null;
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

  get coverageStats(): { covered: number; total: number; pct: number } {
    if (!this.data) return { covered: 0, total: 0, pct: 0 };
    const total = this.data.parentTechniques.length;
    const covered = this.data.parentTechniques.filter((t) => t.mitigationCount > 0).length;
    return { covered, total, pct: total > 0 ? Math.round((covered / total) * 100) : 0 };
  }

  get topCovered(): Array<Technique & { mitigationCount: number }> {
    return [...(this.data?.parentTechniques ?? [])]
      .filter((t) => t.mitigationCount > 0)
      .sort((a, b) => b.mitigationCount - a.mitigationCount)
      .slice(0, 3) as Array<Technique & { mitigationCount: number }>;
  }

  get uncoveredCount(): number {
    return (this.data?.parentTechniques ?? []).filter((t) => t.mitigationCount === 0).length;
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

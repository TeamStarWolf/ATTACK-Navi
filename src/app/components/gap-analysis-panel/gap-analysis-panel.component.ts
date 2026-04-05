import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { GapAnalysisService, GapAnalysisResult, PrioritizedGap } from '../../services/gap-analysis.service';
import { ThreatGroup } from '../../models/group';
import { Domain } from '../../models/domain';

interface CoverageSourceRow {
  key: string;
  label: string;
  covered: number;
  total: number;
  pct: number;
}

@Component({
  selector: 'app-gap-analysis-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './gap-analysis-panel.component.html',
  styleUrl: './gap-analysis-panel.component.scss',
})
export class GapAnalysisPanelComponent implements OnInit, OnDestroy {
  visible = false;
  result: GapAnalysisResult | null = null;

  // Step 1 state
  analyzeAll = false;
  actorSearch = '';
  selectedActorIds = new Set<string>();
  allGroups: ThreatGroup[] = [];
  private domain: Domain | null = null;

  // Step 2 state
  detectionSources: CoverageSourceRow[] = [];
  displayedGaps: PrioritizedGap[] = [];
  gapLimit = 20;
  gapSort: 'priority' | 'kev' | 'groups' | 'name' = 'priority';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private gapService: GapAnalysisService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'gap-analysis';
        if (this.visible && this.allGroups.length === 0) {
          this.loadGroups();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Group loading ──────────────────────────────────────────────────────────

  private loadGroups(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.domain = domain;
      this.allGroups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
      this.cdr.markForCheck();
    });
  }

  get filteredGroups(): ThreatGroup[] {
    if (!this.actorSearch.trim()) return this.allGroups;
    const q = this.actorSearch.toLowerCase();
    return this.allGroups.filter(g =>
      g.name.toLowerCase().includes(q) ||
      g.attackId.toLowerCase().includes(q) ||
      g.aliases.some(a => a.toLowerCase().includes(q)),
    );
  }

  getGroupTechCount(groupId: string): number {
    if (!this.domain) return 0;
    return (this.domain.techniquesByGroup.get(groupId) ?? []).filter(t => !t.isSubtechnique).length;
  }

  // ─── Actor selection helpers ────────────────────────────────────────────────

  toggleActor(id: string): void {
    if (this.selectedActorIds.has(id)) {
      this.selectedActorIds.delete(id);
    } else {
      this.selectedActorIds.add(id);
    }
    this.selectedActorIds = new Set(this.selectedActorIds); // trigger change detection
  }

  selectTop10(): void {
    if (!this.domain) return;
    const sorted = [...this.allGroups]
      .map(g => ({ id: g.id, count: this.getGroupTechCount(g.id) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    this.selectedActorIds = new Set(sorted.map(s => s.id));
    this.cdr.markForCheck();
  }

  selectAptOnly(): void {
    this.selectedActorIds = new Set(
      this.allGroups
        .filter(g => g.name.startsWith('APT') || g.aliases.some(a => a.startsWith('APT')))
        .map(g => g.id),
    );
    this.cdr.markForCheck();
  }

  selectAllGroups(): void {
    this.selectedActorIds = new Set(this.allGroups.map(g => g.id));
    this.cdr.markForCheck();
  }

  clearSelection(): void {
    this.selectedActorIds = new Set();
    this.cdr.markForCheck();
  }

  onAnalyzeAllChange(): void {
    if (this.analyzeAll) {
      this.selectedActorIds = new Set();
    }
    this.cdr.markForCheck();
  }

  // ─── Report generation ──────────────────────────────────────────────────────

  generate(): void {
    if (!this.domain) return;
    const actorIds = this.analyzeAll ? [] : Array.from(this.selectedActorIds);
    this.result = this.gapService.generateReport(this.domain, actorIds);
    this.buildDetectionSources();
    this.gapLimit = 20;
    this.sortGaps();
    this.cdr.markForCheck();
  }

  private buildDetectionSources(): void {
    if (!this.result) return;
    const dc = this.result.detectionCoverage;
    const sources: Array<{ key: string; label: string; data: { covered: number; total: number } }> = [
      { key: 'sigma',   label: 'Sigma',   data: dc.sigma },
      { key: 'elastic', label: 'Elastic', data: dc.elastic },
      { key: 'splunk',  label: 'Splunk',  data: dc.splunk },
      { key: 'm365',    label: 'M365',    data: dc.m365 },
      { key: 'atomic',  label: 'Atomic',  data: dc.atomic },
      { key: 'car',     label: 'CAR',     data: dc.car },
    ];
    this.detectionSources = sources.map(s => ({
      key: s.key,
      label: s.label,
      covered: s.data.covered,
      total: s.data.total,
      pct: s.data.total > 0 ? Math.round((s.data.covered / s.data.total) * 100) : 0,
    }));
  }

  sortGaps(): void {
    if (!this.result) return;
    const gaps = [...this.result.prioritizedGaps];
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    switch (this.gapSort) {
      case 'priority':
        gaps.sort((a, b) => (order[a.priority] ?? 4) - (order[b.priority] ?? 4));
        break;
      case 'kev':
        gaps.sort((a, b) => b.kevCount - a.kevCount || (order[a.priority] ?? 4) - (order[b.priority] ?? 4));
        break;
      case 'groups':
        gaps.sort((a, b) => b.usedByGroups.length - a.usedByGroups.length || (order[a.priority] ?? 4) - (order[b.priority] ?? 4));
        break;
      case 'name':
        gaps.sort((a, b) => a.technique.attackId.localeCompare(b.technique.attackId));
        break;
    }

    this.displayedGaps = gaps.slice(0, this.gapLimit);
    this.cdr.markForCheck();
  }

  showMoreGaps(): void {
    this.gapLimit += 20;
    this.sortGaps();
  }

  // ─── Actions ────────────────────────────────────────────────────────────────

  openTechnique(attackId: string): void {
    if (!this.domain) return;
    const tech = this.domain.techniques.find(t => t.attackId === attackId);
    if (tech) {
      this.filterService.selectTechnique(tech);
    }
  }

  exportCsv(): void {
    if (this.result) this.gapService.exportCsv(this.result);
  }

  exportPdf(): void {
    if (this.result) this.gapService.exportPdf(this.result);
  }

  copyToClipboard(): void {
    if (!this.result) return;
    const lines: string[] = [];
    lines.push(`Detection Gap Analysis Report`);
    lines.push(`Domain: ${this.result.domain}`);
    lines.push(`Generated: ${this.result.generatedAt}`);
    lines.push(`Actors: ${this.result.selectedActors.join(', ') || 'All techniques'}`);
    lines.push('');
    lines.push(`Summary: ${this.result.summary.totalTechniques} total, ${this.result.summary.mitigated} mitigated, ${this.result.summary.detected} detected, ${this.result.summary.fullyBlind} fully blind`);
    lines.push(`RAG: ${this.result.summary.ragStatus.toUpperCase()}`);
    lines.push('');
    lines.push('--- Prioritized Gaps ---');
    for (const gap of this.result.prioritizedGaps.slice(0, 20)) {
      lines.push(`[${gap.priority.toUpperCase()}] ${gap.technique.attackId} ${gap.technique.name} — ${gap.recommendation}`);
    }
    navigator.clipboard.writeText(lines.join('\n')).catch(() => { /* noop */ });
  }

  resetReport(): void {
    this.result = null;
    this.gapLimit = 20;
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}

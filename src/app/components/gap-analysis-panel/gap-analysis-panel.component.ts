// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
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
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { GapAnalysisService, GapAnalysisResult, PrioritizedGap } from '../../services/gap-analysis.service';
import { LibraryService } from '../../services/library.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';
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
  imports: [CommonModule, FormsModule, ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './gap-analysis-panel.component.html',
  styleUrl: './gap-analysis-panel.component.scss',
})
export class GapAnalysisPanelComponent implements OnInit, OnDestroy {
  result: GapAnalysisResult | null = null;
  generating = false;
  /** True while Generate waits for the CTID mapping the KEV counts read. */
  waitingForCves = false;
  /** How the CTID mapping had settled when the shown report was generated. */
  private resultOutcome: 'loaded' | 'failed' | null = null;
  private settleSub?: Subscription;

  // Step 1: the shared threat-profile picker (profile mode) scopes the analysis.
  private domain: Domain | null = null;

  // Step 2 state
  detectionSources: CoverageSourceRow[] = [];
  displayedGaps: PrioritizedGap[] = [];
  gapLimit = 20;
  gapSort: 'priority' | 'kev' | 'groups' | 'name' = 'priority';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private panelNav: PanelNavService,
    private dataService: DataService,
    private gapService: GapAnalysisService,
    private cdr: ChangeDetectorRef,
    private libraryService: LibraryService,
    private threatProfile: ThreatProfileService,
    private attackCveService: AttackCveService,
  ) {}

  /** Count of starred Library tools relevant to a technique's tactic. */
  libraryCountFor(gap: PrioritizedGap): number {
    // gap.tactic is the human-readable tactic name; map to slug
    const slug = this.tacticToSlug(gap.tactic);
    return this.libraryService.getAssetsForTactic(slug).length;
  }

  /** Open Library Index filtered to the gap's tactic. */
  openLibraryForGap(gap: PrioritizedGap): void {
    // The library workbench reads the persisted tactic filter via its own
    // localStorage signal.
    this.panelNav.open('library');
  }

  /** Open the Detection Validation Workbench for the gap's technique. */
  openValidationForGap(_gap: PrioritizedGap): void {
    this.panelNav.open('validation');
  }

  private tacticToSlug(tactic: string): string {
    return tactic.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  }

  ngOnInit(): void {
    // The report counts KEV CVEs from the CTID ATT&CK-to-CVE mapping, which loads on
    // demand: opening this view asks for it (only the first ask fetches).
    this.attackCveService.loadOnDemand();
    this.loadGroups();
    // A report generated while the mapping had failed is generated again when a retry
    // brings the mapping in, so its KEV counts are never left at 0.
    this.subs.add(this.attackCveService.loaded$.subscribe(loaded => {
      if (loaded && this.result && this.resultOutcome === 'failed' && !this.generating) this.generate();
    }));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Domain loading ───────────────────────────────────────────────────────────

  private loadGroups(): void {
    // The shared picker loads and lists the groups itself; the panel only needs the
    // domain for generate(). The scope is the ThreatProfileService profile the picker edits.
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.domain = domain;
      this.cdr.markForCheck();
    });
  }

  // ─── Report generation ──────────────────────────────────────────────────────

  generate(): void {
    if (!this.domain) return;
    this.generating = true;
    this.waitingForCves = true;
    this.cdr.markForCheck();
    // The KEV counts read the CTID ATT&CK-to-CVE mapping, which loads on demand: wait
    // until it has settled (at once when it is already in), so the report is never
    // generated from an index that has not arrived.
    this.settleSub?.unsubscribe();
    this.settleSub = this.attackCveService.settled$().subscribe(outcome => {
      this.waitingForCves = false;
      this.cdr.markForCheck();
      this.runReport(outcome);
    });
    this.subs.add(this.settleSub);
  }

  private runReport(outcome: 'loaded' | 'failed'): void {
    // Defer to next tick so the spinner renders before the sync computation blocks the thread
    setTimeout(() => {
      if (!this.domain) { this.generating = false; this.cdr.markForCheck(); return; }
      this.result = this.gapService.generateReport(this.domain, this.threatProfile.current);
      this.resultOutcome = outcome;
      this.generating = false;
      this.buildDetectionSources();
      this.gapLimit = 20;
      this.sortGaps();
      this.cdr.markForCheck();
    }, 0);
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

  exportXlsx(): void {
    if (this.result) this.gapService.exportXlsx(this.result);
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
    if (!confirm('This will discard your current gap analysis results. Continue?')) return;
    this.result = null;
    this.gapLimit = 20;
    this.cdr.markForCheck();
  }

}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, AfterViewInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, HostListener, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CommonModule, AsyncPipe } from '@angular/common';
import { DataService, AttackDomain } from './services/data.service';
import { Domain } from './models/domain';
import { FilterService, ActivePanel } from './services/filter.service';
import { ViewModeService, ViewMode } from './services/view-mode.service';
import { LibraryWorkbenchComponent } from './components/library-workbench/library-workbench.component';
import { EmulationPlanPanelComponent } from './components/emulation-plan-panel/emulation-plan-panel.component';
import { ValidationPanelComponent } from './components/validation-panel/validation-panel.component';
import { Observable } from 'rxjs';
import { MatrixComponent } from './components/matrix/matrix.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { ToolbarComponent } from './components/toolbar/toolbar.component';
import { LegendComponent } from './components/legend/legend.component';
import { StatsBarComponent } from './components/stats-bar/stats-bar.component';
import { FilterChipsComponent } from './components/filter-chips/filter-chips.component';
import { GapViewComponent } from './components/gap-view/gap-view.component';
import { ThreatPanelComponent } from './components/threat-panel/threat-panel.component';
import { PriorityPanelComponent } from './components/priority-panel/priority-panel.component';
import { WhatifPanelComponent } from './components/whatif-panel/whatif-panel.component';
import { ReportPanelComponent } from './components/report-panel/report-panel.component';
import { ImplementationService } from './services/implementation.service';
import { DocumentationService } from './services/documentation.service';
import { KeyboardHelpComponent } from './components/keyboard-help/keyboard-help.component';
import { ControlsPanelComponent } from './components/controls-panel/controls-panel.component';
import { SoftwarePanelComponent } from './components/software-panel/software-panel.component';
import { ComparisonPanelComponent } from './components/comparison-panel/comparison-panel.component';
import { LayersPanelComponent } from './components/layers-panel/layers-panel.component';
import { CvePanelComponent } from './components/cve-panel/cve-panel.component';
import { AnalyticsPanelComponent } from './components/analytics-panel/analytics-panel.component';
import { NavRailComponent } from './components/nav-rail/nav-rail.component';
import { SigmaExportComponent } from './components/sigma-export/sigma-export.component';
import { SiemExportComponent } from './components/siem-export/siem-export.component';
import { PurpleTeamPanelComponent } from './components/purple-team-panel/purple-team-panel.component';
import { YaraExportComponent } from './components/yara-export/yara-export.component';
import { RoadmapPanelComponent } from './components/roadmap-panel/roadmap-panel.component';
import { ActorProfilePanelComponent } from './components/actor-profile-panel/actor-profile-panel.component';
import { DetectionPanelComponent } from './components/detection-panel/detection-panel.component';
import { DatasourcePanelComponent } from './components/datasource-panel/datasource-panel.component';
import { CompliancePanelComponent } from './components/compliance-panel/compliance-panel.component';
import { ActorComparePanelComponent } from './components/actor-compare-panel/actor-compare-panel.component';
import { TimelinePanelComponent } from './components/timeline-panel/timeline-panel.component';
import { SettingsPanelComponent } from './components/settings-panel/settings-panel.component';
import { CustomMitPanelComponent } from './components/custom-mit-panel/custom-mit-panel.component';
import { KillchainPanelComponent } from './components/killchain-panel/killchain-panel.component';
import { RiskMatrixPanelComponent } from './components/risk-matrix-panel/risk-matrix-panel.component';
import { ScenarioPanelComponent } from './components/scenario-panel/scenario-panel.component';
import { TargetPanelComponent } from './components/target-panel/target-panel.component';
import { QuickFiltersComponent } from './components/quick-filters/quick-filters.component';
import { DashboardPanelComponent } from './components/dashboard-panel/dashboard-panel.component';
import { WatchlistPanelComponent } from './components/watchlist-panel/watchlist-panel.component';
import { ChangelogPanelComponent } from './components/changelog-panel/changelog-panel.component';
import { TagsPanelComponent } from './components/tags-panel/tags-panel.component';
import { CampaignTimelinePanelComponent } from './components/campaign-timeline-panel/campaign-timeline-panel.component';
import { TechniqueGraphPanelComponent } from './components/technique-graph-panel/technique-graph-panel.component';
import { CoverageDiffPanelComponent } from './components/coverage-diff-panel/coverage-diff-panel.component';
import { ThreatIntelligencePanelComponent } from './components/threat-intelligence-panel/threat-intelligence-panel.component';
import { CollectionPanelComponent } from './components/collection-panel/collection-panel.component';
import { AssessmentWizardComponent } from './components/assessment-wizard/assessment-wizard.component';
import { DataHealthComponent } from './components/data-health/data-health.component';
import { GapAnalysisPanelComponent } from './components/gap-analysis-panel/gap-analysis-panel.component';
import { AssetPanelComponent } from './components/asset-panel/asset-panel.component';
import { IRPlaybookPanelComponent } from './components/ir-playbook-panel/ir-playbook-panel.component';
import { OnboardingComponent } from './components/onboarding/onboarding.component';
import { MatrixExportService } from './services/matrix-export.service';
import { HtmlReportService } from './services/html-report.service';
import { PdfReportService } from './services/pdf-report.service';
import { UrlStateService } from './services/url-state.service';
import { XlsxExportService } from './services/xlsx-export.service';
import { CustomMitigationService } from './services/custom-mitigation.service';
import { TimelineService } from './services/timeline.service';
import { TacticSummaryComponent, TacticSummaryData } from './components/tactic-summary/tactic-summary.component';
import { Tactic } from './models/tactic';
import { Technique } from './models/technique';
import { BrowserFileService } from './services/browser-file.service';
import { NavigatorLayerService } from './services/navigator-layer.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, AsyncPipe, MatrixComponent, SidebarComponent, ToolbarComponent, LegendComponent, StatsBarComponent, FilterChipsComponent, GapViewComponent, ThreatPanelComponent, PriorityPanelComponent, WhatifPanelComponent, ReportPanelComponent, KeyboardHelpComponent, ControlsPanelComponent, SoftwarePanelComponent, ComparisonPanelComponent, LayersPanelComponent, CvePanelComponent, AnalyticsPanelComponent, NavRailComponent, SigmaExportComponent, SiemExportComponent, PurpleTeamPanelComponent, YaraExportComponent, RoadmapPanelComponent, ActorProfilePanelComponent, DetectionPanelComponent, CompliancePanelComponent, ActorComparePanelComponent, TimelinePanelComponent, TacticSummaryComponent, SettingsPanelComponent, CustomMitPanelComponent, KillchainPanelComponent, RiskMatrixPanelComponent, ScenarioPanelComponent, QuickFiltersComponent, DashboardPanelComponent, DatasourcePanelComponent, WatchlistPanelComponent, ChangelogPanelComponent, TagsPanelComponent, TargetPanelComponent, CampaignTimelinePanelComponent, TechniqueGraphPanelComponent, CoverageDiffPanelComponent, ThreatIntelligencePanelComponent, CollectionPanelComponent, AssessmentWizardComponent, DataHealthComponent, GapAnalysisPanelComponent, AssetPanelComponent, IRPlaybookPanelComponent, OnboardingComponent, LibraryWorkbenchComponent, EmulationPlanPanelComponent, ValidationPanelComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit, AfterViewInit {
  private readonly destroyRef = inject(DestroyRef);
  @ViewChild(MatrixComponent) matrixRef?: MatrixComponent;
  @ViewChild(GapViewComponent) gapViewRef?: GapViewComponent;
  @ViewChild(TacticSummaryComponent) tacticSummary?: TacticSummaryComponent;
  @ViewChild(KeyboardHelpComponent) keyboardHelp?: KeyboardHelpComponent;
  @ViewChild(CollectionPanelComponent) collectionPanel?: CollectionPanelComponent;

  domain: Domain | null = null;
  loading = true;
  error: string | null = null;
  isLightMode = false;
  activePanel$!: Observable<ActivePanel>;
  viewMode: ViewMode = 'workbench';
  private viewModeService = inject(ViewModeService);
  onViewModeChange(mode: ViewMode): void {
    this.viewModeService.set(mode);
    this.viewMode = mode;
  }
  showToast = false;
  toastMessage = '';
  currentDomain: AttackDomain = 'enterprise';

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private implService: ImplementationService,
    private docService: DocumentationService,
    private matrixExport: MatrixExportService,
    private htmlReportService: HtmlReportService,
    private pdfReportService: PdfReportService,
    private cdr: ChangeDetectorRef,
    private urlStateService: UrlStateService,
    private xlsxExport: XlsxExportService,
    private customMitService: CustomMitigationService,
    private timelineService: TimelineService,
    private browserFileService: BrowserFileService,
    private navigatorLayerService: NavigatorLayerService,
  ) {}

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.domain = d; this.cdr.markForCheck(); });
    this.dataService.loading$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((l) => { this.loading = l; this.cdr.markForCheck(); });
    this.dataService.error$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((e) => { this.error = e; this.cdr.markForCheck(); });
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.currentDomain = d; this.cdr.markForCheck(); });
    this.dataService.loadDomain();
    this.activePanel$ = this.filterService.activePanel$;
    this.viewModeService.viewMode$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(m => { this.viewMode = m; this.cdr.markForCheck(); });
    this.urlStateService.restoreFromUrl();
    if (localStorage.getItem('mitre-nav-theme') === 'light') {
      this.isLightMode = true;
      document.body.classList.add('light-mode');
    }
  }

  ngAfterViewInit(): void {
    // Check URL for shared collection import after view is ready
    setTimeout(() => this.collectionPanel?.checkUrlImport(), 500);
  }

  onDomainChange(domain: AttackDomain): void {
    this.filterService.clearAll();
    this.dataService.switchDomain(domain);
  }

  copyShareLink(): void {
    const url = this.urlStateService.getShareUrl();
    navigator.clipboard.writeText(url)
      .then(() => this.showToastMessage('Link copied to clipboard!'))
      .catch(() => this.showToastMessage('Unable to copy the share link from this browser'));
  }

  showCopiedToast(): void {
    this.showToastMessage('Link copied to clipboard!');
  }

  private showToastMessage(message: string): void {
    this.showToast = true;
    this.toastMessage = message;
    this.cdr.markForCheck();
    setTimeout(() => { this.showToast = false; this.cdr.markForCheck(); }, 2500);
  }

  @HostListener('document:click')
  closePopup(): void {
    this.tacticSummary?.hide();
  }

  @HostListener('document:keydown', ['$event'])
  onGlobalKeydown(event: KeyboardEvent): void {
    // Skip if typing in an input field
    const target = event.target as HTMLElement;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return;
    if (target.isContentEditable) return;

    if (event.key === 'Escape') {
      const activePanel = this.filterService.getActivePanel();
      if (activePanel) {
        this.filterService.setActivePanel(null);
        event.preventDefault();
        return;
      }
      this.filterService.selectTechnique(null);
      event.preventDefault();
      return;
    }

    if (event.ctrlKey || event.metaKey) {
      switch (event.key) {
        case 'f':
          event.preventDefault();
          this.focusTechniqueSearch();
          break;
        case 'k':
          event.preventDefault();
          this.filterService.setActivePanel('search');
          break;
        case 'e':
          event.preventDefault();
          this.matrixRef?.expandAll();
          break;
      }
      return;
    }

    // Single-key shortcuts (no modifier)
    switch (event.key) {
      case 'd':
        event.preventDefault();
        this.filterService.togglePanel('dashboard');
        break;
      case 't':
        event.preventDefault();
        this.filterService.togglePanel('timeline');
        break;
      case 'w':
        event.preventDefault();
        this.filterService.togglePanel('watchlist');
        break;
      case 'r':
        event.preventDefault();
        this.filterService.togglePanel('risk-matrix');
        break;
      case 'c':
        event.preventDefault();
        this.filterService.clearAll();
        break;
    }
  }

  onTacticClick(event: { tactic: Tactic; techniques: Technique[]; event: MouseEvent }): void {
    if (!this.domain) return;
    const parentTechniques = event.techniques.filter((t) => !t.isSubtechnique);
    const data: TacticSummaryData = {
      tactic: event.tactic,
      techniques: event.techniques,
      parentTechniques,
      domain: this.domain,
    };
    this.tacticSummary?.show(data, event.event);
  }

  onNavPanelToggle(panelId: string): void {
    this.filterService.togglePanel(panelId as Exclude<ActivePanel, null>);
  }

  get selectedTechniqueCount(): number {
    return this.matrixRef?.selectedTechIds?.size ?? 0;
  }

  bulkAddToWatchlist(): void {
    this.matrixRef?.bulkAddToWatchlist();
    this.cdr.markForCheck();
  }

  bulkSetStatus(status: import('./services/implementation.service').ImplStatus): void {
    this.matrixRef?.bulkSetStatus(status);
    this.cdr.markForCheck();
  }

  bulkAddTag(): void {
    const tag = prompt('Enter tag name to apply to all selected techniques:');
    if (tag && tag.trim()) {
      this.matrixRef?.bulkAddTag(tag.trim());
      this.cdr.markForCheck();
    }
  }

  clearMultiSelect(): void {
    this.matrixRef?.clearSelection();
    this.cdr.markForCheck();
  }

  toggleDarkMode(): void {
    this.isLightMode = !this.isLightMode;
    if (this.isLightMode) {
      document.body.classList.add('light-mode');
    } else {
      document.body.classList.remove('light-mode');
    }
    localStorage.setItem('mitre-nav-theme', this.isLightMode ? 'light' : 'dark');
    this.cdr.markForCheck();
  }

  scrollToTactic(shortname: string): void {
    const headers = document.querySelectorAll('.tactic-header');
    for (const h of Array.from(headers)) {
      if (h.textContent?.toLowerCase().includes(shortname.toLowerCase().replace(/-/g, ' '))) {
        h.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'start' });
        break;
      }
    }
  }

  focusTechniqueSearch(): void {
    const input = document.querySelector<HTMLInputElement>('.technique-search .search-input');
    if (input) {
      input.focus();
      input.select();
    }
  }

  exportCsv(): void {
    if (!this.domain) return;
    const rows: string[] = ['Technique ID,Technique Name,Tactics,Platforms,Mitigation Count,Mitigation IDs,Mitigation Names'];
    for (const tech of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const rels = this.domain.mitigationsByTechnique.get(tech.id) ?? [];
      rows.push([
        tech.attackId,
        `"${tech.name.replace(/"/g, '""')}"`,
        `"${tech.tacticShortnames.join('; ')}"`,
        `"${tech.platforms.join('; ')}"`,
        rels.length,
        `"${rels.map((r) => r.mitigation.attackId).join('; ')}"`,
        `"${rels.map((r) => r.mitigation.name.replace(/"/g, '""')).join('; ')}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'attack-mitigation-coverage.csv');
  }

  exportTacticCsv(): void {
    if (!this.domain) return;
    const rows: string[] = ['Tactic,Technique Count,Covered Count,Coverage %,Uncovered Technique IDs'];
    for (const col of this.domain.tacticColumns) {
      const parents = col.techniques.filter((t) => !t.isSubtechnique);
      const covered = parents.filter((t) => t.mitigationCount > 0);
      const uncoveredIds = parents.filter((t) => t.mitigationCount === 0).map((t) => t.attackId).join('; ');
      const pct = parents.length ? Math.round((covered.length / parents.length) * 100) : 0;
      rows.push([
        `"${col.tactic.name}"`,
        parents.length,
        covered.length,
        `${pct}%`,
        `"${uncoveredIds}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'attack-tactic-coverage.csv');
  }

  exportImplPlanCsv(): void {
    if (!this.domain) return;
    const statusMap = this.implService.getStatusMap();
    const rows: string[] = [
      'Mitigation ID,Mitigation Name,Status,Owner,Target Date,Security Controls,Evidence URL,Covered Techniques,Unique Coverage,Notes'
    ];
    const techMitCount = new Map<string, number>();
    for (const [techId, rels] of this.domain.mitigationsByTechnique.entries()) {
      techMitCount.set(techId, rels.length);
    }
    for (const mit of this.domain.mitigations) {
      const techniques = this.domain.techniquesByMitigation.get(mit.id) ?? [];
      const unique = techniques.filter((t) => (techMitCount.get(t.id) ?? 0) === 1).length;
      const doc = this.docService.getMitDoc(mit.id);
      const status = statusMap.get(mit.id) ?? 'not-tracked';
      rows.push([
        mit.attackId,
        `"${mit.name.replace(/"/g, '""')}"`,
        status,
        `"${doc.owner.replace(/"/g, '""')}"`,
        doc.dueDate,
        `"${doc.controlRefs.replace(/"/g, '""')}"`,
        `"${doc.evidenceUrl.replace(/"/g, '""')}"`,
        techniques.length,
        unique,
        `"${doc.notes.replace(/"/g, '""')}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'mitigation-implementation-plan.csv');
  }

  async exportXlsxWorkbook(): Promise<void> {
    if (!this.domain) return;
    await this.xlsxExport.exportWorkbook(
      this.domain,
      this.implService.getStatusMap(),
      this.customMitService.all,
      this.timelineService.getAll(),
    );
  }

  exportHtmlCoverageReport(): void {
    if (!this.domain) return;
    this.htmlReportService.generateAndOpen(this.domain, this.implService.getStatusMap());
  }

  exportPdf(): void {
    if (!this.domain) return;
    this.pdfReportService.generateReport(this.domain, this.implService.getStatusMap());
  }

  exportMatrixPng(): void {
    if (!this.domain) return;
    const heatmapMode = (this.filterService.getStateSnapshot().heatmapMode as import('./services/filter.service').HeatmapMode) ?? 'coverage';
    this.matrixExport.exportPng(this.domain, this.implService.getStatusMap(), heatmapMode);
  }

  exportStateJson(): void {
    const state = {
      implementation: JSON.parse(this.implService.exportJson()),
      documentation: JSON.parse(this.docService.exportJson()),
    };
    this.browserFileService.downloadJson(state, 'mitigation-navigator-state.json');
  }

  async importStateJson(): Promise<void> {
    const json = await this.browserFileService.pickTextFile('.json');
    if (!json) return;
    try {
      const state = JSON.parse(json) as { implementation?: unknown; documentation?: unknown };
      if (state.implementation) this.implService.importJson(JSON.stringify(state.implementation));
      if (state.documentation) this.docService.importJson(JSON.stringify(state.documentation));
    } catch {
      alert('Invalid state file.');
    }
  }

  async importNavigatorLayer(): Promise<void> {
    if (!this.domain) return;
    const json = await this.browserFileService.pickTextFile('.json');
    if (!json) return;
    try {
      const result = await this.navigatorLayerService.importLayer(json, this.domain, this.implService);
      alert(`Layer "${result.layerName}" imported - ${result.appliedCount} technique annotations applied.`);
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to import Navigator layer.');
    }
  }


  exportNavigatorLayer(): void {
    if (!this.domain) return;
    this.navigatorLayerService.downloadLayer(this.domain, this.currentDomain, this.implService.getStatusMap(), this.browserFileService);
  }


  openInNavigator(): void {
    this.exportNavigatorLayer();
    setTimeout(() => window.open('https://mitre-attack.github.io/attack-navigator/', '_blank'), 300);
  }

  exportFullReport(): void {
    if (!this.domain) return;
    const statusMap = this.implService.getStatusMap();
    const date = new Date().toISOString().slice(0, 10);
    const rows: string[] = [
      'Technique ID,Technique Name,Tactics,Platforms,Mitigation ID,Mitigation Name,Impl Status,Owner,Due Date,Control Refs,Evidence URL,Impl Notes,Analyst Note,Total Mitigation Count,Threat Group Count'
    ];
    for (const tech of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const rels = this.domain.mitigationsByTechnique.get(tech.id) ?? [];
      const analystNote = this.docService.getTechNote(tech.id);
      const threatGroupCount = (this.domain.groupsByTechnique.get(tech.id) ?? []).length;
      const totalMitCount = rels.length;
      const techId = tech.attackId;
      const techName = `"${tech.name.replace(/"/g, '""')}"`;
      const tactics = `"${tech.tacticShortnames.join('|')}"`;
      const platforms = `"${tech.platforms.join('|')}"`;
      const analystNoteCell = `"${analystNote.replace(/"/g, '""')}"`;
      if (rels.length === 0) {
        rows.push([
          techId, techName, tactics, platforms,
          '', '', '', '', '', '', '', '',
          analystNoteCell, totalMitCount, threatGroupCount,
        ].join(','));
      } else {
        for (const rel of rels) {
          const doc = this.docService.getMitDoc(rel.mitigation.id);
          const status = statusMap.get(rel.mitigation.id) ?? 'not-tracked';
          rows.push([
            techId, techName, tactics, platforms,
            rel.mitigation.attackId,
            `"${rel.mitigation.name.replace(/"/g, '""')}"`,
            status,
            `"${doc.owner.replace(/"/g, '""')}"`,
            doc.dueDate,
            `"${doc.controlRefs.replace(/"/g, '""')}"`,
            `"${doc.evidenceUrl.replace(/"/g, '""')}"`,
            `"${doc.notes.replace(/"/g, '""')}"`,
            analystNoteCell, totalMitCount, threatGroupCount,
          ].join(','));
        }
      }
    }
    this.downloadCsv(rows.join('\n'), `mitre-full-report-${date}.csv`);
  }

  private downloadCsv(content: string, filename: string): void {
    this.browserFileService.downloadText(content, filename, 'text/csv');
  }
}

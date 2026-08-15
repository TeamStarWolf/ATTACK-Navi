// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, AfterViewInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, HostListener, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CommonModule, AsyncPipe } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { DataService, AttackDomain } from './services/data.service';
import { Domain } from './models/domain';
import { FilterService, ActivePanel } from './services/filter.service';
import { ViewModeService, ViewMode } from './services/view-mode.service';
import { LibraryWorkbenchComponent } from './components/library-workbench/library-workbench.component';
import { EmulationPlanPanelComponent } from './components/emulation-plan-panel/emulation-plan-panel.component';
import { ValidationPanelComponent } from './components/validation-panel/validation-panel.component';
import { Observable } from 'rxjs';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { ToolbarComponent } from './components/toolbar/toolbar.component';
import { GapViewComponent } from './components/gap-view/gap-view.component';
import { ThreatPanelComponent } from './components/threat-panel/threat-panel.component';
import { PriorityPanelComponent } from './components/priority-panel/priority-panel.component';
import { WhatifPanelComponent } from './components/whatif-panel/whatif-panel.component';
import { ReportPanelComponent } from './components/report-panel/report-panel.component';
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
import { GapAnalysisPanelComponent } from './components/gap-analysis-panel/gap-analysis-panel.component';
import { AssetPanelComponent } from './components/asset-panel/asset-panel.component';
import { IRPlaybookPanelComponent } from './components/ir-playbook-panel/ir-playbook-panel.component';
import { OnboardingComponent } from './components/onboarding/onboarding.component';
import { UrlStateService } from './services/url-state.service';
import { PanelNavService } from './services/panel-nav.service';
import { MatrixControlService } from './services/matrix-control.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, AsyncPipe, RouterOutlet, SidebarComponent, ToolbarComponent, GapViewComponent, ThreatPanelComponent, PriorityPanelComponent, WhatifPanelComponent, ReportPanelComponent, KeyboardHelpComponent, ControlsPanelComponent, SoftwarePanelComponent, ComparisonPanelComponent, LayersPanelComponent, CvePanelComponent, AnalyticsPanelComponent, NavRailComponent, SigmaExportComponent, SiemExportComponent, PurpleTeamPanelComponent, YaraExportComponent, RoadmapPanelComponent, ActorProfilePanelComponent, DetectionPanelComponent, CompliancePanelComponent, ActorComparePanelComponent, TimelinePanelComponent, SettingsPanelComponent, CustomMitPanelComponent, KillchainPanelComponent, RiskMatrixPanelComponent, ScenarioPanelComponent, DashboardPanelComponent, DatasourcePanelComponent, WatchlistPanelComponent, ChangelogPanelComponent, TagsPanelComponent, TargetPanelComponent, CampaignTimelinePanelComponent, TechniqueGraphPanelComponent, CoverageDiffPanelComponent, ThreatIntelligencePanelComponent, CollectionPanelComponent, AssessmentWizardComponent, GapAnalysisPanelComponent, AssetPanelComponent, IRPlaybookPanelComponent, OnboardingComponent, LibraryWorkbenchComponent, EmulationPlanPanelComponent, ValidationPanelComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit, AfterViewInit {
  private readonly destroyRef = inject(DestroyRef);
  @ViewChild(GapViewComponent) gapViewRef?: GapViewComponent;
  @ViewChild(KeyboardHelpComponent) keyboardHelp?: KeyboardHelpComponent;
  @ViewChild(CollectionPanelComponent) collectionPanel?: CollectionPanelComponent;

  domain: Domain | null = null;
  isLightMode = false;
  activePanel$!: Observable<ActivePanel>;
  viewMode: ViewMode = 'workbench';
  private viewModeService = inject(ViewModeService);
  private panelNav = inject(PanelNavService);
  private matrixControl = inject(MatrixControlService);
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
    private cdr: ChangeDetectorRef,
    private urlStateService: UrlStateService,
  ) {}

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.domain = d; this.cdr.markForCheck(); });
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.currentDomain = d; this.cdr.markForCheck(); });
    this.dataService.loadDomain();
    this.activePanel$ = this.filterService.activePanel$;
    this.viewModeService.viewMode$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(m => { this.viewMode = m; this.cdr.markForCheck(); });
    this.urlStateService.init();
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
          this.matrixControl.expandAll();
          break;
      }
      return;
    }

    // Single-key shortcuts (no modifier)
    switch (event.key) {
      case 'd':
        event.preventDefault();
        this.panelNav.toggle('dashboard');
        break;
      case 't':
        event.preventDefault();
        this.panelNav.toggle('timeline');
        break;
      case 'w':
        event.preventDefault();
        this.panelNav.toggle('watchlist');
        break;
      case 'r':
        event.preventDefault();
        this.panelNav.toggle('risk-matrix');
        break;
      case 'c':
        event.preventDefault();
        this.filterService.clearAll();
        break;
      case 'm':
        event.preventDefault();
        this.panelNav.open('matrix');
        break;
    }
  }

  onNavPanelToggle(panelId: string): void {
    this.panelNav.toggle(panelId);
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

  focusTechniqueSearch(): void {
    const input = document.querySelector<HTMLInputElement>('.technique-search .search-input');
    if (input) {
      input.focus();
      input.select();
    }
  }
}

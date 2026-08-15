// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  OnDestroy,
  OnInit,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Mitigation } from '../../models/mitigation';
import { Technique } from '../../models/technique';
import { FilterService, SearchScope, SortMode } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { HEATMAP_MODES, HEATMAP_GROUPS, heatmapShortLabel } from '../../models/heatmap-modes';
import { PLATFORM_PILLS } from '../../components/toolbar/toolbar.component';

/**
 * Matrix-scoped controls row: technique + mitigation search, platform /
 * data-source / status filters, the heatmap dropdown, matrix view actions,
 * and clear. Lives inside the matrix page — other workspaces don't carry
 * this chrome (it used to crowd the global toolbar).
 */
@Component({
  selector: 'app-matrix-controls',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './matrix-controls.component.html',
  styleUrl: './matrix-controls.component.scss',
})
export class MatrixControlsComponent implements OnInit, OnDestroy {
  readonly PLATFORM_PILLS = PLATFORM_PILLS;
  readonly heatmapModes = HEATMAP_MODES;
  readonly heatmapGroups = HEATMAP_GROUPS;

  techniques: Technique[] = [];
  mitigations: Mitigation[] = [];

  // Technique search
  techniqueSearchText = '';
  filteredTechniques: Technique[] = [];
  showTechniqueDropdown = false;
  cveSearchHint: { cveId: string; techniqueCount: number } | null = null;
  searchScope: SearchScope = 'name';
  searchFilterMode = false;

  // Mitigation search
  mitigationSearchText = '';
  filteredMitigations: Mitigation[] = [];
  showDropdown = false;
  activeMitigations: Mitigation[] = [];

  // Filters
  activePlatforms: Set<string> = new Set();
  showPlatformRow = false;
  selectedDataSource = '';
  dataSourceNames: string[] = [];
  implStatusFilter = '';
  readonly implStatusOptions = [
    { value: 'implemented', label: '✅ Implemented' },
    { value: 'in-progress', label: '🔄 In Progress' },
    { value: 'planned', label: '📋 Planned' },
    { value: 'not-started', label: '❌ Not Started' },
  ];

  // View menu
  showViewMenu = false;
  heatmapMode: import('../../services/filter.service').HeatmapMode = 'coverage';
  sortMode: SortMode = 'alpha';
  dimUncovered = false;
  multiSelectMode = false;
  activeThreatGroupCount = 0;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private matrixControl: MatrixControlService,
    private attackCveService: AttackCveService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.dataService.domain$.subscribe((d) => {
      this.techniques = d?.techniques ?? [];
      this.mitigations = d?.mitigations ?? [];
      this.dataSourceNames = d ? [...new Set(d.dataComponents.map(dc => dc.dataSourceName))].filter(Boolean).sort() : [];
      this.cdr.markForCheck();
    }));
    this.subs.add(this.filterService.activeMitigationFilters$.subscribe((mits) => {
      this.activeMitigations = mits;
      this.cdr.markForCheck();
    }));
    this.subs.add(this.filterService.techniqueQuery$.subscribe((q) => {
      this.techniqueSearchText = q;
      if (!q) {
        this.filteredTechniques = [];
        this.showTechniqueDropdown = false;
      }
      this.cdr.markForCheck();
    }));
    this.subs.add(this.filterService.searchScope$.subscribe((s) => { this.searchScope = s; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.searchFilterMode$.subscribe((v) => { this.searchFilterMode = v; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.platformMulti$.subscribe((ps) => { this.activePlatforms = ps; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.activeDataSource$.subscribe((ds) => { this.selectedDataSource = ds ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.implStatusFilter$.subscribe((s) => { this.implStatusFilter = s ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.heatmapMode$.subscribe((m) => { this.heatmapMode = m; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.sortMode$.subscribe((m) => { this.sortMode = m; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.dimUncovered$.subscribe((v) => { this.dimUncovered = v; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.activeThreatGroupIds$.subscribe((ids) => { this.activeThreatGroupCount = ids.size; this.cdr.markForCheck(); }));
    this.subs.add(this.matrixControl.multiSelectMode$.subscribe((v) => { this.multiSelectMode = v; this.cdr.markForCheck(); }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  get heatmapShort(): string { return heatmapShortLabel(this.heatmapMode); }

  modesForGroup(group: string) {
    return this.heatmapModes.filter(m => m.group === group);
  }

  // ── Technique search ────────────────────────────────────────
  onTechniqueSearchInput(): void {
    const q = this.techniqueSearchText.trim();
    this.filterService.setTechniqueQuery(q);
    this.cveSearchHint = null;
    if (!q) {
      this.filteredTechniques = [];
      this.showTechniqueDropdown = false;
      return;
    }
    if (/^CVE-\d{4}-\d+$/i.test(q)) {
      const mapping = this.attackCveService.getMappingForCve(q.toUpperCase());
      if (mapping) {
        const attackIds = new Set([...mapping.primaryImpact, ...mapping.secondaryImpact, ...mapping.exploitationTechnique]);
        this.cveSearchHint = { cveId: q.toUpperCase(), techniqueCount: attackIds.size };
      } else {
        this.cveSearchHint = { cveId: q.toUpperCase(), techniqueCount: 0 };
      }
      this.filteredTechniques = [];
      this.showTechniqueDropdown = true;
      return;
    }
    const ql = q.toLowerCase();
    this.filteredTechniques = this.techniques
      .filter((t) => t.attackId.toLowerCase().includes(ql) || t.name.toLowerCase().includes(ql))
      .slice(0, 50);
    this.showTechniqueDropdown = this.filteredTechniques.length > 0;
  }

  selectTechnique(t: Technique): void {
    this.showTechniqueDropdown = false;
    this.cveSearchHint = null;
    this.filterService.setTechniqueQuery(t.attackId);
  }

  closeTechniqueDropdown(): void {
    setTimeout(() => { this.showTechniqueDropdown = false; this.cveSearchHint = null; this.cdr.markForCheck(); }, 150);
  }

  toggleSearchScope(): void { this.filterService.toggleSearchScope(); }
  toggleSearchFilterMode(): void { this.filterService.toggleSearchFilterMode(); }

  // ── Mitigation search ───────────────────────────────────────
  onMitigationSearchInput(): void {
    const q = this.mitigationSearchText.toLowerCase().trim();
    if (!q) {
      this.filteredMitigations = [];
      this.showDropdown = false;
      return;
    }
    const selectedIds = new Set(this.activeMitigations.map((m) => m.id));
    this.filteredMitigations = this.mitigations
      .filter((m) => !selectedIds.has(m.id) && (
        m.attackId.toLowerCase().includes(q) ||
        m.name.toLowerCase().includes(q) ||
        m.description.toLowerCase().includes(q)
      ))
      .slice(0, 50);
    this.showDropdown = this.filteredMitigations.length > 0;
  }

  selectMitigation(m: Mitigation): void {
    this.mitigationSearchText = '';
    this.filteredMitigations = [];
    this.showDropdown = false;
    this.filterService.addMitigationFilter(m);
  }

  closeDropdown(): void {
    setTimeout(() => { this.showDropdown = false; this.cdr.markForCheck(); }, 150);
  }

  // ── Filters ─────────────────────────────────────────────────
  togglePlatformRow(): void {
    this.showPlatformRow = !this.showPlatformRow;
    this.cdr.markForCheck();
  }

  togglePlatformPill(platform: string): void { this.filterService.togglePlatform(platform); }
  clearPlatformPills(): void { this.filterService.clearPlatformFilter(); }
  onDetectionSourceChange(): void { this.filterService.setDataSourceFilter(this.selectedDataSource || null); }
  onImplStatusFilterChange(): void { this.filterService.setImplStatusFilter(this.implStatusFilter || null); }

  get hasActiveFilters(): boolean {
    return this.activeMitigations.length > 0 || !!this.techniqueSearchText || !!this.selectedDataSource
      || this.dimUncovered || this.activeThreatGroupCount > 0 || !!this.implStatusFilter
      || this.activePlatforms.size > 0;
  }

  clearAll(): void {
    this.mitigationSearchText = '';
    this.filteredMitigations = [];
    this.filteredTechniques = [];
    this.showDropdown = false;
    this.showTechniqueDropdown = false;
    this.implStatusFilter = '';
    this.selectedDataSource = '';
    this.filterService.setImplStatusFilter(null);
    this.filterService.clearAll();
  }

  // ── View menu ───────────────────────────────────────────────
  toggleViewMenu(): void {
    this.showViewMenu = !this.showViewMenu;
    this.cdr.markForCheck();
  }

  setHeatmap(mode: import('../../services/filter.service').HeatmapMode): void {
    this.filterService.setHeatmapMode(mode);
    this.showViewMenu = false;
  }

  toggleSort(): void { this.filterService.setSortMode(this.sortMode === 'alpha' ? 'coverage' : 'alpha'); }
  toggleDimUncovered(): void { this.filterService.toggleDimUncovered(); }
  onExpandAll(): void { this.matrixControl.expandAll(); }
  onCollapseAll(): void { this.matrixControl.collapseAll(); }
  onToggleMultiSelect(): void { this.matrixControl.toggleMultiSelect(); }
  onGapView(): void { this.matrixControl.requestGapView(); }
}

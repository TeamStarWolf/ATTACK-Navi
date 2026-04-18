// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Mitigation } from '../../models/mitigation';
import { Technique } from '../../models/technique';
import { FilterService, SortMode, SearchScope } from '../../services/filter.service';
import { DataService, DataSourceMode, AttackDomain } from '../../services/data.service';
import { ViewMode } from '../../services/view-mode.service';
import { SavedViewsService, SavedView } from '../../services/saved-views.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { UniversalSearchComponent } from '../universal-search/universal-search.component';

export const PLATFORMS = [
  'Windows', 'Linux', 'macOS', 'Azure AD', 'Office 365',
  'Google Workspace', 'SaaS', 'IaaS', 'Network', 'Containers', 'PRE',
];

export const PLATFORM_PILLS = [
  { name: 'Windows', icon: '🪟' },
  { name: 'Linux', icon: '🐧' },
  { name: 'macOS', icon: '🍎' },
  { name: 'IaaS', icon: '☁️' },
  { name: 'Containers', icon: '🐳' },
  { name: 'Network', icon: '🌐' },
  { name: 'Office 365', icon: '📧' },
  { name: 'SaaS', icon: '💼' },
  { name: 'Azure AD', icon: '🔷' },
  { name: 'Google Workspace', icon: '📁' },
];

@Component({
  selector: 'app-toolbar',
  standalone: true,
  imports: [CommonModule, FormsModule, UniversalSearchComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './toolbar.component.html',
  styleUrl: './toolbar.component.scss',
})
export class ToolbarComponent implements OnInit, OnDestroy {
  @Input() mitigations: Mitigation[] = [];
  @Input() techniques: Technique[] = [];
  @Input() isLightMode = false;
  @Input() set currentDomain(value: AttackDomain) {
    this.attackDomain = value;
  }
  @Input() viewMode: ViewMode = 'workbench';
  @Output() viewModeChange = new EventEmitter<ViewMode>();
  brandMenuOpen = false;
  toggleBrandMenu(): void {
    this.brandMenuOpen = !this.brandMenuOpen;
    this.cdr.markForCheck();
  }
  selectViewMode(mode: ViewMode): void {
    this.brandMenuOpen = false;
    if (mode !== this.viewMode) {
      this.viewModeChange.emit(mode);
    }
    this.cdr.markForCheck();
  }
  closeBrandMenu(): void {
    if (this.brandMenuOpen) {
      this.brandMenuOpen = false;
      this.cdr.markForCheck();
    }
  }
  @Output() domainChange = new EventEmitter<AttackDomain>();
  @Output() expandAll = new EventEmitter<void>();
  @Output() collapseAll = new EventEmitter<void>();
  @Output() toggleMultiSelect = new EventEmitter<void>();
  @Input() multiSelectMode = false;
  @Output() exportCsv = new EventEmitter<void>();
  @Output() exportTacticCsv = new EventEmitter<void>();
  @Output() exportImplPlan = new EventEmitter<void>();
  @Output() exportState = new EventEmitter<void>();
  @Output() importState = new EventEmitter<void>();
  @Output() exportNavigatorLayer = new EventEmitter<void>();
  @Output() importNavigatorLayer = new EventEmitter<void>();
  @Output() openNavigator = new EventEmitter<void>();
  @Output() exportFullReport = new EventEmitter<void>();
  @Output() exportMatrixPng = new EventEmitter<void>();
  @Output() exportHtmlReport = new EventEmitter<void>();
  @Output() exportPdf = new EventEmitter<void>();
  @Output() exportXlsx = new EventEmitter<void>();
  @Output() showGapView = new EventEmitter<void>();
  @Output() toggleDark = new EventEmitter<void>();
  @Output() copyShareLink = new EventEmitter<void>();

  @Input() activePlatforms: Set<string> = new Set();

  readonly PLATFORM_PILLS = PLATFORM_PILLS;

  activePanel: import('../../services/filter.service').ActivePanel = null;
  activeThreatGroupCount = 0;
  attackVersion = '';
  heatmapMode: import('../../services/filter.service').HeatmapMode = 'coverage';
  searchScope: SearchScope = 'name';
  implStatusFilter = '';
  readonly implStatusOptions = [
    { value: 'implemented', label: '✅ Implemented' },
    { value: 'in-progress', label: '🔄 In Progress' },
    { value: 'planned', label: '📋 Planned' },
    { value: 'not-started', label: '❌ Not Started' },
  ];

  searchFilterMode = false;
  mitigationSearchText = '';
  techniqueSearchText = '';
  filteredMitigations: Mitigation[] = [];
  filteredTechniques: Technique[] = [];
  showDropdown = false;
  showTechniqueDropdown = false;
  activeMitigations: Mitigation[] = [];
  dataSourceMode: DataSourceMode = 'live';
  attackDomain: AttackDomain = 'enterprise';
  loading = false;
  sortMode: SortMode = 'alpha';
  dimUncovered = false;
  selectedPlatform: string = '';
  platforms = PLATFORMS;
  selectedDataSource: string = '';
  dataSourceNames: string[] = [];

  // Saved views
  views: SavedView[] = [];
  showViewsMenu = false;
  showSaveDialog = false;
  showExportMenu = false;
  showViewMenu = false;
  showPlatformRow = false;
  newViewName = '';
  newViewDesc = '';

  private subs = new Subscription();

  // CVE search hint for dropdown
  cveSearchHint: { cveId: string; techniqueCount: number } | null = null;

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
    private savedViewsService: SavedViewsService,
    private attackCveService: AttackCveService,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activeMitigationFilters$.subscribe((mits) => {
        this.activeMitigations = mits;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.techniqueQuery$.subscribe((q) => {
        this.techniqueSearchText = q;
        if (!q) {
          this.filteredTechniques = [];
          this.showTechniqueDropdown = false;
        }
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(this.filterService.sortMode$.subscribe((mode) => { this.sortMode = mode; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.dimUncovered$.subscribe((dim) => { this.dimUncovered = dim; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.platformFilter$.subscribe((p) => { this.selectedPlatform = p ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.platformMulti$.subscribe((ps) => { this.activePlatforms = ps; this.cdr.markForCheck(); }));
    this.subs.add(this.dataService.loading$.subscribe((l) => { this.loading = l; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.activePanel$.subscribe((p) => { this.activePanel = p; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.activeThreatGroupIds$.subscribe((ids) => { this.activeThreatGroupCount = ids.size; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.heatmapMode$.subscribe((m) => { this.heatmapMode = m; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.implStatusFilter$.subscribe((s) => { this.implStatusFilter = s ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.searchScope$.subscribe((s) => { this.searchScope = s; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.searchFilterMode$.subscribe((v) => { this.searchFilterMode = v; this.cdr.markForCheck(); }));
    this.subs.add(this.dataService.domain$.subscribe((d) => {
      this.attackVersion = d?.attackVersion ?? '';
      this.dataSourceNames = d ? [...new Set(d.dataComponents.map(dc => dc.dataSourceName))].filter(Boolean).sort() : [];
      this.cdr.markForCheck();
    }));
    this.subs.add(this.filterService.activeDataSource$.subscribe((ds) => { this.selectedDataSource = ds ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.savedViewsService.views$.subscribe(views => { this.views = views; this.cdr.markForCheck(); }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

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

  onTechniqueSearchInput(): void {
    const q = this.techniqueSearchText.trim();
    this.filterService.setTechniqueQuery(q);
    this.cveSearchHint = null;
    if (!q) {
      this.filteredTechniques = [];
      this.showTechniqueDropdown = false;
      return;
    }
    // CVE ID search: look up mapped techniques
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

  onPlatformChange(): void { this.filterService.setPlatformFilter(this.selectedPlatform || null); }

  togglePlatformPill(platform: string): void {
    this.filterService.togglePlatform(platform);
  }

  clearPlatformPills(): void {
    this.filterService.clearPlatformFilter();
  }

  togglePlatformRow(): void {
    this.showPlatformRow = !this.showPlatformRow;
    this.cdr.markForCheck();
  }

  toggleViewMenu(): void {
    this.showViewMenu = !this.showViewMenu;
    this.showExportMenu = false;
    this.showViewsMenu = false;
    this.showSaveDialog = false;
    this.cdr.markForCheck();
  }
  onDetectionSourceChange(): void { this.filterService.setDataSourceFilter(this.selectedDataSource || null); }

  selectMitigation(m: Mitigation): void {
    this.mitigationSearchText = '';
    this.filteredMitigations = [];
    this.showDropdown = false;
    this.filterService.addMitigationFilter(m);
  }

  selectTechnique(t: Technique): void {
    this.showTechniqueDropdown = false;
    this.cveSearchHint = null;
    this.filterService.setTechniqueQuery(t.attackId);
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

  toggleSort(): void { this.filterService.setSortMode(this.sortMode === 'alpha' ? 'coverage' : 'alpha'); }
  toggleDimUncovered(): void { this.filterService.toggleDimUncovered(); }
  togglePanel(panel: 'threats' | 'priority' | 'whatif' | 'report' | 'controls' | 'software' | 'comparison' | 'layers' | 'cve' | 'analytics'): void {
    this.filterService.togglePanel(panel);
  }

  readonly heatmapModes: { value: import('../../services/filter.service').HeatmapMode; label: string }[] = [
    { value: 'coverage',  label: '🛡 Coverage'  },
    { value: 'risk',      label: '🔥 Risk'       },
    { value: 'exposure',  label: '☢ Exposure'   },
    { value: 'frequency', label: '📊 Frequency'  },
    { value: 'software',  label: '💾 Software'   },
    { value: 'campaign',  label: '🎯 Campaign'   },
    { value: 'status',    label: '✅ Status'     },
    { value: 'controls',  label: '🔒 Controls'   },
    { value: 'kev',       label: '🚨 KEV'        },
    { value: 'd3fend',    label: '🛡 D3FEND'     },
    { value: 'atomic',    label: '⚛ Atomic'     },
    { value: 'engage',    label: '🎭 Engage'     },
    { value: 'car',       label: '🔬 CAR'        },
    { value: 'cve',       label: '🔴 CVE'        },
    { value: 'detection', label: '🔍 Detection'  },
    { value: 'cri',       label: '🏦 CRI Profile' },
    { value: 'unified',   label: '🎯 Unified Risk' },
    { value: 'sigma',     label: 'Σ Sigma Rules'  },
    { value: 'nist',      label: '🏛 NIST 800-53'  },
    { value: 'veris',     label: '📋 VERIS Actions'  },
    { value: 'epss',      label: '🎯 EPSS Prob.'     },
    { value: 'elastic',   label: '🟢 Elastic Rules'   },
    { value: 'splunk',    label: '🟠 Splunk Detections' },
    { value: 'intelligence', label: '🧠 Intelligence' },
    { value: 'm365',         label: '🔷 M365 Defender' },
    { value: 'my-exposure',  label: '🎯 My Exposure'   },
    { value: 'wazuh',        label: '🔵 Wazuh XDR'     },
    { value: 'csa-ccm',      label: '☁ CSA CCM'        },
    { value: 'm365-controls', label: '🔷 M365 Controls'  },
    { value: 'kill-chain',    label: '🔗 CVE Kill Chain'  },
    { value: 'poc-exploits',  label: '💣 PoC Exploits'    },
  ];

  setHeatmap(mode: import('../../services/filter.service').HeatmapMode): void {
    this.filterService.setHeatmapMode(mode);
    this.showViewMenu = false;
  }

  cycleHeatmap(): void {
    const modes = this.heatmapModes.map(m => m.value);
    const next = modes[(modes.indexOf(this.heatmapMode) + 1) % modes.length];
    this.filterService.setHeatmapMode(next);
  }

  toggleSearchScope(): void {
    this.filterService.toggleSearchScope();
  }

  toggleSearchFilterMode(): void {
    this.filterService.toggleSearchFilterMode();
  }

  onImplStatusFilterChange(): void {
    this.filterService.setImplStatusFilter(this.implStatusFilter || null);
  }

  onDataSourceChange(): void {
    this.dataService.setDataSourceMode(this.dataSourceMode);
    this.dataService.loadDomain();
  }

  onDomainChange(): void {
    this.domainChange.emit(this.attackDomain);
  }

  forceRefresh(): void {
    this.dataService.forceRefresh();
  }

  printPage(): void { window.print(); }

  saveView(): void {
    if (!this.newViewName.trim()) return;
    this.savedViewsService.saveCurrentView(this.newViewName.trim(), this.newViewDesc.trim());
    this.newViewName = '';
    this.newViewDesc = '';
    this.showSaveDialog = false;
    this.cdr.markForCheck();
  }

  restoreView(view: SavedView): void {
    this.savedViewsService.restoreView(view);
    this.showViewsMenu = false;
  }

  deleteView(id: string): void {
    this.savedViewsService.deleteView(id);
    this.cdr.markForCheck();
  }

  formatViewDate(iso: string): string {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
      return '';
    }
  }

  closeDropdown(): void {
    setTimeout(() => { this.showDropdown = false; this.cdr.markForCheck(); }, 150);
  }

  closeTechniqueDropdown(): void {
    setTimeout(() => { this.showTechniqueDropdown = false; this.cveSearchHint = null; this.cdr.markForCheck(); }, 150);
  }

  /** Returns a consistent daily technique selected by date-seeded index. */
  get techniqueOfDay(): import('../../models/technique').Technique | null {
    if (!this.techniques.length) return null;
    const today = new Date();
    const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
    return this.techniques[seed % this.techniques.length] ?? null;
  }

  selectTechniqueOfDay(): void {
    const t = this.techniqueOfDay;
    if (t) this.selectTechnique(t);
  }

}

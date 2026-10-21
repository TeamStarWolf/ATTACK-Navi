// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  OnDestroy,
  OnInit,
  Injector,
  inject,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Mitigation } from '../../models/mitigation';
import { Technique } from '../../models/technique';
import { DEFAULT_HEATMAP_MODE, FilterService, HeatmapMode, SearchScope, SortMode } from '../../services/filter.service';
import { AttackDomain, DataService } from '../../services/data.service';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { LibraryLayerService, LibraryLayerMeta } from '../../services/library-layer.service';
import { UserLayerService } from '../../services/user-layer.service';
import { AttackNaviLayer } from '../../models/user-layer';
import { HEATMAP_MODES, HEATMAP_GROUPS, HeatmapModeDef, LensAvailability, heatmapShortLabel, lensAvailability } from '../../models/heatmap-modes';
import { domainLabel } from '../../models/lens-sources';
import { LensCardService } from '../../services/lens-card.service';
import { PLATFORM_PILLS } from '../../components/toolbar/toolbar.component';
import { Viewpoint, ViewpointService } from '../../services/viewpoint.service';
import { distinctDataSourceNames, sameDataSource } from '../../utils/data-source-names';
import { PostureService } from '../../services/posture.service';
import { lensNameVisible, lensOnScreen, lensQuestion } from '../../models/lens-registry';

/** The impl= select's tooltip (P2-14, §6): what the four values match under the breadth guard. */
export const IMPL_FILTER_TITLE = 'Filter by implementation status. Broad mitigations count as partial: '
  + 'a technique implemented only through mitigations mapped to more techniques than the breadth threshold '
  + '(Settings, 15 by default) matches none of these values, and Implemented matches full implementation only.';

/**
 * Matrix-scoped controls row: technique + mitigation search, platform /
 * data-source / status filters, the heatmap dropdown, matrix view actions,
 * and clear. Lives inside the matrix page — other workspaces don't carry
 * this chrome (it used to crowd the global toolbar).
 */
@Component({
  selector: 'app-matrix-controls',
  standalone: true,
  imports: [FormsModule],
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

  // Active mitigation filters (applied via sidebar relationship navigation)
  // still drive hasActiveFilters + the Clear button; the toolbar's own
  // "Filter by mitigation" search input was removed.
  activeMitigations: Mitigation[] = [];

  // Filters
  activePlatforms: Set<string> = new Set();
  showPlatformRow = false;
  selectedDataSource = '';
  dataSourceNames: string[] = [];
  /** The data source as the filter holds it, in whatever spelling the URL or picker gave. */
  private rawDataSource: string | null = null;
  implStatusFilter = '';
  readonly implStatusOptions = [
    { value: 'implemented', label: '✅ Implemented' },
    { value: 'in-progress', label: '🔄 In Progress' },
    { value: 'planned', label: '📋 Planned' },
    { value: 'not-started', label: '❌ Not Started' },
  ];

  // View menu
  showViewMenu = false;
  /** Active viewpoint — drives the pinned "featured lenses" group in the menu. */
  currentViewpoint: Viewpoint | null = null;
  heatmapMode: HeatmapMode = DEFAULT_HEATMAP_MODE;
  /** The first-visit lens (E1.5, D4); the View button is highlighted when any other lens is on. */
  readonly defaultHeatmapMode = DEFAULT_HEATMAP_MODE;
  /** The ATT&CK domain on screen; lenses without data for it are disabled with a reason (E1.2). */
  attackDomain: AttackDomain = 'enterprise';
  /** Availability of every lens in attackDomain, rebuilt when the domain changes. */
  private lensAvailabilityByMode = new Map<HeatmapMode, LensAvailability>();
  /** How many lenses are disabled in attackDomain. */
  disabledLensCount = 0;
  libraryLayers: LibraryLayerMeta[] = [];
  /** False until the library manifest loads - the menu says "loading" rather than showing nothing. */
  libraryManifestLoaded = false;
  /** Why the manifest did not load (E1.3): a failure is shown as a failure, not as "loading" or an empty list. */
  libraryManifestError: string | null = null;
  activeLibraryFile: string | null = null;
  /**
   * The imported (user) Navigator layer the matrix is colouring by, if any. It
   * takes precedence over every curated layer, so the menu must show it and
   * offer to unload it - otherwise picking a curated layer looks broken.
   */
  activeUserLayer: AttackNaviLayer | null = null;
  sortMode: SortMode = 'alpha';
  dimUncovered = false;
  multiSelectMode = false;
  activeThreatGroupCount = 0;

  private subs = new Subscription();
  private readonly injector = inject(Injector);

  /**
   * The impl= select's tooltip. While a value is selected it also names the
   * techniques that are partial only (PostureService.implPartialOnly), which
   * no value matches. PostureService is injected only then.
   */
  get implFilterTitle(): string {
    if (!this.implStatusFilter) return IMPL_FILTER_TITLE;
    const { count, via } = this.injector.get(PostureService).implPartialOnly();
    if (count === 0) return IMPL_FILTER_TITLE;
    const n = count === 1 ? '1 technique is' : `${count} techniques are`;
    return `${IMPL_FILTER_TITLE} Now ${n} implemented, partial via ${via.join(', ')} and not shown as a match.`;
  }

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private matrixControl: MatrixControlService,
    private attackCveService: AttackCveService,
    private libraryLayerService: LibraryLayerService,
    private userLayerService: UserLayerService,
    private viewpointService: ViewpointService,
    private cdr: ChangeDetectorRef,
    private lensCards: LensCardService,
  ) {
    this.rebuildLensAvailability();
  }

  ngOnInit(): void {
    this.subs.add(this.dataService.domain$.subscribe((d) => {
      this.techniques = d?.techniques ?? [];
      this.mitigations = d?.mitigations ?? [];
      this.dataSourceNames = d ? distinctDataSourceNames(d.dataComponents.map(dc => dc.dataSourceName)) : [];
      // On a cold deep link the filter is set before the domain loads; resolve it again now the names exist.
      this.selectedDataSource = this.resolveDs(this.rawDataSource);
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
    // A share link may carry another spelling of the name ('macOS:unifiedlog'); select the listed one.
    this.subs.add(this.filterService.activeDataSource$.subscribe((ds) => { this.rawDataSource = ds; this.selectedDataSource = this.resolveDs(ds); this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.implStatusFilter$.subscribe((s) => { this.implStatusFilter = s ?? ''; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.heatmapMode$.subscribe((m) => { this.heatmapMode = m; this.cdr.markForCheck(); }));
    this.subs.add(this.libraryLayerService.manifest$.subscribe((list) => { this.libraryLayers = list; this.cdr.markForCheck(); }));
    this.subs.add(this.libraryLayerService.manifestLoaded$.subscribe((v) => { this.libraryManifestLoaded = v; this.cdr.markForCheck(); }));
    this.subs.add(this.libraryLayerService.manifestError$.subscribe((e) => { this.libraryManifestError = e; this.cdr.markForCheck(); }));
    this.subs.add(this.libraryLayerService.activeFile$.subscribe((f) => { this.activeLibraryFile = f; this.cdr.markForCheck(); }));
    this.subs.add(this.userLayerService.activeLayer$.subscribe((l) => { this.activeUserLayer = l; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.sortMode$.subscribe((m) => { this.sortMode = m; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.dimUncovered$.subscribe((v) => { this.dimUncovered = v; this.cdr.markForCheck(); }));
    this.subs.add(this.filterService.activeThreatGroupIds$.subscribe((ids) => { this.activeThreatGroupCount = ids.size; this.cdr.markForCheck(); }));
    this.subs.add(this.matrixControl.multiSelectMode$.subscribe((v) => { this.multiSelectMode = v; this.cdr.markForCheck(); }));
    this.subs.add(this.viewpointService.viewpoint$.subscribe((vp) => { this.currentViewpoint = vp; this.cdr.markForCheck(); }));
    this.subs.add(this.dataService.currentDomain$.subscribe((d) => {
      this.attackDomain = d;
      this.rebuildLensAvailability();
      this.cdr.markForCheck();
    }));
  }

  /** The listed spelling of `ds`, or `ds` itself until the domain's names are known. */
  private resolveDs(ds: string | null): string {
    return ds ? (this.dataSourceNames.find((n) => sameDataSource(n, ds)) ?? ds) : '';
  }

  private rebuildLensAvailability(): void {
    this.lensAvailabilityByMode = new Map(this.heatmapModes.map((m) => [m.value, lensAvailability(m, this.attackDomain)]));
    this.disabledLensCount = [...this.lensAvailabilityByMode.values()].filter((a) => !a.available).length;
  }

  /** Whether `mode` has data in the domain on screen, and if not, why. */
  lensState(mode: HeatmapMode): LensAvailability {
    return this.lensAvailabilityByMode.get(mode) ?? { available: true, short: null, reason: null };
  }

  get domainName(): string { return domainLabel(this.attackDomain); }

  /** True when the active lens has no data for the domain on screen. */
  get activeLensUnavailable(): boolean { return !this.lensState(this.heatmapMode).available; }

  /** Open the '?' definition card for a lens; focus returns to the '?' button on close. */
  openLensCard(mode: HeatmapMode, event: Event): void {
    event.stopPropagation();
    this.lensCards.open(mode, event.currentTarget);
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  /**
   * Whether Covered and Proven words may render (PostureService.ownerWords,
   * §1.3). The picker, the View button and the lens count read it, so the
   * Proven and Covered lenses are offered and named only once owner data
   * exists (design §10.4 item 14: rung words never appear for an empty user).
   */
  private get ownerWords(): boolean {
    return this.injector.get(PostureService).ownerWords();
  }

  /** The View button's lens name: the default lens's while the active one may not be named (lensOnScreen). */
  get heatmapShort(): string {
    return heatmapShortLabel(lensOnScreen(this.heatmapMode, this.ownerWords, DEFAULT_HEATMAP_MODE));
  }

  /** The lenses the picker offers: every lens, less the Proven and Covered lenses until owner data exists. */
  get pickerModes(): HeatmapModeDef[] {
    const ownerWords = this.ownerWords;
    return this.heatmapModes.filter((m) => lensNameVisible(m, ownerWords));
  }

  /** How many lenses the picker offers (the lens-count line). */
  get pickerModeCount(): number {
    return this.pickerModes.length;
  }

  /** A lens button's title: why it is disabled, else its question (lensQuestion: no Covered word for an empty user). */
  lensTitle(m: HeatmapModeDef, state: LensAvailability): string {
    return state.reason ?? lensQuestion(m, this.ownerWords);
  }

  modesForGroup(group: string): HeatmapModeDef[] {
    return this.pickerModes.filter(m => m.group === group);
  }

  /** True when a non-neutral viewpoint is active (analyst = today's default). */
  get hasFeaturedLenses(): boolean {
    return !!this.currentViewpoint && this.currentViewpoint.id !== 'analyst';
  }

  /** The active viewpoint's featured lenses as full mode defs, in order. */
  get featuredModeDefs(): HeatmapModeDef[] {
    const vp = this.currentViewpoint;
    if (!vp) return [];
    const offered = this.pickerModes;
    return vp.featuredLenses
      .map((v) => offered.find((m) => m.value === v))
      .filter((m): m is HeatmapModeDef => !!m);
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
    this.filteredTechniques = [];
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

  /** Pick a lens. A lens with no data for the domain on screen is disabled: the click does nothing. */
  setHeatmap(mode: HeatmapMode): void {
    if (!this.lensState(mode).available) return;
    this.filterService.setHeatmapMode(mode);
    this.showViewMenu = false;
  }

  /**
   * Select a curated library layer and switch the matrix to color by it. An
   * imported user layer would otherwise silently keep winning (the matrix
   * prefers it), so picking a curated layer unloads it: the last choice shows.
   */
  pickLibraryLayer(file: string): void {
    if (this.userLayerService.activeLayer) this.userLayerService.clearActive();
    this.libraryLayerService.setActive(file);
    this.filterService.setHeatmapMode('library');
    this.showViewMenu = false;
  }

  /** Unload the imported layer; the matrix falls back to the curated layer, if one is picked. */
  unloadUserLayer(): void {
    this.userLayerService.clearActive();
  }

  /** Display name for a layer, without the "TeamStarWolf - " prefix. */
  layerLabel(name: string): string {
    return name.replace(/^TeamStarWolf\s*[-–]\s*/, '');
  }

  toggleSort(): void { this.filterService.setSortMode(this.sortMode === 'alpha' ? 'coverage' : 'alpha'); }
  toggleDimUncovered(): void { this.filterService.toggleDimUncovered(); }
  onExpandAll(): void { this.matrixControl.expandAll(); }
  onCollapseAll(): void { this.matrixControl.collapseAll(); }
  onToggleMultiSelect(): void { this.matrixControl.toggleMultiSelect(); }
  onGapView(): void { this.matrixControl.requestGapView(); }
}

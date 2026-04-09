// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnInit,
  OnDestroy,
  OnChanges,
  HostListener,
  HostBinding,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  ViewChild,
  ElementRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { combineLatest, Subscription } from 'rxjs';
import { Domain, TacticColumn } from '../../models/domain';
import { Tactic } from '../../models/tactic';
import { Technique } from '../../models/technique';
import { FilterService, SortMode, HeatmapMode } from '../../services/filter.service';
import { ImplementationService, ImplStatus } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { ControlsService } from '../../services/controls.service';
import { DocumentationService } from '../../services/documentation.service';
import { D3fendService } from '../../services/d3fend.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { EngageService } from '../../services/engage.service';
import { CARService } from '../../services/car.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { VerisService } from '../../services/veris.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { EpssService } from '../../services/epss.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { MispService } from '../../services/misp.service';
import { M365DefenderService } from '../../services/m365-defender.service';
import { SettingsService } from '../../services/settings.service';
import { AnnotationService, TechniqueAnnotation } from '../../services/annotation.service';
import { WatchlistService } from '../../services/watchlist.service';
import { TaggingService } from '../../services/tagging.service';
import { TechniqueCellComponent } from '../technique-cell/technique-cell.component';
import { TechniqueTooltipComponent } from '../technique-tooltip/technique-tooltip.component';
import { CustomTechniqueService, CustomTechnique } from '../../services/custom-technique.service';
import { AssetInventoryService } from '../../services/asset-inventory.service';
import { WazuhService } from '../../services/wazuh.service';
import { CsaCcmService } from '../../services/csa-ccm.service';
import { M365ControlsService } from '../../services/m365-controls.service';
import { Cve2CapecService } from '../../services/cve2capec.service';
import { PocExploitService } from '../../services/poc-exploit.service';

@Component({
  selector: 'app-matrix',
  standalone: true,
  imports: [CommonModule, TechniqueCellComponent, TechniqueTooltipComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './matrix.component.html',
  styleUrl: './matrix.component.scss',
})
export class MatrixComponent implements OnInit, OnChanges, OnDestroy {
  @Input() domain!: Domain;
  @Output() focusSearch = new EventEmitter<void>();
  @Output() tacticClicked = new EventEmitter<{ tactic: Tactic; techniques: Technique[]; event: MouseEvent }>();
  @ViewChild(TechniqueTooltipComponent) tooltip!: TechniqueTooltipComponent;

  cellSize: 'compact' | 'normal' | 'large' = 'normal';
  showTechniqueIds = true;
  showMitigationCount = true;

  @HostBinding('class.cell-compact') get isCompact() { return this.cellSize === 'compact'; }
  @HostBinding('class.cell-large') get isLarge() { return this.cellSize === 'large'; }
  @HostBinding('style.--mz') get matrixZoom() { return this.zoom; }

  focusedCell: Technique | null = null;
  focusedColIdx = 0;
  focusedRowIdx = 0;

  multiSelectMode = false;
  selectedTechIds = new Set<string>();
  selectedTechniqueId: string | null = null;
  highlightedIds = new Set<string>();
  matchedIds = new Set<string>();
  platformIds: Set<string> | null = null;
  dataSourceIds: Set<string> | null = null;
  hiddenTacticIds = new Set<string>();
  threatGroupIds = new Set<string>();
  softwareFilterIds = new Set<string>();
  campaignFilterIds = new Set<string>();
  hasMitigationFilter = false;
  hasTechniqueSearch = false;
  hasPlatformFilter = false;
  hasDataSourceFilter = false;
  hasThreatFilter = false;
  hasSoftwareFilter = false;
  hasCampaignFilter = false;
  platformMultiFilter = new Set<string>();
  dimUncovered = false;
  sortMode: SortMode = 'alpha';
  expandedParents = new Set<string>();
  sortedColumns: TacticColumn[] = [];
  currentQuery = '';
  // exposureScore per technique id (number of active threat groups using it)
  exposureScores = new Map<string, number>();
  maxExposure = 1;
  // softwareScore per technique id (number of software/malware families using it)
  softwareScores = new Map<string, number>();
  maxSoftware = 1;
  // campaignScore per technique id (number of campaigns using it)
  campaignScores = new Map<string, number>();
  maxCampaign = 1;
  riskScores = new Map<string, number>();
  maxRisk = 1;
  heatmapMode: HeatmapMode = 'coverage';
  implStatusFilter: string | null = null;
  searchFilterMode = false;
  // per-technique "best" impl status (for status heatmap mode)
  techniqueImplStatus = new Map<string, ImplStatus>();
  // controls heatmap coverage
  controlsCoveredIds = new Set<string>();
  controlsPlannedIds = new Set<string>();
  // technique notes for note indicator
  techNotes = new Map<string, string>();
  // KEV exposure scores: attackId -> count of KEV CVEs
  kevScores = new Map<string, number>();
  maxKev = 1;
  // CVE filter: set of attackIds currently highlighted from CVE panel
  cveTechniqueIds = new Set<string>();
  // D3FEND countermeasure scores: technique.id -> count
  d3fendScoreMap = new Map<string, number>();
  maxD3fend = 1;
  // Atomic Red Team scores: technique.attackId -> count
  atomicScoreMap = new Map<string, number>();
  maxAtomic = 1;
  // Engage activity scores: technique.id -> count
  engageScoreMap = new Map<string, number>();
  maxEngageScore = 1;
  // CAR analytic scores: technique.id -> count
  carScoreMap = new Map<string, number>();
  maxCarScore = 1;
  // CRI Profile scores: technique.id -> count of CRI controls
  criScoreMap = new Map<string, number>();
  maxCriScore = 1;
  // CVE exposure scores (CTID ATT&CK→CVE dataset): attackId -> CVE count
  cveScoreMap = new Map<string, number>();
  maxCveScore = 1;
  // Detection coverage scores (CAR + Atomic + D3FEND combined): attackId -> weighted score
  detectionScoreMap = new Map<string, number>();
  maxDetectionScore = 1;
  // Unified Risk Score: attackId -> 0–100 composite
  unifiedScoreMap = new Map<string, number>();
  // Sigma rule scores: attackId -> rule count
  sigmaScoreMap = new Map<string, number>();
  maxSigmaScore = 1;
  // NIST 800-53 control counts: attackId -> control count
  nistScoreMap = new Map<string, number>();
  maxNistScore = 1;
  // VERIS incident action counts: attackId -> action count
  verisScoreMap = new Map<string, number>();
  maxVerisScore = 1;
  // EPSS exploitation probability: attackId -> avg EPSS (0-1)
  epssScoreMap = new Map<string, number>();
  epssLoading = false;
  // Elastic Detection Rules scores: attackId -> rule count
  elasticScoreMap = new Map<string, number>();
  maxElasticScore = 1;
  // Splunk Security Content scores: attackId -> detection count
  splunkScoreMap = new Map<string, number>();
  maxSplunkScore = 1;
  // Intelligence heatmap scores: attackId -> intel signal count
  intelScoreMap = new Map<string, number>();
  maxIntelScore = 1;
  // M365 Defender hunting query scores: attackId -> query count
  m365ScoreMap = new Map<string, number>();
  maxM365Score = 1;
  // My Exposure scores: attackId -> asset exposure count from AssetInventoryService
  myExposureScoreMap = new Map<string, number>();
  maxMyExposure = 1;
  // Wazuh XDR rule scores: attackId -> rule count
  wazuhScoreMap = new Map<string, number>();
  maxWazuhScore = 1;
  // CSA CCM control scores: attackId -> control count
  csaCcmScoreMap = new Map<string, number>();
  maxCsaCcmScore = 1;
  // M365 Controls scores: attackId -> control count
  m365ControlsScoreMap = new Map<string, number>();
  maxM365ControlsScore = 1;
  // CVE2CAPEC kill chain scores: attackId -> chain count
  killChainScoreMap = new Map<string, number>();
  maxKillChainScore = 1;
  // PoC Exploit scores: attackId -> PoC count
  pocScoreMap = new Map<string, number>();
  maxPocScore = 1;
  // Track current heatmap mode for loaded$ re-trigger
  private currentHeatmapMode: HeatmapMode = 'coverage';
  // Annotation map: techniqueId (attackId) -> annotation
  annotationMap = new Map<string, TechniqueAnnotation>();

  // Watchlist: set of ATT&CK IDs currently on watchlist
  watchedIds = new Set<string>();

  // Live technique search (matrix search bar)
  searchQuery = '';
  matchingIds = new Set<string>();

  // Zoom state
  zoom = 1.0;
  readonly ZOOM_MIN = 0.5;
  readonly ZOOM_MAX = 1.5;
  readonly ZOOM_STEP = 0.1;

  // Columns dropdown
  showColumnMenu = false;

  // Minimap overlay
  showMinimap = false;

  // Frequency heatmap: technique STIX id → count of unique threat groups using it
  frequencyMap = new Map<string, number>();
  maxFrequencyScore = 1;

  // Custom techniques from user-created collection
  customTechniques: CustomTechnique[] = [];
  customTechniqueIds = new Set<string>();

  // Show/hide technique names
  showTechniqueNames = true;

  // Tactic header colors keyed by shortname
  readonly TACTIC_COLORS: Record<string, string> = {
    'reconnaissance': '#1a1a2e',
    'resource-development': '#16213e',
    'initial-access': '#0f3460',
    'execution': '#533483',
    'persistence': '#2d6a4f',
    'privilege-escalation': '#1b4332',
    'defense-evasion': '#6b2737',
    'credential-access': '#7b2d00',
    'discovery': '#3d405b',
    'lateral-movement': '#2c3e50',
    'collection': '#1a535c',
    'command-and-control': '#1a4a4a',
    'exfiltration': '#5a4200',
    'impact': '#5a1a1a',
    'inhibit-response-function': '#8b0000',
    'impair-process-control': '#6b2737',
  };

  getTacticHeaderColor(shortname: string): string {
    return this.TACTIC_COLORS[shortname] ?? '#07101a';
  }

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private implService: ImplementationService,
    private controlsService: ControlsService,
    private docService: DocumentationService,
    private cveService: CveService,
    private d3fendService: D3fendService,
    private atomicService: AtomicService,
    private sigmaService: SigmaService,
    private engageService: EngageService,
    private carService: CARService,
    private attackCveService: AttackCveService,
    private settingsService: SettingsService,
    private annotationService: AnnotationService,
    private watchlistService: WatchlistService,
    private taggingService: TaggingService,
    private criProfileService: CriProfileService,
    private nistMappingService: NistMappingService,
    private verisService: VerisService,
    private epssService: EpssService,
    private elasticService: ElasticService,
    private splunkContentService: SplunkContentService,
    private mispService: MispService,
    private m365DefenderService: M365DefenderService,
    private customTechniqueService: CustomTechniqueService,
    private assetInventoryService: AssetInventoryService,
    private wazuhService: WazuhService,
    private csaCcmService: CsaCcmService,
    private m365ControlsService: M365ControlsService,
    private cve2capecService: Cve2CapecService,
    private pocExploitService: PocExploitService,
    private cdr: ChangeDetectorRef,
    private el: ElementRef,
  ) {}

  private refreshActiveHeatmap(...modes: HeatmapMode[]): void {
    if (modes.includes(this.currentHeatmapMode)) {
      this.filterService.setHeatmapMode(this.currentHeatmapMode);
    }
  }

  private wheelListener = (event: WheelEvent): void => {
    if (!event.ctrlKey) return;
    event.preventDefault();
    if (event.deltaY < 0) this.zoomIn();
    else this.zoomOut();
  };

  @HostListener('document:keydown.escape')
  onEsc(): void {
    if (this.selectedTechIds.size > 0) {
      this.clearSelection();
    } else {
      this.filterService.selectTechnique(null);
      this.focusedCell = null;
      this.cdr.markForCheck();
    }
  }

  @HostListener('document:keydown', ['$event'])
  onKeydown(e: KeyboardEvent): void {
    if (this.isInputFocused()) return;

    if ((e.key === 'a' || e.key === 'A') && (e.ctrlKey || e.metaKey) && this.multiSelectMode) {
      e.preventDefault();
      this.selectAllVisible();
      return;
    }

    if (e.key === '/') {
      e.preventDefault();
      this.filterService.setTechniqueQuery('');
      this.focusSearch.emit();
      return;
    }

    if (e.key === 'Enter' && this.focusedCell) {
      e.preventDefault();
      this.filterService.selectTechnique(this.focusedCell);
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      this.moveFocus(0, 1);
      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      this.moveFocus(0, -1);
      return;
    }

    if (e.key === 'ArrowRight') {
      e.preventDefault();
      this.moveFocus(1, 0);
      return;
    }

    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      this.moveFocus(-1, 0);
      return;
    }
  }

  moveFocus(colDelta: number, rowDelta: number): void {
    if (!this.domain) return;

    const visibleCols = this.sortedColumns;

    if (this.focusedCell === null) {
      this.focusedColIdx = 0;
      this.focusedRowIdx = 0;
    } else {
      let newCol = this.focusedColIdx + colDelta;
      let newRow = this.focusedRowIdx + rowDelta;

      // Clamp column
      newCol = Math.max(0, Math.min(visibleCols.length - 1, newCol));

      // Get parent techniques for the new column
      const colTechs = visibleCols[newCol]?.techniques.filter(t => !t.isSubtechnique) ?? [];
      newRow = Math.max(0, Math.min(colTechs.length - 1, newRow));

      this.focusedColIdx = newCol;
      this.focusedRowIdx = newRow;
    }

    const col = visibleCols[this.focusedColIdx];
    const techs = col?.techniques.filter(t => !t.isSubtechnique) ?? [];
    this.focusedCell = techs[this.focusedRowIdx] ?? null;

    if (this.focusedCell) {
      this.scrollCellIntoView(this.focusedCell.id);
    }
    this.cdr.markForCheck();
  }

  private scrollCellIntoView(techniqueId: string): void {
    setTimeout(() => {
      const el = document.querySelector(`[data-tech-id="${techniqueId}"]`);
      el?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
    }, 0);
  }

  private isInputFocused(): boolean {
    const tag = document.activeElement?.tagName?.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select';
  }

  ngOnChanges(): void {
    this.rebuildSortedColumns();
    // Initialize all parents as expanded on domain load
    if (this.domain && this.expandedParents.size === 0) {
      for (const tech of this.domain.techniques) {
        if (!tech.isSubtechnique && tech.subtechniques.length > 0) {
          this.expandedParents.add(tech.id);
        }
      }
    }
    this.rebuildSearchMatches();
  }

  ngOnInit(): void {
    this.el.nativeElement.addEventListener('wheel', this.wheelListener, { passive: false });

    this.subs.add(
      this.filterService.selectedTechnique$.subscribe((t) => {
        this.selectedTechniqueId = t?.id ?? null;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      combineLatest([
        this.filterService.highlightedTechniqueIds$,
        this.filterService.matchedTechniqueIds$,
        this.filterService.platformFilteredIds$,
        this.filterService.dimUncovered$,
        this.filterService.sortMode$,
        this.filterService.hiddenTacticIds$,
        this.filterService.techniqueQuery$,
        this.filterService.threatGroupTechniqueIds$,
        this.filterService.activeThreatGroupIds$,
        this.filterService.softwareTechniqueIds$,
        this.filterService.activeSoftwareIds$,
        this.filterService.campaignTechniqueIds$,
        this.filterService.activeCampaignIds$,
        this.filterService.dataSourceFilteredIds$,
        this.filterService.searchFilterMode$,
      ]).subscribe(([highlighted, matched, platform, dimUncovered, sortMode, hiddenTactics, techniqueQuery, threatTechIds, activeGroupIds, swTechIds, activeSwIds, campTechIds, activeCampIds, dsIds, searchFilterMode]) => {
        this.highlightedIds = highlighted;
        this.matchedIds = matched;
        this.platformIds = platform;
        this.dataSourceIds = dsIds;
        this.hiddenTacticIds = hiddenTactics;
        this.threatGroupIds = threatTechIds;
        this.softwareFilterIds = swTechIds;
        this.campaignFilterIds = campTechIds;
        this.hasMitigationFilter = highlighted.size > 0;
        this.hasTechniqueSearch = techniqueQuery.trim().length > 0;
        this.hasPlatformFilter = platform !== null;
        this.hasDataSourceFilter = dsIds !== null;
        this.hasThreatFilter = activeGroupIds.size > 0;
        this.hasSoftwareFilter = activeSwIds.size > 0;
        this.hasCampaignFilter = activeCampIds.size > 0;
        this.dimUncovered = dimUncovered;
        this.sortMode = sortMode;
        this.currentQuery = techniqueQuery.trim();
        this.searchFilterMode = searchFilterMode;

        // Build per-technique exposure scores
        this.exposureScores = new Map();
        if (this.hasThreatFilter && this.domain) {
          for (const groupId of activeGroupIds) {
            const techs = this.domain.techniquesByGroup.get(groupId) ?? [];
            for (const t of techs) {
              this.exposureScores.set(t.id, (this.exposureScores.get(t.id) ?? 0) + 1);
            }
          }
        }
        this.maxExposure = this.exposureScores.size > 0 ? Math.max(...this.exposureScores.values()) : 1;

        this.rebuildSortedColumns();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      combineLatest([
        this.filterService.heatmapMode$,
        this.filterService.implStatusFilter$,
        this.implService.status$,
      ]).subscribe(([mode, implFilter, statusMap]) => {
        this.heatmapMode = mode;
        this.currentHeatmapMode = mode;
        this.implStatusFilter = implFilter;

        // Build per-technique "best" impl status for status heatmap
        this.techniqueImplStatus = new Map();
        if (this.domain) {
          const STATUS_RANK: Record<string, number> = { 'implemented': 4, 'in-progress': 3, 'planned': 2, 'not-started': 1 };
          for (const tech of this.domain.techniques) {
            const rels = this.domain.mitigationsByTechnique.get(tech.id) ?? [];
            let best: ImplStatus | null = null;
            let bestRank = 0;
            for (const rel of rels) {
              const s = statusMap.get(rel.mitigation.id);
              if (s && (STATUS_RANK[s] ?? 0) > bestRank) { best = s; bestRank = STATUS_RANK[s]; }
            }
            if (best) this.techniqueImplStatus.set(tech.id, best);
          }
        }

        this.cdr.markForCheck();
      }),
    );

    // Build global software/campaign scores from domain (used in heatmap modes)
    this.subs.add(
      this.filterService.heatmapMode$.subscribe((mode) => {
        this.currentHeatmapMode = mode;
        if (mode === 'kev' || mode === 'unified') {
          this.cveService.loadKev();
        }
        if (mode === 'm365') {
          this.m365DefenderService.loadOnDemand();
        }
        if (mode === 'software' && this.domain) {
          this.softwareScores = new Map();
          for (const [techId, swList] of this.domain.softwareByTechnique.entries()) {
            this.softwareScores.set(techId, swList.length);
          }
          this.maxSoftware = this.softwareScores.size > 0 ? Math.max(...this.softwareScores.values()) : 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
        } else if (mode === 'campaign' && this.domain) {
          this.campaignScores = new Map();
          for (const [techId, campList] of this.domain.campaignsByTechnique.entries()) {
            this.campaignScores.set(techId, campList.length);
          }
          this.maxCampaign = this.campaignScores.size > 0 ? Math.max(...this.campaignScores.values()) : 1;
          this.softwareScores = new Map();
          this.maxSoftware = 1;
        } else if (mode === 'risk' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          // Risk score = groupCount * (1 + 1/(mitigationCount+1)) using all domain groups
          this.riskScores = new Map();
          for (const tech of this.domain.techniques) {
            const groupCount = (this.domain.groupsByTechnique.get(tech.id) ?? []).length;
            const mitCount = tech.mitigationCount;
            const risk = groupCount * (1 + 1 / (mitCount + 1));
            if (risk > 0) this.riskScores.set(tech.id, risk);
          }
          this.maxRisk = this.riskScores.size > 0 ? Math.max(...this.riskScores.values()) : 1;
        } else if (mode === 'd3fend' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.d3fendScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.d3fendService.getCountermeasures(tech.attackId).length;
            if (count > 0) this.d3fendScoreMap.set(tech.id, count);
          }
          this.maxD3fend = this.d3fendScoreMap.size > 0 ? Math.max(...this.d3fendScoreMap.values()) : 1;
        } else if (mode === 'atomic' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.atomicScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const score = this.atomicService.getHeatScore(tech.attackId);
            if (score > 0) this.atomicScoreMap.set(tech.id, score);
          }
          this.maxAtomic = this.atomicScoreMap.size > 0 ? Math.max(...this.atomicScoreMap.values()) : 1;
        } else if (mode === 'engage' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.engageScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.engageService.getActivities(tech.attackId).length;
            if (count > 0) this.engageScoreMap.set(tech.id, count);
          }
          this.maxEngageScore = this.engageScoreMap.size > 0 ? Math.max(...this.engageScoreMap.values()) : 1;
        } else if (mode === 'car' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.carScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            // Use live navigator layer count when available — covers more techniques
            const count = this.carService.getLiveCount(tech.attackId);
            if (count > 0) this.carScoreMap.set(tech.id, count);
          }
          this.maxCarScore = this.carScoreMap.size > 0 ? Math.max(...this.carScoreMap.values()) : 1;
        } else if (mode === 'cve' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.cveScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.attackCveService.getCvesForTechnique(tech.attackId).length;
            if (count > 0) this.cveScoreMap.set(tech.attackId, count);
          }
          this.maxCveScore = Math.max(1, ...this.cveScoreMap.values());
        } else if (mode === 'detection' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.detectionScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const sigmaCount  = this.sigmaService.getRuleCount(tech.attackId);
            const carCount    = this.carService.getAnalytics(tech.attackId).length;
            const atomicCount = this.atomicService.getTestCount(tech.attackId);   // live count
            const d3fendCount = this.d3fendService.getCountermeasures(tech.attackId).length;
            // Sigma rules (3pt) + D3FEND countermeasures (2pt) + CAR analytics (2pt) + Atomic tests (1pt)
            const score = (sigmaCount * 3) + (d3fendCount * 2) + (carCount * 2) + (atomicCount * 1);
            if (score > 0) this.detectionScoreMap.set(tech.attackId, score);
          }
          this.maxDetectionScore = Math.max(1, ...this.detectionScoreMap.values());
        } else if (mode === 'frequency' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.frequencyMap = new Map();
          for (const [techId, groups] of this.domain.groupsByTechnique.entries()) {
            if (groups.length > 0) this.frequencyMap.set(techId, groups.length);
          }
          this.maxFrequencyScore = this.frequencyMap.size > 0 ? Math.max(...this.frequencyMap.values()) : 1;
        } else if (mode === 'cri' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.criScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.criProfileService.getControlCount(tech.attackId);
            if (count > 0) this.criScoreMap.set(tech.id, count);
          }
          this.maxCriScore = this.criScoreMap.size > 0 ? Math.max(...this.criScoreMap.values()) : 1;
        } else if (mode === 'unified' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.sigmaScoreMap = new Map();
          this.unifiedScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            // Mitigation coverage (weight 30): 4+ mitigations = full score
            const mitScore = Math.min(tech.mitigationCount / 4, 1) * 30;
            // Detection (weight 20): sigma + CAR rules presence
            const sigmaCount  = this.sigmaService.getRuleCount(tech.attackId);
            const carCount    = this.carService.getLiveCount(tech.attackId);
            const detectScore = Math.min((sigmaCount + carCount) / 5, 1) * 20;
            // Atomic test validation (weight 15)
            const atomicCount = this.atomicService.getTestCount(tech.attackId);
            const atomicScore = Math.min(atomicCount / 3, 1) * 15;
            // D3FEND countermeasures (weight 10)
            const d3fendCount = this.d3fendService.getCountermeasures(tech.attackId).length;
            const d3fendScore = Math.min(d3fendCount / 2, 1) * 10;
            // KEV exposure INVERTED (weight 25): more KEV CVEs = lower score = higher risk
            const kevCount = this.kevScores.get(tech.attackId) ?? 0;
            const kevPenalty = Math.min(kevCount * 5, 25);
            const kevScore = 25 - kevPenalty;
            const total = Math.round(mitScore + detectScore + atomicScore + d3fendScore + kevScore);
            this.unifiedScoreMap.set(tech.attackId, total);
          }
        } else if (mode === 'sigma' && this.domain) {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
          this.sigmaScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.sigmaService.getRuleCount(tech.attackId);
            if (count > 0) this.sigmaScoreMap.set(tech.attackId, count);
          }
          this.maxSigmaScore = this.sigmaScoreMap.size > 0 ? Math.max(...this.sigmaScoreMap.values()) : 1;
        } else if (mode === 'nist' && this.domain) {
          this.nistScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.nistMappingService.getControlCount(tech.attackId);
            if (count > 0) this.nistScoreMap.set(tech.attackId, count);
          }
          this.maxNistScore = this.nistScoreMap.size > 0 ? Math.max(...this.nistScoreMap.values()) : 1;
        } else if (mode === 'veris' && this.domain) {
          this.verisScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.verisService.getActionsForTechnique(tech.attackId).length;
            if (count > 0) this.verisScoreMap.set(tech.attackId, count);
          }
          this.maxVerisScore = this.verisScoreMap.size > 0 ? Math.max(...this.verisScoreMap.values()) : 1;
        } else if (mode === 'elastic' && this.domain) {
          this.elasticScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.elasticService.getRuleCount(tech.attackId);
            if (count > 0) this.elasticScoreMap.set(tech.attackId, count);
          }
          this.maxElasticScore = this.elasticScoreMap.size > 0 ? Math.max(...this.elasticScoreMap.values()) : 1;
        } else if (mode === 'splunk' && this.domain) {
          this.splunkScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.splunkContentService.getRuleCount(tech.attackId);
            if (count > 0) this.splunkScoreMap.set(tech.attackId, count);
          }
          this.maxSplunkScore = this.splunkScoreMap.size > 0 ? Math.max(...this.splunkScoreMap.values()) : 1;
        } else if (mode === 'intelligence' && this.domain) {
          this.intelScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const hasMisp = this.mispService.hasMisp(tech.attackId) ? 1 : 0;
            const groupCount = (this.domain.groupsByTechnique.get(tech.id) ?? []).length;
            const score = hasMisp + groupCount;
            if (score > 0) this.intelScoreMap.set(tech.attackId, score);
          }
          this.maxIntelScore = this.intelScoreMap.size > 0 ? Math.max(...this.intelScoreMap.values()) : 1;
        } else if (mode === 'm365' && this.domain) {
          this.m365ScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.m365DefenderService.getHeatScore(tech.attackId);
            if (count > 0) this.m365ScoreMap.set(tech.attackId, count);
          }
          this.maxM365Score = this.m365ScoreMap.size > 0 ? Math.max(...this.m365ScoreMap.values()) : 1;
        } else if (mode === 'epss' && this.domain) {
          this.epssScoreMap = new Map();
          // Collect all unique CVE IDs across all techniques
          const allCveIds = new Set<string>();
          for (const tech of this.domain.techniques) {
            for (const m of this.attackCveService.getCvesForTechnique(tech.attackId)) {
              allCveIds.add(m.cveId);
            }
          }
          if (allCveIds.size > 0) {
            this.epssLoading = true;
            this.cdr.markForCheck();
            this.subs.add(
              this.epssService.fetchScores([...allCveIds]).subscribe(scores => {
                this.epssScoreMap = new Map();
                for (const tech of this.domain!.techniques) {
                  const cves = this.attackCveService.getCvesForTechnique(tech.attackId);
                  const withScores = cves.map(m => scores.get(m.cveId)?.epss).filter((s): s is number => s !== undefined);
                  if (withScores.length > 0) {
                    const avg = withScores.reduce((a, b) => a + b, 0) / withScores.length;
                    this.epssScoreMap.set(tech.attackId, avg);
                  }
                }
                this.epssLoading = false;
                this.cdr.markForCheck();
              }),
            );
          }
        } else if (mode === 'my-exposure') {
          // Scores come from AssetInventoryService subscription — just trigger redraw
          this.cdr.markForCheck();
        } else if (mode === 'wazuh' && this.domain) {
          this.wazuhScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.wazuhService.getRulesForTechnique(tech.attackId).length;
            if (count > 0) this.wazuhScoreMap.set(tech.attackId, count);
          }
          this.maxWazuhScore = this.wazuhScoreMap.size > 0 ? Math.max(...this.wazuhScoreMap.values()) : 1;
        } else if (mode === 'csa-ccm' && this.domain) {
          this.csaCcmScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.csaCcmService.getHeatScore(tech.attackId);
            if (count > 0) this.csaCcmScoreMap.set(tech.attackId, count);
          }
          this.maxCsaCcmScore = this.csaCcmScoreMap.size > 0 ? Math.max(...this.csaCcmScoreMap.values()) : 1;
        } else if (mode === 'm365-controls' && this.domain) {
          this.m365ControlsScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.m365ControlsService.getHeatScore(tech.attackId);
            if (count > 0) this.m365ControlsScoreMap.set(tech.attackId, count);
          }
          this.maxM365ControlsScore = this.m365ControlsScoreMap.size > 0 ? Math.max(...this.m365ControlsScoreMap.values()) : 1;
        } else if (mode === 'kill-chain' && this.domain) {
          this.killChainScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.cve2capecService.getChainCount(tech.attackId);
            if (count > 0) this.killChainScoreMap.set(tech.attackId, count);
          }
          this.maxKillChainScore = this.killChainScoreMap.size > 0 ? Math.max(...this.killChainScoreMap.values()) : 1;
        } else if (mode === 'poc-exploits' && this.domain) {
          this.pocScoreMap = new Map();
          for (const tech of this.domain.techniques) {
            const count = this.pocExploitService.getPocCount(tech.attackId);
            if (count > 0) this.pocScoreMap.set(tech.attackId, count);
          }
          this.maxPocScore = this.pocScoreMap.size > 0 ? Math.max(...this.pocScoreMap.values()) : 1;
        } else {
          this.softwareScores = new Map();
          this.maxSoftware = 1;
          this.campaignScores = new Map();
          this.maxCampaign = 1;
          this.riskScores = new Map();
          this.maxRisk = 1;
        }
        this.cdr.markForCheck();
      }),
    );


    this.subs.add(
      this.docService.techNotes$.subscribe((notes) => {
        this.techNotes = notes;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      combineLatest([this.controlsService.controls$, this.filterService.heatmapMode$]).subscribe(
        ([controls, mode]) => {
          if (mode === 'controls' && this.domain) {
            const { coveredIds, plannedIds } = this.controlsService.computeCoverage(controls, this.domain);
            this.controlsCoveredIds = coveredIds;
            this.controlsPlannedIds = plannedIds;
          } else {
            this.controlsCoveredIds = new Set();
            this.controlsPlannedIds = new Set();
          }
          this.cdr.markForCheck();
        },
      ),
    );

    this.subs.add(
      this.cveService.kevTechScores$.subscribe(scores => {
        this.kevScores = scores;
        this.maxKev = scores.size > 0 ? Math.max(...scores.values()) : 1;
        this.refreshActiveHeatmap('unified');
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.cveTechniqueIds$.subscribe(ids => {
        this.cveTechniqueIds = ids;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.d3fendService.loaded$.subscribe(loaded => {
        if (loaded) {
          this.refreshActiveHeatmap('d3fend', 'detection', 'unified');
        }
      }),
    );

    this.subs.add(
      this.atomicService.loaded$.subscribe(loaded => {
        if (loaded) {
          this.refreshActiveHeatmap('atomic', 'detection', 'unified');
        }
      }),
    );

    this.subs.add(
      this.attackCveService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'cve') {
          this.filterService.setHeatmapMode('cve');
        }
        if (loaded && this.currentHeatmapMode === 'epss') {
          this.filterService.setHeatmapMode('epss');
        }
      }),
    );

    this.subs.add(
      this.criProfileService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'cri') {
          this.filterService.setHeatmapMode('cri');
        }
      }),
    );

    this.subs.add(
      this.carService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'car') {
          this.filterService.setHeatmapMode('car');
        }
        if (loaded && (this.currentHeatmapMode === 'detection' || this.currentHeatmapMode === 'unified')) {
          this.filterService.setHeatmapMode(this.currentHeatmapMode);
        }
      }),
    );

    // Re-render detection/sigma heatmap when Sigma live counts arrive
    this.subs.add(
      this.sigmaService.loaded$.subscribe(loaded => {
        if (loaded && (this.currentHeatmapMode === 'detection' || this.currentHeatmapMode === 'sigma' || this.currentHeatmapMode === 'unified')) {
          this.filterService.setHeatmapMode(this.currentHeatmapMode);
        }
      }),
    );

    // Re-render NIST heatmap when NIST data loads
    this.subs.add(
      this.nistMappingService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'nist') {
          this.filterService.setHeatmapMode('nist');
        }
      }),
    );

    // Re-render VERIS heatmap when VERIS data loads
    this.subs.add(
      this.verisService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'veris') {
          this.filterService.setHeatmapMode('veris');
        }
      }),
    );

    // Subscribe to asset inventory exposure map for 'my-exposure' heatmap
    this.subs.add(
      this.assetInventoryService.exposureMap$.subscribe(exposureMap => {
        this.myExposureScoreMap = new Map();
        for (const [techId, count] of exposureMap.entries()) {
          this.myExposureScoreMap.set(techId, count);
        }
        this.maxMyExposure = this.myExposureScoreMap.size > 0 ? Math.max(...this.myExposureScoreMap.values()) : 1;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.mispService.loaded$.subscribe(loaded => {
        if (loaded) {
          this.refreshActiveHeatmap('intelligence');
        }
      }),
    );

    this.subs.add(
      this.m365DefenderService.loaded$.subscribe(loaded => {
        if (loaded) {
          this.refreshActiveHeatmap('m365');
        }
      }),
    );

    // Re-render Elastic heatmap when Elastic data loads
    this.subs.add(
      this.elasticService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'elastic') {
          this.filterService.setHeatmapMode('elastic');
        }
      }),
    );

    // Re-render Splunk heatmap when Splunk data loads
    this.subs.add(
      this.splunkContentService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'splunk') {
          this.filterService.setHeatmapMode('splunk');
        }
      }),
    );

    // Re-render CSA CCM heatmap when CSA CCM data loads
    this.subs.add(
      this.csaCcmService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'csa-ccm') {
          this.filterService.setHeatmapMode('csa-ccm');
        }
      }),
    );

    // Re-render M365 Controls heatmap when M365 Controls data loads
    this.subs.add(
      this.m365ControlsService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'm365-controls') {
          this.filterService.setHeatmapMode('m365-controls');
        }
      }),
    );

    // Re-render CVE Kill Chain heatmap when CVE2CAPEC data loads
    this.subs.add(
      this.cve2capecService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'kill-chain') {
          this.filterService.setHeatmapMode('kill-chain');
        }
      }),
    );

    // Re-render PoC Exploits heatmap when PoC data loads
    this.subs.add(
      this.pocExploitService.loaded$.subscribe(loaded => {
        if (loaded && this.currentHeatmapMode === 'poc-exploits') {
          this.filterService.setHeatmapMode('poc-exploits');
        }
      }),
    );

    // Kick off Sigma live fetch
    this.sigmaService.loadLive();

    this.subs.add(
      this.settingsService.settings$.subscribe(s => {
        this.cellSize = s.matrixCellSize;
        this.showTechniqueIds = s.showTechniqueIds;
        this.showMitigationCount = s.showMitigationCount;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.annotationService.annotations$.subscribe(map => {
        this.annotationMap = map;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.watchlistService.entries$.subscribe(entries => {
        this.watchedIds = new Set(entries.map(e => e.techniqueId));
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.platformMulti$.subscribe(platforms => {
        this.platformMultiFilter = platforms;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.techniqueSearch$.subscribe(query => {
        this.searchQuery = query;
        this.rebuildSearchMatches();
        this.cdr.markForCheck();
      }),
    );

    // Subscribe to custom technique changes
    this.subs.add(
      this.customTechniqueService.techniques$.subscribe(techniques => {
        this.customTechniques = techniques;
        this.customTechniqueIds = new Set(techniques.map(t => t.attackId));
        this.rebuildSortedColumns();
        this.cdr.markForCheck();
      }),
    );

    // Restore search query from URL on init
    const initialSearch = this.filterService.getTechniqueSearch();
    if (initialSearch) {
      this.searchQuery = initialSearch;
      this.rebuildSearchMatches();
    }
  }

  ngOnDestroy(): void {
    this.el.nativeElement.removeEventListener('wheel', this.wheelListener);
    this.subs.unsubscribe();
  }

  // --- Live technique search ---
  private rebuildSearchMatches(): void {
    if (!this.searchQuery || !this.domain) {
      this.matchingIds = new Set();
      return;
    }
    const q = this.searchQuery.trim();
    const ql = q.toLowerCase();
    const ids = new Set<string>();

    // CVE lookup: if query looks like a CVE ID, highlight all mapped techniques
    if (/^cve-\d{4}-\d+$/i.test(q)) {
      const mapping = this.attackCveService.getMappingForCve(q.toUpperCase());
      if (mapping) {
        const attackIds = new Set([
          ...mapping.primaryImpact,
          ...mapping.secondaryImpact,
          ...mapping.exploitationTechnique,
        ]);
        for (const t of this.domain.techniques) {
          if (attackIds.has(t.attackId)) ids.add(t.id);
        }
      }
      this.matchingIds = ids;
      return;
    }

    for (const t of this.domain.techniques) {
      const haystack = `${t.attackId} ${t.name} ${(t as any).description ?? ''}`.toLowerCase();
      if (haystack.includes(ql)) ids.add(t.id);
    }
    this.matchingIds = ids;
  }

  isMatrixSearchMatch(t: Technique): boolean {
    return !this.searchQuery || this.matchingIds.has(t.id);
  }

  onSearchInput(event: Event): void {
    const query = (event.target as HTMLInputElement).value;
    this.filterService.setTechniqueSearch(query);
  }

  clearSearch(): void {
    this.filterService.setTechniqueSearch('');
  }

  // --- Zoom controls ---
  zoomIn(): void {
    this.zoom = Math.min(this.ZOOM_MAX, +(this.zoom + this.ZOOM_STEP).toFixed(1));
    this.cdr.markForCheck();
  }

  zoomOut(): void {
    this.zoom = Math.max(this.ZOOM_MIN, +(this.zoom - this.ZOOM_STEP).toFixed(1));
    this.cdr.markForCheck();
  }

  resetZoom(): void {
    this.zoom = 1.0;
    this.cdr.markForCheck();
  }

  zoomToFit(): void {
    const wrapper = this.el.nativeElement.querySelector('#matrix-content');
    const table = this.el.nativeElement.querySelector('.matrix');
    if (!wrapper || !table) return;
    const visibleCols = this.sortedColumns.filter(c => !this.hiddenTacticIds.has(c.tactic.id)).length;
    if (visibleCols === 0) return;
    const viewportWidth = wrapper.clientWidth;
    const colWidth = 140; // base column width from CSS --col-width
    const tableNaturalWidth = visibleCols * colWidth + 20; // 20px padding buffer
    const idealZoom = viewportWidth / tableNaturalWidth;
    this.zoom = Math.max(this.ZOOM_MIN, Math.min(this.ZOOM_MAX, +idealZoom.toFixed(2)));
    this.cdr.markForCheck();
  }

  get noResults(): boolean {
    if (this.hasTechniqueSearch) return this.matchedIds.size === 0;
    if (this.searchQuery) return this.matchingIds.size === 0;
    return false;
  }

  get hiddenTacticCount(): number {
    return this.hiddenTacticIds.size;
  }

  private customTechToTechnique(ct: CustomTechnique): Technique {
    return {
      id: `custom--${ct.id}`,
      attackId: ct.attackId,
      name: ct.name,
      description: ct.description,
      url: '',
      tacticShortnames: ct.tacticShortnames,
      isSubtechnique: false,
      parentId: null,
      subtechniques: [],
      mitigationCount: 0,
      platforms: ct.platforms,
      dataSources: ct.dataSources,
      detectionText: '',
      defenseBypassed: [],
      permissionsRequired: [],
      effectivePermissions: [],
      systemRequirements: [],
      impactType: [],
      remoteSupport: false,
      capecIds: [],
    };
  }

  isCustomTechnique(tech: Technique): boolean {
    return tech.id.startsWith('custom--') || this.customTechniqueIds.has(tech.attackId);
  }

  private rebuildSortedColumns(): void {
    if (!this.domain) return;
    this.sortedColumns = this.domain.tacticColumns
      .filter((col) => !this.hiddenTacticIds.has(col.tactic.id))
      .map((col) => {
        let techniques = [...col.techniques];
        if (this.hasPlatformFilter && this.platformIds) {
          techniques = techniques.filter((t) => this.platformIds!.has(t.id));
        }
        if (this.hasDataSourceFilter && this.dataSourceIds) {
          techniques = techniques.filter((t) => this.dataSourceIds!.has(t.id) || t.subtechniques.some((s) => this.dataSourceIds!.has(s.id)));
        }
        // Append custom techniques for this tactic
        const tacticShortname = col.tactic.shortname;
        const customForTactic = this.customTechniques
          .filter(ct => ct.tacticShortnames.includes(tacticShortname))
          .map(ct => this.customTechToTechnique(ct));
        techniques = [...techniques, ...customForTactic];
        if (this.sortMode === 'coverage') {
          techniques.sort((a, b) => a.mitigationCount - b.mitigationCount || a.attackId.localeCompare(b.attackId));
        }
        return { ...col, techniques };
      });
  }

  expandAll(): void {
    for (const col of this.sortedColumns) {
      for (const t of col.techniques) {
        if (t.subtechniques.length > 0) this.expandedParents.add(t.id);
      }
    }
    this.cdr.markForCheck();
  }

  collapseAll(): void {
    this.expandedParents.clear();
    this.cdr.markForCheck();
  }

  onTechniqueClick(technique: Technique): void {
    if (this.multiSelectMode) {
      this.toggleCellSelection(technique);
    } else {
      this.filterService.selectTechnique(this.selectedTechniqueId === technique.id ? null : technique);
    }
  }

  toggleMultiSelectMode(): void {
    this.multiSelectMode = !this.multiSelectMode;
    if (!this.multiSelectMode) this.selectedTechIds.clear();
    this.cdr.markForCheck();
  }

  toggleCellSelection(tech: Technique): void {
    if (this.selectedTechIds.has(tech.id)) {
      this.selectedTechIds.delete(tech.id);
    } else {
      this.selectedTechIds.add(tech.id);
    }
    this.cdr.markForCheck();
  }

  selectAllVisible(): void {
    for (const col of this.sortedColumns) {
      for (const tech of col.techniques) {
        if (!this.isTechniqueHidden(tech)) this.selectedTechIds.add(tech.id);
        if (this.isParentExpanded(tech.id)) {
          for (const sub of tech.subtechniques) {
            if (!this.isSubHidden(sub)) this.selectedTechIds.add(sub.id);
          }
        }
      }
    }
    this.cdr.markForCheck();
  }

  bulkSetStatus(status: ImplStatus | null): void {
    for (const techId of this.selectedTechIds) {
      const tech = this.domain?.techniques.find(t => t.id === techId);
      if (!tech) continue;
      const mits = this.domain!.mitigationsByTechnique.get(techId) ?? [];
      for (const mr of mits) {
        this.implService.setStatus(mr.mitigation.id, status);
      }
    }
    this.selectedTechIds.clear();
    this.cdr.markForCheck();
  }

  clearSelection(): void {
    this.selectedTechIds.clear();
    if (this.multiSelectMode) this.multiSelectMode = false;
    this.cdr.markForCheck();
  }

  bulkAddToWatchlist(): void {
    for (const techId of this.selectedTechIds) {
      const tech = this.domain?.techniques.find(t => t.id === techId);
      if (tech) this.watchlistService.add(tech);
    }
    this.selectedTechIds.clear();
    this.cdr.markForCheck();
  }

  bulkAddTag(tag: string): void {
    if (!tag.trim()) return;
    for (const techId of this.selectedTechIds) {
      this.taggingService.addTag(techId, tag.trim());
    }
    this.selectedTechIds.clear();
    this.cdr.markForCheck();
  }

  toggleExpand(techniqueId: string, event: Event): void {
    event.stopPropagation();
    if (this.expandedParents.has(techniqueId)) this.expandedParents.delete(techniqueId);
    else this.expandedParents.add(techniqueId);
    this.cdr.markForCheck();
  }

  hideTactic(tacticId: string, event: Event): void {
    event.stopPropagation();
    this.filterService.toggleTacticVisibility(tacticId);
  }

  toggleColumnMenu(event: MouseEvent): void {
    event.stopPropagation();
    this.showColumnMenu = !this.showColumnMenu;
    this.cdr.markForCheck();
  }

  toggleTacticFromMenu(tacticId: string): void {
    this.filterService.toggleTacticVisibility(tacticId);
  }

  showAllTactics(): void {
    this.filterService.clearHiddenTactics();
  }

  @HostListener('document:click')
  onDocumentClick(): void {
    if (this.showColumnMenu) {
      this.showColumnMenu = false;
      this.cdr.markForCheck();
    }
  }

  onTacticHeaderClick(col: TacticColumn, event: MouseEvent): void {
    event.stopPropagation(); // prevent document:click from immediately closing the popup
    // Collect all techniques (parents + subs) for the tactic from the original domain column
    const domainCol = this.domain.tacticColumns.find((c) => c.tactic.id === col.tactic.id);
    const parentTechniques = domainCol?.techniques ?? [];
    const allTechniques: Technique[] = [];
    for (const t of parentTechniques) {
      allTechniques.push(t);
      for (const sub of t.subtechniques) {
        allTechniques.push(sub);
      }
    }
    this.tacticClicked.emit({ tactic: col.tactic, techniques: allTechniques, event });
  }

  restoreAllTactics(): void {
    this.filterService.clearHiddenTactics();
  }

  isExpanded(id: string): boolean { return this.expandedParents.has(id); }

  toggleParent(techId: string): void {
    if (this.expandedParents.has(techId)) {
      this.expandedParents.delete(techId);
    } else {
      this.expandedParents.add(techId);
    }
    this.cdr.markForCheck();
  }

  isParentExpanded(techId: string): boolean {
    return this.expandedParents.has(techId);
  }

  onCellMouseEnter(tech: Technique, event: MouseEvent): void {
    if (!this.tooltip) return;
    const mitCount = this.domain.mitigationsByTechnique.get(tech.id)?.length ?? 0;
    const groupCount = this.domain.groupsByTechnique.get(tech.id)?.length ?? 0;
    this.tooltip.show(tech, mitCount, groupCount, event.clientX, event.clientY);
  }

  onCellMouseLeave(): void {
    if (!this.tooltip) return;
    this.tooltip.hide();
  }

  get visibleTechniqueIds(): string[] {
    const ids: string[] = [];
    for (const col of this.sortedColumns) {
      for (const tech of col.techniques) {
        if (this.isTechniqueHidden(tech)) continue;
        ids.push(tech.id);
        if (this.expandedParents.has(tech.id)) {
          for (const sub of tech.subtechniques) {
            if (!this.isSubHidden(sub)) {
              ids.push(sub.id);
            }
          }
        }
      }
    }
    return ids;
  }

  isHighlighted(t: Technique): boolean {
    // CVE filter always takes priority when active
    if (this.cveTechniqueIds.size > 0) {
      return this.cveTechniqueIds.has(t.attackId) || t.subtechniques.some((s) => this.cveTechniqueIds.has(s.attackId));
    }
    if (this.hasTechniqueSearch) {
      return this.matchedIds.has(t.id) || t.subtechniques.some((s) => this.matchedIds.has(s.id));
    }
    if (this.hasThreatFilter) {
      return this.threatGroupIds.has(t.id) || t.subtechniques.some((s) => this.threatGroupIds.has(s.id));
    }
    if (this.hasSoftwareFilter) {
      return this.softwareFilterIds.has(t.id) || t.subtechniques.some((s) => this.softwareFilterIds.has(s.id));
    }
    if (this.hasCampaignFilter) {
      return this.campaignFilterIds.has(t.id) || t.subtechniques.some((s) => this.campaignFilterIds.has(s.id));
    }
    if (this.hasMitigationFilter) {
      return this.highlightedIds.has(t.id) || t.subtechniques.some((s) => this.highlightedIds.has(s.id));
    }
    return false;
  }

  getKevScore(t: Technique): number {
    return this.kevScores.get(t.attackId) ?? 0;
  }

  getD3fendScore(t: Technique): number {
    return this.d3fendScoreMap.get(t.id) ?? 0;
  }

  getAtomicScore(t: Technique): number {
    return this.atomicScoreMap.get(t.id) ?? 0;
  }

  getEngageScore(t: Technique): number {
    return this.engageScoreMap.get(t.id) ?? 0;
  }

  getCarScore(t: Technique): number {
    return this.carScoreMap.get(t.id) ?? 0;
  }

  getCriScore(t: Technique): number {
    return this.criScoreMap.get(t.id) ?? 0;
  }

  getCveScore(t: Technique): number {
    return this.cveScoreMap.get(t.attackId) ?? 0;
  }

  getDetectionScore(t: Technique): number {
    return this.detectionScoreMap.get(t.attackId) ?? 0;
  }

  getUnifiedScore(t: Technique): number {
    return this.unifiedScoreMap.get(t.attackId) ?? 0;
  }

  getSigmaScore(t: Technique): number {
    return this.sigmaScoreMap.get(t.attackId) ?? 0;
  }

  getNistScore(t: Technique): number {
    return this.nistScoreMap.get(t.attackId) ?? 0;
  }

  getVerisScore(t: Technique): number {
    return this.verisScoreMap.get(t.attackId) ?? 0;
  }

  getEpssScore(t: Technique): number {
    return this.epssScoreMap.get(t.attackId) ?? 0;
  }

  getElasticScore(t: Technique): number {
    return this.elasticScoreMap.get(t.attackId) ?? 0;
  }

  getSplunkScore(t: Technique): number {
    return this.splunkScoreMap.get(t.attackId) ?? 0;
  }

  getIntelScore(t: Technique): number {
    return this.intelScoreMap.get(t.attackId) ?? 0;
  }

  getM365Score(t: Technique): number {
    return this.m365ScoreMap.get(t.attackId) ?? 0;
  }

  getMyExposureScore(t: Technique): number {
    return this.myExposureScoreMap.get(t.attackId) ?? 0;
  }

  getWazuhScore(t: Technique): number {
    return this.wazuhScoreMap.get(t.attackId) ?? 0;
  }

  getCsaCcmScore(t: Technique): number {
    return this.csaCcmScoreMap.get(t.attackId) ?? 0;
  }

  getM365ControlsScore(t: Technique): number {
    return this.m365ControlsScoreMap.get(t.attackId) ?? 0;
  }

  getKillChainScore(t: Technique): number {
    return this.killChainScoreMap.get(t.attackId) ?? 0;
  }

  getPocScore(t: Technique): number {
    return this.pocScoreMap.get(t.attackId) ?? 0;
  }

  getFrequencyScore(t: Technique): number {
    return this.frequencyMap.get(t.id) ?? 0;
  }

  private getRelativeHeatColor(score: number, max: number, zero: string, colors: [string, string, string, string]): string {
    if (score === 0) return zero;
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return colors[3];
    if (ratio >= 0.5) return colors[2];
    if (ratio >= 0.25) return colors[1];
    return colors[0];
  }

  private getThresholdHeatColor(score: number, zero: string, stops: Array<{ limit: number; color: string }>): string {
    if (score === 0) return zero;
    for (const stop of stops) {
      if (score <= stop.limit) return stop.color;
    }
    return stops[stops.length - 1]?.color ?? zero;
  }

  /** Returns the minimap cell background color for the currently active heatmap mode. */
  getCellColor(tech: Technique): string {
    switch (this.heatmapMode) {
      case 'coverage': {
        const colors = this.settingsService.getCoverageColors();
        const count = Math.min(tech.mitigationCount, colors.length - 1);
        return colors[count < 0 ? 0 : count];
      }
      case 'frequency':
        return this.getRelativeHeatColor(this.getFrequencyScore(tech), this.maxFrequencyScore, '#1c2a38', ['#1e3a5f', '#1565c0', '#0ea5e9', '#38bdf8']);
      case 'status': {
        const status = this.getTechniqueImplStatus(tech);
        if (status === 'implemented') return '#4caf50';
        if (status === 'in-progress') return '#ff9800';
        if (status === 'planned') return '#2196f3';
        if (status === 'not-started') return '#e53935';
        return '#90a4ae';
      }
      case 'controls': {
        const status = this.getControlStatus(tech);
        if (status === 'covered') return '#00c853';
        if (status === 'planned') return '#1565c0';
        return '#1c2b30';
      }
      case 'exposure':
        return this.getRelativeHeatColor(this.getExposureScore(tech), this.maxExposure, '#eceff1', ['#ffb74d', '#ff7043', '#e53935', '#b71c1c']);
      case 'software':
        return this.getRelativeHeatColor(this.getSoftwareScore(tech), this.maxSoftware, '#eceff1', ['#ffb74d', '#ff7043', '#e53935', '#b71c1c']);
      case 'campaign':
        return this.getRelativeHeatColor(this.getCampaignScore(tech), this.maxCampaign, '#eceff1', ['#ce93d8', '#ab47bc', '#7b1fa2', '#4a148c']);
      case 'risk':
        return this.getRelativeHeatColor(this.getRiskScore(tech), this.maxRisk, '#eceff1', ['#ff7043', '#e53935', '#b71c1c', '#4a0000']);
      case 'kev':
        return this.getRelativeHeatColor(this.getKevScore(tech), this.maxKev, '#eceff1', ['#ffd54f', '#ffb300', '#ff7043', '#d32f2f']);
      case 'd3fend':
        return this.getRelativeHeatColor(this.getD3fendScore(tech), this.maxD3fend, '#d32f2f', ['#e64a19', '#f57c00', '#1565c0', '#1a6fba']);
      case 'atomic':
        return this.getRelativeHeatColor(this.getAtomicScore(tech), this.maxAtomic, '#1a1a0a', ['#6d3a10', '#c06020', '#e08030', '#f0a040']);
      case 'engage':
        return this.getRelativeHeatColor(this.getEngageScore(tech), this.maxEngageScore, '#0a1a0a', ['#4a3a10', '#906020', '#c08030', '#f0a040']);
      case 'car':
        return this.getRelativeHeatColor(this.getCarScore(tech), this.maxCarScore, '#0a0a1a', ['#0d2a4a', '#1a4a7a', '#2a6aaa', '#58a6ff']);
      case 'cve':
        return this.getRelativeHeatColor(this.getCveScore(tech), this.maxCveScore, '#1a2332', ['#4a1a4a', '#7b2d8b', '#a855b5', '#d946ef']);
      case 'detection':
        return this.getRelativeHeatColor(this.getDetectionScore(tech), this.maxDetectionScore, '#1a2332', ['#0c2d2d', '#0d5e5e', '#0e8a7a', '#10b981']);
      case 'cri':
        return this.getRelativeHeatColor(this.getCriScore(tech), this.maxCriScore, '#1a0a2e', ['#ce93d8', '#ab47bc', '#8e24aa', '#6a1b9a']);
      case 'unified':
        return this.getThresholdHeatColor(this.getUnifiedScore(tech), '#7f0000', [
          { limit: 15, color: '#7f0000' },
          { limit: 30, color: '#c62828' },
          { limit: 50, color: '#e65100' },
          { limit: 65, color: '#f9a825' },
          { limit: 80, color: '#558b2f' },
          { limit: Number.POSITIVE_INFINITY, color: '#1b5e20' },
        ]);
      case 'sigma':
        return this.getRelativeHeatColor(this.getSigmaScore(tech), this.maxSigmaScore, '#0a1a1a', ['#0d4a3a', '#0d7a5e', '#0ea87a', '#10b981']);
      case 'nist':
        return this.getRelativeHeatColor(this.getNistScore(tech), this.maxNistScore, '#0d1b2a', ['#1a4a7a', '#1565c0', '#1976d2', '#42a5f5']);
      case 'veris':
        return this.getRelativeHeatColor(this.getVerisScore(tech), this.maxVerisScore, '#1a0a0a', ['#5c1a1a', '#a83232', '#d64e4e', '#f28b8b']);
      case 'epss': {
        const epss = this.getEpssScore(tech);
        if (epss === 0) return '#1a1a0a';
        if (epss < 0.01) return '#5c4a00';
        if (epss < 0.05) return '#c17900';
        if (epss < 0.2) return '#e65100';
        return '#d32f2f';
      }
      case 'elastic':
        return this.getRelativeHeatColor(this.getElasticScore(tech), this.maxElasticScore, '#0a1a0a', ['#1a3a1a', '#2a6a2a', '#3a9a3a', '#4caf50']);
      case 'splunk':
        return this.getRelativeHeatColor(this.getSplunkScore(tech), this.maxSplunkScore, '#1a0a0a', ['#4a2a0a', '#7a4a1a', '#c06a20', '#ff9800']);
      case 'intelligence':
        return this.getRelativeHeatColor(this.getIntelScore(tech), this.maxIntelScore, '#0a1a2e', ['#1a3a7a', '#5a2d8b', '#8b1a5a', '#d32f2f']);
      case 'm365':
        return this.getRelativeHeatColor(this.getM365Score(tech), this.maxM365Score, '#0a1a2e', ['#003a6e', '#005a9e', '#0078d4', '#4ca6ff']);
      case 'my-exposure':
        return this.getRelativeHeatColor(this.getMyExposureScore(tech), this.maxMyExposure, '#1a2332', ['#ff9800', '#f44336', '#d32f2f', '#b71c1c']);
      case 'wazuh':
        return this.getRelativeHeatColor(this.getWazuhScore(tech), this.maxWazuhScore, '#0a1520', ['#0d3a5c', '#1a6fa0', '#2196c8', '#3aabe0']);
      case 'csa-ccm':
        return this.getRelativeHeatColor(this.getCsaCcmScore(tech), this.maxCsaCcmScore, '#0a1a10', ['#1a4a2a', '#2a7a3a', '#3aaa4a', '#4cce5a']);
      case 'm365-controls':
        return this.getRelativeHeatColor(this.getM365ControlsScore(tech), this.maxM365ControlsScore, '#0a1028', ['#0a3068', '#0050a8', '#0070e8', '#40a0ff']);
      case 'kill-chain':
        return this.getRelativeHeatColor(this.getKillChainScore(tech), this.maxKillChainScore, '#0e0a1a', ['#2d1a5e', '#5a2d8b', '#7b3faa', '#9c5cc5']);
      case 'poc-exploits':
        return this.getRelativeHeatColor(this.getPocScore(tech), this.maxPocScore, '#1a0e0a', ['#5c2a0a', '#a84a1a', '#d96a2a', '#ff8c3a']);
      default:
        return '#1a2a3a';
    }
  }

  isDimmed(t: Technique): boolean {
    if (this.implStatusFilter && this.isImplFiltered(t)) return true;
    if (this.hasPlatformFilter && this.platformIds && !this.platformIds.has(t.id)) return true;
    if (this.platformMultiFilter.size > 0) {
      const techMatches = t.platforms.some(p => this.platformMultiFilter.has(p));
      const subMatches = t.subtechniques.some(s => s.platforms.some(p => this.platformMultiFilter.has(p)));
      if (!techMatches && !subMatches) return true;
    }
    if (this.hasDataSourceFilter && this.dataSourceIds && !this.dataSourceIds.has(t.id) && !t.subtechniques.some((s) => this.dataSourceIds!.has(s.id))) return true;
    if (this.dimUncovered && t.mitigationCount === 0) return true;
    if (this.hasTechniqueSearch) {
      if (this.matchedIds.has(t.id)) return false;
      if (t.subtechniques.some((s) => this.matchedIds.has(s.id))) return false;
      return true;
    }
    if (this.hasThreatFilter) {
      if (this.threatGroupIds.has(t.id)) return false;
      if (t.subtechniques.some((s) => this.threatGroupIds.has(s.id))) return false;
      return true;
    }
    if (this.hasSoftwareFilter) {
      if (this.softwareFilterIds.has(t.id)) return false;
      if (t.subtechniques.some((s) => this.softwareFilterIds.has(s.id))) return false;
      return true;
    }
    if (this.hasCampaignFilter) {
      if (this.campaignFilterIds.has(t.id)) return false;
      if (t.subtechniques.some((s) => this.campaignFilterIds.has(s.id))) return false;
      return true;
    }
    if (this.hasMitigationFilter) {
      if (this.highlightedIds.has(t.id)) return false;
      if (t.subtechniques.some((s) => this.highlightedIds.has(s.id))) return false;
      return true;
    }
    return false;
  }

  getExposureScore(t: Technique): number {
    return this.exposureScores.get(t.id) ?? 0;
  }

  getSoftwareScore(t: Technique): number {
    return this.softwareScores.get(t.id) ?? 0;
  }

  getCampaignScore(t: Technique): number {
    return this.campaignScores.get(t.id) ?? 0;
  }

  getRiskScore(t: Technique): number {
    return this.riskScores.get(t.id) ?? 0;
  }

  getTechniqueImplStatus(t: Technique): ImplStatus | null {
    return this.techniqueImplStatus.get(t.id) ?? null;
  }

  isImplFiltered(t: Technique): boolean {
    if (!this.implStatusFilter) return false;
    const status = this.techniqueImplStatus.get(t.id) ?? null;
    return status !== this.implStatusFilter;
  }

  isSelected(t: Technique): boolean { return this.selectedTechniqueId === t.id; }

  getControlStatus(t: Technique): 'covered' | 'planned' | 'none' {
    if (this.controlsCoveredIds.has(t.id)) return 'covered';
    if (this.controlsPlannedIds.has(t.id)) return 'planned';
    return 'none';
  }

  tacticCoverage(col: TacticColumn): number {
    const src = this.domain.tacticColumns.find((c) => c.tactic.id === col.tactic.id);
    const techs = src?.techniques ?? [];
    const total = techs.length;
    if (!total) return 0;
    return Math.round((techs.filter((t) => t.mitigationCount > 0).length / total) * 100);
  }

  trackByTacticId(_: number, col: TacticColumn): string { return col.tactic.id; }
  trackByTechniqueId(_: number, tech: Technique): string { return tech.id; }

  isTechniqueHidden(tech: Technique): boolean {
    if (!this.searchFilterMode) return false;
    if (this.hasTechniqueSearch) {
      return !this.matchedIds.has(tech.id) && !(tech.subtechniques?.some((s) => this.matchedIds.has(s.id)));
    }
    if (this.searchQuery) {
      return !this.matchingIds.has(tech.id) && !(tech.subtechniques?.some((s) => this.matchingIds.has(s.id)));
    }
    return false;
  }

  isSubHidden(sub: Technique): boolean {
    if (!this.searchFilterMode) return false;
    if (this.hasTechniqueSearch) return !this.matchedIds.has(sub.id);
    if (this.searchQuery) return !this.matchingIds.has(sub.id);
    return false;
  }

  isColumnHidden(col: TacticColumn): boolean {
    if (!this.searchFilterMode) return false;
    if (!this.hasTechniqueSearch && !this.searchQuery) return false;
    return col.techniques.every((tech) => this.isTechniqueHidden(tech));
  }

  toggleSearchFilterMode(): void {
    this.filterService.toggleSearchFilterMode();
  }
}

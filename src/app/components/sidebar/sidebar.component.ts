import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

interface GraphNode { id: string; label: string; type: 'technique' | 'mitigation' | 'group'; x: number; y: number; }
interface GraphLink { source: string; target: string; type: string; }
interface RelGraphData { nodes: GraphNode[]; links: GraphLink[]; }
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Technique } from '../../models/technique';
import { Mitigation, MitigationRelationship } from '../../models/mitigation';
import { ThreatGroup } from '../../models/group';
import { AttackSoftware } from '../../models/software';
import { ProcedureExample } from '../../models/procedure';
import { MitreDataComponent } from '../../models/datasource';
import { Campaign } from '../../models/campaign';
import { AttackTextPipe } from '../../pipes/attack-text.pipe';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS, IMPL_STATUS_COLORS } from '../../services/implementation.service';
import { DocumentationService, MitigationDoc } from '../../services/documentation.service';
import { D3fendService, D3fendTechnique } from '../../services/d3fend.service';
import { EngageService, EngageActivity } from '../../services/engage.service';
import { CARService, CarAnalytic } from '../../services/car.service';
import { AtomicService, AtomicTest, AtomicLiveTest } from '../../services/atomic.service';
import { TaggingService } from '../../services/tagging.service';
import { AttackCveService, CveAttackMapping } from '../../services/attack-cve.service';
import { NistMappingService, NistControl } from '../../services/nist-mapping.service';
import { CisControlsService, CisControl } from '../../services/cis-controls.service';
import { CloudControlsService, CloudControl } from '../../services/cloud-controls.service';
import { VerisService, VerisAction } from '../../services/veris.service';
import { CriProfileService, CriControl } from '../../services/cri-profile.service';
import { CapecService, CapecEntry } from '../../services/capec.service';
import { CweService } from '../../services/cwe.service';
import { SettingsService } from '../../services/settings.service';
import { CustomMitigationService, CustomMitigation } from '../../services/custom-mitigation.service';
import { AnnotationService, TechniqueAnnotation } from '../../services/annotation.service';
import { WatchlistService } from '../../services/watchlist.service';
import { MispService, MispGalaxyCluster, MispTag } from '../../services/misp.service';
import { SigmaService } from '../../services/sigma.service';
import { OpenCtiService, OpenCtiIndicator, OpenCtiThreatActor } from '../../services/opencti.service';
import { EpssService } from '../../services/epss.service';
import { ExploitdbService } from '../../services/exploitdb.service';
import { NucleiService } from '../../services/nuclei.service';
import { CustomTechniqueService } from '../../services/custom-technique.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, FormsModule, AttackTextPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent implements OnInit, OnDestroy {
  technique: Technique | null = null;
  mitigations: MitigationRelationship[] = [];
  parentMitigations: MitigationRelationship[] = [];
  threatGroups: ThreatGroup[] = [];
  softwareList: AttackSoftware[] = [];
  campaigns: Campaign[] = [];
  procedures: ProcedureExample[] = [];
  dataComponents: MitreDataComponent[] = [];
  open = false;
  isCustomTechnique = false;
  mitSearchText = '';
  showRelGraph = false;
  showDetection = false;
  showProcedures = false;
  showSubtechniques = false;
  descExpanded = false;
  procedureLimit = 5;
  statusLabels = IMPL_STATUS_LABELS;
  statusColors = IMPL_STATUS_COLORS;
  readonly statusOptions: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
  implStatusMap = new Map<string, ImplStatus>();

  // D3FEND countermeasures
  d3fendMeasures: D3fendTechnique[] = [];

  // Engage activities
  engageActivities: EngageActivity[] = [];

  // CAR analytics
  carAnalytics: CarAnalytic[] = [];

  // Atomic Red Team tests
  atomicTests: AtomicTest[] = [];
  atomicLiveTests: AtomicLiveTest[] = [];  // fetched from GitHub YAML
  atomicLiveCount = 0;   // live count from Navigator layer (may exceed hardcoded detail list)
  atomicGitHubUrl = 'https://github.com/redcanaryco/atomic-red-team';
  atomicFetching = false;

  // MISP Galaxy
  mispCluster: MispGalaxyCluster | null = null;
  mispTagCopied = false;

  // Collapsible sections
  collapsedSections = new Set<string>();

  toggleSection(name: string): void {
    if (this.collapsedSections.has(name)) {
      this.collapsedSections.delete(name);
    } else {
      this.collapsedSections.add(name);
    }
    this.cdr.markForCheck();
  }

  isSectionCollapsed(name: string): boolean {
    return this.collapsedSections.has(name);
  }

  collapseAll(): void {
    const sections = [
      'annotation', 'datasources', 'subtechniques', 'detection', 'datacomponents',
      'procedures', 'cve', 'nist', 'cloud', 'veris', 'cri', 'capec',
      'exploitdb', 'nuclei', 'tags', 'notes', 'threats', 'software',
      'campaigns', 'd3fend', 'engage', 'car', 'atomic', 'misp', 'opencti',
      'custom', 'mitigations', 'relgraph',
    ];
    for (const s of sections) this.collapsedSections.add(s);
    this.cdr.markForCheck();
  }

  expandRelevant(): void {
    this.collapsedSections.clear();
    // Collapse sections that have no data
    if (this.mitigations.length === 0 && this.parentMitigations.length === 0) this.collapsedSections.add('mitigations');
    if (this.threatGroups.length === 0) this.collapsedSections.add('threats');
    if (this.softwareList.length === 0) this.collapsedSections.add('software');
    if (this.campaigns.length === 0) this.collapsedSections.add('campaigns');
    if (this.d3fendMeasures.length === 0) this.collapsedSections.add('d3fend');
    if (this.engageActivities.length === 0) this.collapsedSections.add('engage');
    if (this.carAnalytics.length === 0) this.collapsedSections.add('car');
    if (this.atomicTests.length === 0 && this.atomicLiveCount === 0) this.collapsedSections.add('atomic');
    if (this.cveExposures.length === 0) this.collapsedSections.add('cve');
    if (this.nistControls.length === 0) this.collapsedSections.add('nist');
    if (this.capecEntries.length === 0) this.collapsedSections.add('capec');
    if (this.procedures.length === 0) this.collapsedSections.add('procedures');
    if (this.verisActions.length === 0) this.collapsedSections.add('veris');
    if (this.criControls.length === 0) this.collapsedSections.add('cri');
    if (this.exploitCount === 0) this.collapsedSections.add('exploitdb');
    if (this.nucleiCount === 0) this.collapsedSections.add('nuclei');
    if (!this.mispCluster) this.collapsedSections.add('misp');
    if (this.customMitigations.length === 0) this.collapsedSections.add('custom');
    this.cdr.markForCheck();
  }

  // Technique completeness score (0-100)
  completenessScore = 0;

  computeCompleteness(): void {
    if (!this.technique) { this.completenessScore = 0; return; }
    let score = 0;
    if (this.mitigations.length > 0 || this.parentMitigations.length > 0) score += 15;
    if (this.cveExposures.length > 0) score += 10;
    if (this.nistControls.length > 0) score += 10;
    if (this.d3fendMeasures.length > 0) score += 10;
    if (this.atomicTests.length > 0 || this.atomicLiveCount > 0) score += 10;
    if (this.sigmaService.getRuleCount(this.technique.attackId) > 0) score += 10;
    if (this.threatGroups.length > 0) score += 5;
    if (this.softwareList.length > 0) score += 5;
    if (this.capecEntries.length > 0) score += 5;
    if (this.cisControls.length > 0 || this.cloudControls.length > 0) score += 5;
    if (this.engageActivities.length > 0) score += 5;
    if (this.carAnalytics.length > 0) score += 5;
    if (this.dataComponents.length > 0) score += 5;
    this.completenessScore = Math.min(score, 100);
  }

  // Signal summary pills
  signals: { icon: string; label: string; value: string; color: string }[] = [];

  // CVE Exposure
  cveExposures: CveAttackMapping[] = [];
  showAllCves = false;

  // NIST 800-53 Rev5 Controls
  nistControls: NistControl[] = [];
  showAllNist = false;

  // CIS Controls & Cloud Controls
  cisControls: CisControl[] = [];
  cloudControls: CloudControl[] = [];
  showAllCloud = false;

  // VERIS Incident Actions
  verisActions: VerisAction[] = [];
  showAllVeris = false;

  // CRI Profile Controls
  criControls: CriControl[] = [];
  showAllCri = false;

  // CAPEC attack patterns
  capecEntries: CapecEntry[] = [];
  showAllCapec = false;

  // Custom Mitigations
  customMitigations: CustomMitigation[] = [];

  // OpenCTI indicators
  openctiIndicators: OpenCtiIndicator[] = [];
  openctiActors: OpenCtiThreatActor[] = [];
  openctiLoading = false;
  openctiError = '';

  // EPSS average for the selected technique's CVEs
  epssAvg: number | null = null;

  // ExploitDB exploit count for selected technique
  exploitCount = 0;

  // Nuclei template count for selected technique
  nucleiCount = 0;

  /** Unified list with a consistent 'provider' field for template use. */
  get allCloudControls(): { id: string; description: string; provider: string; mappingType: string }[] {
    const cis = this.cisControls.map(c => ({ id: c.id, description: c.description, provider: 'cis', mappingType: c.mappingType }));
    const cloud = this.cloudControls.map(c => ({ id: c.id, description: c.description, provider: c.provider, mappingType: c.mappingType }));
    return [...cis, ...cloud];
  }

  get visibleCloudControls(): { id: string; description: string; provider: string; mappingType: string }[] {
    return this.showAllCloud ? this.allCloudControls : this.allCloudControls.slice(0, 5);
  }

  // Annotation state
  annotation: TechniqueAnnotation | undefined = undefined;
  annotationNote = '';
  annotationColor = 'default';
  annotationPinned = false;

  // Tagging state
  currentTags: string[] = [];
  allUsedTags: string[] = [];
  newTagInput = '';
  presetTags: string[] = [];

  // Documentation state
  techniqueNote = '';
  expandedDocs = new Set<string>();
  expandedMitDescs = new Set<string>();
  expandedRelDescs = new Set<string>();
  mitDocs = new Map<string, MitigationDoc>();
  editingDocs = new Map<string, MitigationDoc>();

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private docService: DocumentationService,
    private d3fendService: D3fendService,
    private engageService: EngageService,
    private carService: CARService,
    private atomicService: AtomicService,
    private taggingService: TaggingService,
    private attackCveService: AttackCveService,
    private nistMappingService: NistMappingService,
    private cisControlsService: CisControlsService,
    private cloudControlsService: CloudControlsService,
    private verisService: VerisService,
    private criProfileService: CriProfileService,
    private capecService: CapecService,
    private settingsService: SettingsService,
    private customMitigationService: CustomMitigationService,
    private annotationService: AnnotationService,
    private watchlistService: WatchlistService,
    private mispService: MispService,
    private sigmaService: SigmaService,
    public openctiService: OpenCtiService,
    public cweService: CweService,
    private epssService: EpssService,
    private exploitdbService: ExploitdbService,
    private nucleiService: NucleiService,
    private customTechniqueService: CustomTechniqueService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.selectedTechnique$.subscribe((tech) => {
        this.technique = tech;
        this.open = tech !== null;
        this.isCustomTechnique = tech !== null && (
          tech.id.startsWith('custom--') ||
          this.customTechniqueService.getAll().some(ct => ct.attackId === tech.attackId)
        );
        this.mitigations = tech ? this.dataService.getMitigationsForTechnique(tech.id) : [];
        this.parentMitigations = [];
        if (tech?.parentId) {
          const parentMits = this.dataService.getMitigationsForTechnique(tech.parentId);
          const directIds = new Set(this.mitigations.map(r => r.mitigation.id));
          this.parentMitigations = parentMits.filter(r => !directIds.has(r.mitigation.id));
        }
        this.threatGroups = tech ? this.dataService.getGroupsForTechnique(tech.id) : [];
        this.softwareList = tech ? this.dataService.getSoftwareForTechnique(tech.id) : [];
        this.campaigns = tech ? this.dataService.getCampaignsForTechnique(tech.id) : [];
        this.procedures = tech ? this.dataService.getProceduresForTechnique(tech.id) : [];
        this.dataComponents = tech ? this.dataService.getDataComponentsForTechnique(tech.id) : [];
        this.d3fendMeasures = tech ? this.d3fendService.getCountermeasures(tech.attackId) : [];
        this.engageActivities = tech ? this.engageService.getActivities(tech.attackId) : [];
        this.carAnalytics = tech ? this.carService.getAnalytics(tech.attackId) : [];
        this.atomicTests = tech ? this.atomicService.getTests(tech.attackId) : [];
        this.atomicLiveCount = tech ? this.atomicService.getTestCount(tech.attackId) : 0;
        this.atomicLiveTests = [];
        this.atomicFetching = !!tech;
        this.mispCluster = tech ? this.mispService.getCluster(tech.attackId) : null;
        this.atomicGitHubUrl = tech
          ? `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${tech.attackId}/${tech.attackId}.md`
          : 'https://github.com/redcanaryco/atomic-red-team';
        if (tech) {
          this.subs.add(
            this.atomicService.fetchLiveTests(tech.attackId, 5).subscribe(liveTests => {
              this.atomicLiveTests = liveTests;
              this.atomicFetching = false;
              this.cdr.markForCheck();
            }),
          );
        }
        this.cveExposures = tech ? this.attackCveService.getCvesForTechnique(tech.attackId).slice(0, 20) : [];
        this.showAllCves = false;
        this.nistControls = tech ? this.nistMappingService.getControlsForTechnique(tech.attackId) : [];
        this.showAllNist = false;
        this.cisControls = tech ? this.cisControlsService.getControlsForTechnique(tech.attackId) : [];
        this.cloudControls = tech ? this.cloudControlsService.getControlsForTechnique(tech.attackId) : [];
        this.showAllCloud = false;
        this.verisActions = tech ? this.verisService.getActionsForTechnique(tech.attackId) : [];
        this.showAllVeris = false;
        this.criControls = tech ? this.criProfileService.getControlsForTechnique(tech.attackId) : [];
        this.showAllCri = false;
        this.capecEntries = tech ? this.capecService.getCapecForTechnique(tech.attackId) : [];
        this.showAllCapec = false;
        this.customMitigations = tech ? this.customMitigationService.getForTechnique(tech.attackId) : [];
        this.techniqueNote = tech ? this.docService.getTechNote(tech.id) : '';
        this.currentTags = tech ? this.taggingService.getTags(tech.id) : [];
        this.allUsedTags = this.taggingService.getAllUsedTags();
        this.presetTags = this.taggingService.presetTags;
        const ann = tech ? this.annotationService.getAnnotation(tech.attackId) : undefined;
        this.annotation = ann;
        this.annotationNote = ann?.note ?? '';
        this.annotationColor = ann?.color ?? 'default';
        this.annotationPinned = ann?.isPinned ?? false;
        this.mitSearchText = '';
        this.showRelGraph = false;
        this._relGraphData = null;
        this.showDetection = false;
        this.showProcedures = false;
        this.showSubtechniques = false;
        this.descExpanded = false;
        this.procedureLimit = 5;
        this.expandedDocs.clear();
        this.expandedMitDescs.clear();
        this.expandedRelDescs.clear();
        this.editingDocs.clear();
        this.epssAvg = null;
        this.exploitCount = tech ? this.exploitdbService.getExploitCount(tech.attackId) : 0;
        this.nucleiCount = tech ? this.nucleiService.getTemplateCount(tech.attackId) : 0;
        this.signals = tech ? this.getSignals(tech) : [];
        this.computeCompleteness();
        // OpenCTI — load if connected
        this.openctiIndicators = [];
        this.openctiActors = [];
        this.openctiError = '';
        if (tech && this.openctiService.getConfig().connected) {
          this.openctiLoading = true;
          this.subs.add(
            this.openctiService.getIndicatorsForTechnique(tech.attackId).subscribe({
              next: (inds) => {
                this.openctiIndicators = inds;
                this.openctiLoading = false;
                this.cdr.markForCheck();
              },
              error: (e) => {
                this.openctiError = e?.message ?? 'Failed to load OpenCTI indicators';
                this.openctiLoading = false;
                this.cdr.markForCheck();
              },
            }),
          );
        }
        // EPSS — fetch scores for CVEs mapped to this technique
        if (tech) {
          const cveIds = this.attackCveService.getCvesForTechnique(tech.attackId).map(m => m.cveId);
          if (cveIds.length > 0) {
            this.subs.add(
              this.epssService.fetchScores(cveIds).subscribe(scores => {
                const vals = cveIds.map(id => scores.get(id)?.epss).filter((s): s is number => s !== undefined);
                this.epssAvg = vals.length > 0 ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
                if (this.technique?.attackId === tech.attackId) {
                  this.signals = this.getSignals(tech);
                  this.cdr.markForCheck();
                }
              })
            );
          }
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.implService.status$.subscribe((map) => {
        this.implStatusMap = map;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.docService.mitDocs$.subscribe((docs) => {
        this.mitDocs = docs;
        this.cdr.markForCheck();
      }),
    );

    // Refresh CVE exposures when CTID data finishes loading
    this.subs.add(
      this.attackCveService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.cveExposures = this.attackCveService.getCvesForTechnique(this.technique.attackId).slice(0, 20);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh NIST controls when mapping data finishes loading
    this.subs.add(
      this.nistMappingService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.nistControls = this.nistMappingService.getControlsForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh CIS controls when data finishes loading
    this.subs.add(
      this.cisControlsService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.cisControls = this.cisControlsService.getControlsForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh cloud controls when any provider finishes loading
    this.subs.add(
      this.cloudControlsService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.cloudControls = this.cloudControlsService.getControlsForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh VERIS actions when mapping data finishes loading
    this.subs.add(
      this.verisService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.verisActions = this.verisService.getActionsForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );
    this.subs.add(
      this.criProfileService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.criControls = this.criProfileService.getControlsForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );
    this.subs.add(
      this.capecService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.capecEntries = this.capecService.getCapecForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh ExploitDB counts when data finishes loading
    this.subs.add(
      this.exploitdbService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.exploitCount = this.exploitdbService.getExploitCount(this.technique.attackId);
          this.signals = this.getSignals(this.technique);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh Nuclei template counts when data finishes loading
    this.subs.add(
      this.nucleiService.loaded$.subscribe((loaded) => {
        if (loaded && this.technique) {
          this.nucleiCount = this.nucleiService.getTemplateCount(this.technique.attackId);
          this.signals = this.getSignals(this.technique);
          this.cdr.markForCheck();
        }
      }),
    );

    // Re-render coverage score whenever settings (weights) change
    this.subs.add(
      this.settingsService.settings$.subscribe(() => {
        this.cdr.markForCheck();
      }),
    );

    // Refresh watchlist state reactively so the button updates
    this.subs.add(
      this.watchlistService.entries$.subscribe(() => {
        this.cdr.markForCheck();
      }),
    );

    // Refresh custom mitigations reactively when they change
    this.subs.add(
      this.customMitigationService.mitigations$.subscribe(() => {
        if (this.technique) {
          this.customMitigations = this.customMitigationService.getForTechnique(this.technique.attackId);
          this.cdr.markForCheck();
        }
      }),
    );

    // Refresh annotation when annotations change (e.g. from another part of the UI)
    this.subs.add(
      this.annotationService.annotations$.subscribe(() => {
        if (this.technique) {
          const ann = this.annotationService.getAnnotation(this.technique.attackId);
          this.annotation = ann;
          if (!ann) {
            this.annotationNote = '';
            this.annotationColor = 'default';
            this.annotationPinned = false;
          }
          this.cdr.markForCheck();
        }
      }),
    );
  }

  get filteredMitigations(): MitigationRelationship[] {
    if (!this.mitSearchText) return this.mitigations;
    const q = this.mitSearchText.toLowerCase();
    return this.mitigations.filter(
      rel =>
        rel.mitigation.name.toLowerCase().includes(q) ||
        (rel.mitigation.description ?? '').toLowerCase().includes(q),
    );
  }

  get implSummary(): { implemented: number; total: number } {
    const total = this.mitigations.length;
    const implemented = this.mitigations.filter(
      rel => this.implStatusMap.get(rel.mitigation.id) === 'implemented'
    ).length;
    return { implemented, total };
  }

  setAllMitigationStatus(status: ImplStatus): void {
    for (const rel of this.filteredMitigations) {
      this.implService.setStatus(rel.mitigation.id, status);
    }
  }

  clearAllMitigationStatus(): void {
    for (const rel of this.filteredMitigations) {
      this.implService.setStatus(rel.mitigation.id, null);
    }
  }

  saveAnnotation(): void {
    if (!this.technique) return;
    if (this.annotationNote.trim()) {
      this.annotationService.setAnnotation(
        this.technique.attackId,
        this.annotationNote,
        this.annotationColor,
        this.annotationPinned,
      );
    } else {
      this.annotationService.deleteAnnotation(this.technique.attackId);
    }
    this.annotation = this.annotationService.getAnnotation(this.technique.attackId);
    this.cdr.markForCheck();
  }

  clearAnnotation(): void {
    if (!this.technique) return;
    this.annotationService.deleteAnnotation(this.technique.attackId);
    this.annotation = undefined;
    this.annotationNote = '';
    this.annotationColor = 'default';
    this.annotationPinned = false;
    this.cdr.markForCheck();
  }

  copyMispTag(): void {
    if (!this.mispCluster) return;
    const tag = `misp-galaxy:mitre-attack-pattern="${this.mispCluster.value}"`;
    navigator.clipboard.writeText(tag).then(() => {
      this.mispTagCopied = true;
      this.cdr.markForCheck();
      setTimeout(() => { this.mispTagCopied = false; this.cdr.markForCheck(); }, 2000);
    });
  }

  executorIcon(executorName: string): string {
    const icons: Record<string, string> = {
      'powershell': '💙',
      'command_prompt': '⬛',
      'bash': '🐚',
      'sh': '🐚',
      'python': '🐍',
      'ruby': '💎',
      'perl': '🦪',
      'manual': '🖐️',
    };
    return icons[executorName?.toLowerCase() ?? ''] ?? '▶';
  }

  getPlatformIcon(platform: string): string {
    const icons: Record<string, string> = {
      'Windows': '🪟',
      'Linux': '🐧',
      'macOS': '🍎',
      'Cloud': '☁️',
      'AWS': '☁️',
      'Azure': '☁️',
      'GCP': '☁️',
      'Containers': '🐳',
      'Network': '🌐',
      'Office 365': '📧',
      'SaaS': '💼',
      'IaaS': '🏗️',
      'Google Workspace': '📧',
    };
    return icons[platform] ?? '💻';
  }

  get difficultyLevel(): { label: string; color: string } {
    const subCount = this.technique?.subtechniques?.length ?? 0;
    if (subCount >= 4) return { label: 'Complex', color: '#f87171' };
    if (subCount >= 1) return { label: 'Moderate', color: '#fbbf24' };
    return { label: 'Basic', color: '#4ade80' };
  }

  selectSubtechnique(sub: Technique): void {
    this.filterService.selectTechnique(sub);
  }

  private _relGraphData: RelGraphData | null = null;

  get relGraphData(): RelGraphData {
    if (this._relGraphData) return this._relGraphData;
    if (!this.technique) return { nodes: [], links: [] };

    const nodes: GraphNode[] = [{
      id: 'tech', label: this.technique.attackId, type: 'technique', x: 200, y: 120
    }];
    const links: GraphLink[] = [];

    this.mitigations.slice(0, 5).forEach((rel, i) => {
      const angle = -Math.PI / 2 + (i - 2) * (Math.PI / 4);
      const x = 200 + Math.cos(angle) * 120;
      const y = 120 + Math.sin(angle) * 90;
      nodes.push({ id: rel.mitigation.id, label: rel.mitigation.attackId, type: 'mitigation', x, y });
      links.push({ source: 'tech', target: rel.mitigation.id, type: 'mitigates' });
    });

    this.threatGroups.slice(0, 4).forEach((g, i) => {
      const angle = Math.PI + (i - 1.5) * (Math.PI / 6);
      const x = 200 + Math.cos(angle) * 130;
      const y = 120 + Math.sin(angle) * 80;
      nodes.push({ id: g.id, label: g.attackId, type: 'group', x, y });
      links.push({ source: g.id, target: 'tech', type: 'uses' });
    });

    this._relGraphData = { nodes, links };
    return this._relGraphData;
  }

  getNodeById(id: string): GraphNode | undefined {
    return this.relGraphData.nodes.find(n => n.id === id);
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  close(): void {
    this.filterService.selectTechnique(null);
  }

  /** Clicking the CVE signal pill highlights all techniques sharing this technique's CVEs in the matrix. */
  onCvePillClick(): void {
    if (!this.technique) return;
    const mappings = this.attackCveService.getCvesForTechnique(this.technique.attackId);
    const techIds = new Set<string>();
    for (const m of mappings) {
      [...m.primaryImpact, ...m.secondaryImpact, ...m.exploitationTechnique].forEach(id => techIds.add(id));
    }
    if (techIds.size === 0) return;
    this.filterService.setCveFilter([...techIds]);
    this.close();
  }

  openTechniqueGraph(): void {
    this.filterService.setActivePanel('technique-graph');
  }

  filterByMitigation(mitigation: Mitigation): void {
    this.filterService.filterByMitigation(mitigation);
    this.filterService.selectTechnique(null);
  }

  setImplStatus(mitigationId: string, status: ImplStatus): void {
    const current = this.implStatusMap.get(mitigationId);
    this.implService.setStatus(mitigationId, current === status ? null : status);
  }

  getImplStatus(mitigationId: string): ImplStatus | null {
    return this.implStatusMap.get(mitigationId) ?? null;
  }

  filterByGroup(group: ThreatGroup): void {
    this.filterService.toggleThreatGroup(group.id);
    this.filterService.setActivePanel('threats');
    this.filterService.selectTechnique(null);
  }

  filterBySoftware(sw: AttackSoftware): void {
    this.filterService.toggleSoftware(sw.id);
    this.filterService.setActivePanel('software');
    this.filterService.selectTechnique(null);
  }

  filterByCampaign(campaign: Campaign): void {
    this.filterService.toggleCampaign(campaign.id);
    this.filterService.setActivePanel('threats');
    this.filterService.selectTechnique(null);
  }

  filterByDataSource(dsName: string): void {
    this.filterService.setDataSourceFilter(dsName);
    this.filterService.selectTechnique(null);
  }

  get groupedD3fend(): { category: string; measures: D3fendTechnique[] }[] {
    const map = new Map<string, D3fendTechnique[]>();
    for (const m of this.d3fendMeasures) {
      if (!map.has(m.category)) map.set(m.category, []);
      map.get(m.category)!.push(m);
    }
    const order = ['Harden', 'Detect', 'Isolate', 'Deceive', 'Evict'];
    return order.filter(c => map.has(c)).map(c => ({ category: c, measures: map.get(c)! }));
  }

  get groupedDataComponents(): { sourceName: string; components: MitreDataComponent[] }[] {
    const map = new Map<string, MitreDataComponent[]>();
    for (const dc of this.dataComponents) {
      if (!map.has(dc.dataSourceName)) map.set(dc.dataSourceName, []);
      map.get(dc.dataSourceName)!.push(dc);
    }
    return [...map.entries()].map(([sourceName, components]) => {
      // Deduplicate components by name within each data source group
      const seen = new Set<string>();
      const unique = components.filter(c => {
        if (seen.has(c.name)) return false;
        seen.add(c.name);
        return true;
      });
      return { sourceName, components: unique };
    });
  }

  saveTechNote(): void {
    if (this.technique) {
      this.docService.setTechNote(this.technique.id, this.techniqueNote);
    }
  }

  toggleDoc(mitigationId: string): void {
    if (this.expandedDocs.has(mitigationId)) {
      this.expandedDocs.delete(mitigationId);
    } else {
      this.expandedDocs.add(mitigationId);
      if (!this.editingDocs.has(mitigationId)) {
        this.editingDocs.set(mitigationId, { ...this.docService.getMitDoc(mitigationId) });
      }
    }
    this.cdr.markForCheck();
  }

  isDocExpanded(mitigationId: string): boolean {
    return this.expandedDocs.has(mitigationId);
  }

  toggleMitDesc(mitigationId: string): void {
    if (this.expandedMitDescs.has(mitigationId)) {
      this.expandedMitDescs.delete(mitigationId);
    } else {
      this.expandedMitDescs.add(mitigationId);
    }
    this.cdr.markForCheck();
  }

  isMitDescExpanded(mitigationId: string): boolean {
    return this.expandedMitDescs.has(mitigationId);
  }

  toggleRelDesc(mitigationId: string): void {
    if (this.expandedRelDescs.has(mitigationId)) {
      this.expandedRelDescs.delete(mitigationId);
    } else {
      this.expandedRelDescs.add(mitigationId);
    }
    this.cdr.markForCheck();
  }

  isRelDescExpanded(mitigationId: string): boolean {
    return this.expandedRelDescs.has(mitigationId);
  }

  getEditingDoc(mitigationId: string): MitigationDoc {
    if (!this.editingDocs.has(mitigationId)) {
      this.editingDocs.set(mitigationId, { ...this.docService.getMitDoc(mitigationId) });
    }
    return this.editingDocs.get(mitigationId)!;
  }

  saveDoc(mitigationId: string): void {
    const doc = this.editingDocs.get(mitigationId);
    if (doc) {
      this.docService.setMitDoc(mitigationId, doc);
    }
    this.expandedDocs.delete(mitigationId);
    this.cdr.markForCheck();
  }

  hasDoc(mitigationId: string): boolean {
    const doc = this.mitDocs.get(mitigationId);
    return !!doc && (!!doc.notes || !!doc.owner || !!doc.dueDate || !!doc.controlRefs || !!doc.evidenceUrl);
  }

  addTag(tag: string): void {
    if (this.technique && tag) {
      this.taggingService.addTag(this.technique.id, tag);
      this.currentTags = this.taggingService.getTags(this.technique.id);
      this.newTagInput = '';
      this.cdr.markForCheck();
    }
  }

  removeTag(tag: string): void {
    if (this.technique) {
      this.taggingService.removeTag(this.technique.id, tag);
      this.currentTags = this.taggingService.getTags(this.technique.id);
      this.cdr.markForCheck();
    }
  }

  get coverageScore(): number {
    const w = this.settingsService.getNormalizedWeights();
    const mitScore = Math.min(w.mitigations, (this.mitigations.length / 5) * w.mitigations);
    const carScore = this.carAnalytics.length > 0 ? w.car : 0;
    const atomicScore = this.atomicTests.length > 0 ? w.atomic : 0;
    const d3fendScore = this.d3fendMeasures.length > 0 ? w.d3fend : 0;
    const nistScore = this.nistControls.length > 0 ? w.nist : 0;
    const criScore = this.criControls.length > 0 ? Math.min(w.nist * 0.5, (this.criControls.length / 10) * w.nist * 0.5) : 0;
    return Math.min(100, Math.round(mitScore + carScore + atomicScore + d3fendScore + nistScore + criScore));
  }

  get coverageGrade(): string {
    const s = this.coverageScore;
    if (s >= 90) return 'A';
    if (s >= 75) return 'B';
    if (s >= 60) return 'C';
    if (s >= 40) return 'D';
    return 'F';
  }

  get isWatched(): boolean {
    return this.technique ? this.watchlistService.isWatched(this.technique.attackId) : false;
  }

  toggleWatchlist(): void {
    if (this.technique) {
      this.watchlistService.toggle(this.technique);
      this.cdr.markForCheck();
    }
  }

  get coverageColor(): string {
    const s = this.coverageScore;
    if (s >= 75) return '#4ade80';   // green
    if (s >= 50) return '#fb923c';   // orange
    return '#f87171';                 // red
  }

  /** Builds the compact signal pills for the sidebar header area. */
  getSignals(tech: Technique): { icon: string; label: string; value: string; color: string }[] {
    const signals: { icon: string; label: string; value: string; color: string }[] = [];
    const id = tech.attackId;

    const sigmaCount = this.sigmaService.getRuleCount(id);
    if (sigmaCount > 0) signals.push({ icon: 'Σ', label: 'Sigma', value: String(sigmaCount), color: '#10b981' });

    const atomicCount = this.atomicService.getTestCount(id);
    if (atomicCount > 0) signals.push({ icon: '⚛', label: 'Atomic', value: String(atomicCount), color: '#f0a040' });

    const carCount = this.carService.getLiveCount(id);
    if (carCount > 0) signals.push({ icon: '🔬', label: 'CAR', value: String(carCount), color: '#58a6ff' });

    const d3Count = this.d3fendService.getCountermeasures(id).length;
    if (d3Count > 0) signals.push({ icon: '🛡', label: 'D3FEND', value: String(d3Count), color: '#7c3aed' });

    const cveCount = this.attackCveService.getCvesForTechnique(id).length;
    if (cveCount > 0) signals.push({ icon: '🔴', label: 'CVE', value: String(cveCount), color: '#ef4444' });

    const capecCount = this.capecService.getCapecForTechnique(id).length;
    if (capecCount > 0) signals.push({ icon: '⚠', label: 'CAPEC', value: String(capecCount), color: '#f59e0b' });

    const misp = this.mispService.getCluster(id);
    if (misp) signals.push({ icon: '🔴', label: 'MISP', value: '1 cluster', color: '#c0392b' });

    const nistCount = this.nistMappingService.getControlCount(id);
    if (nistCount > 0) signals.push({ icon: '🏛', label: 'NIST', value: String(nistCount), color: '#42a5f5' });

    if (this.epssAvg !== null && this.epssAvg > 0) {
      signals.push({
        icon: '🎯',
        label: 'EPSS',
        value: this.epssService.formatEpss(this.epssAvg),
        color: this.epssService.getEpssColor(this.epssAvg),
      });
    }

    const exploitCount = this.exploitdbService.getExploitCount(id);
    if (exploitCount > 0) signals.push({ icon: '💥', label: 'ExploitDB', value: String(exploitCount), color: '#dc2626' });

    const nucleiCount = this.nucleiService.getTemplateCount(id);
    if (nucleiCount > 0) signals.push({ icon: '🔬', label: 'Nuclei', value: String(nucleiCount), color: '#3b82f6' });

    return signals;
  }

  /** Returns a compact signal summary for the given technique. */
  getSignalSummary(tech: Technique): { icon: string; label: string; value: string; color: string }[] {
    const signals: { icon: string; label: string; value: string; color: string }[] = [];

    const mitCount = this.mitigations.length;
    signals.push({
      icon: '🛡️',
      label: 'Mitigations',
      value: String(mitCount),
      color: mitCount >= 4 ? '#4ade80' : mitCount >= 2 ? '#fb923c' : mitCount >= 1 ? '#facc15' : '#f87171',
    });

    const sigmaRules = this.carAnalytics.length;
    signals.push({
      icon: '🔬',
      label: 'Detection',
      value: sigmaRules > 0 ? `${sigmaRules} rules` : 'none',
      color: sigmaRules > 0 ? '#38bdf8' : '#64748b',
    });

    const atomicCount = this.atomicLiveCount > 0 ? this.atomicLiveCount : this.atomicTests.length;
    signals.push({
      icon: '🧪',
      label: 'Tests',
      value: atomicCount > 0 ? `${atomicCount}${this.atomicLiveCount >= 3 ? '+' : ''}` : 'none',
      color: atomicCount >= 3 ? '#f97316' : atomicCount >= 1 ? '#fbbf24' : '#64748b',
    });

    const d3fendCount = this.d3fendMeasures.length;
    signals.push({
      icon: '🔵',
      label: 'D3FEND',
      value: d3fendCount > 0 ? 'covered' : 'none',
      color: d3fendCount > 0 ? '#60a5fa' : '#64748b',
    });

    const kevCount = this.cveExposures.length;
    if (kevCount > 0) {
      signals.push({
        icon: '🔴',
        label: 'KEV',
        value: `${kevCount} CVE${kevCount !== 1 ? 's' : ''}`,
        color: kevCount >= 5 ? '#ef4444' : kevCount >= 2 ? '#f97316' : '#facc15',
      });
    }

    const capecCount = this.capecEntries.length;
    if (capecCount > 0) {
      signals.push({
        icon: '🟠',
        label: 'CAPEC',
        value: `${capecCount} pattern${capecCount !== 1 ? 's' : ''}`,
        color: '#fb923c',
      });
    }

    return signals;
  }
}

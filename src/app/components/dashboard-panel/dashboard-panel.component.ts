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
import { Observable, Subscription, combineLatest, distinctUntilChanged, filter, map, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { Technique } from '../../models/technique';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import { HtmlReportService } from '../../services/html-report.service';
import { DashboardConfigService, DashboardWidget } from '../../services/dashboard-config.service';
import { SigmaService } from '../../services/sigma.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { CveService } from '../../services/cve.service';
import { MispService } from '../../services/misp.service';
import { OpenCtiService } from '../../services/opencti.service';
import { XlsxExportService } from '../../services/xlsx-export.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { EnrichmentService } from '../../services/enrichment.service';
import { KevEntry } from '../../models/cve';
import { SourceRegistryService } from '../../services/source-registry.service';

export interface DashboardStats {
  // Coverage (enrichment = ≥1 cross-framework signal)
  totalTechniques: number;
  coveredTechniques: number;
  coveragePct: number;
  uncoveredCount: number;

  // Per-framework coverage (so no single framework is the headline)
  mitigationCoveragePct: number;
  controlCoveragePct: number;

  // Composite defensive posture (0–100): mitigation is ONE weighted input
  postureScore: number;

  // Implementation
  implementedCount: number;
  inProgressCount: number;
  plannedCount: number;
  notStartedCount: number;
  totalMitigations: number;

  // Detection
  withCarCount: number;
  withAtomicCount: number;
  withD3fendCount: number;
  detectionCoveragePct: number;

  // Risk
  criticalRiskCount: number;  // high threat + no mitigation
  cveExposedCount: number;

  // Trend (from last 2 snapshots)
  coverageTrend: number;  // +/- % from previous snapshot
  hasTrendData: boolean;

  // Per-tactic coverage (for bar chart)
  tacticStats: Array<{ name: string; shortname: string; pct: number; covered: number; total: number }>;

  // Top risk techniques (expanded to 10 for gap-summary widget)
  topRiskTechniques: Array<{ attackId: string; name: string; threatGroupCount: number }>;

  // Avg mitigations per covered technique
  avgMitigations: number;

  // Detection rule counts
  sigmaRuleCount: number;
  elasticRuleCount: number;
  splunkRuleCount: number;

  // Intel
  mispClusterCount: number;
  openctiConnected: boolean;
  threatGroupCount: number;

  // Recent KEV entries
  recentKevEntries: KevEntry[];
}

// Radar chart types
interface RadarSpoke {
  x1: number; y1: number; x2: number; y2: number;
  labelX: number; labelY: number;
  label: string; pct: number; anchor: string;
}

interface RadarChart {
  polygon: string;
  spokes: RadarSpoke[];
  gridCircles: number[];
}

// Data-health entry
interface HealthEntry {
  name: string;
  status: 'loading' | 'loaded' | 'failed' | 'empty';
  /** Why the entry is failed or empty, from the source registry. */
  detail?: string;
}

/** What the source registry says about a health entry: failed or empty with a reason, or nothing. */
interface RegistryVerdict { status: 'failed' | 'empty'; detail: string; }

@Component({
  selector: 'app-dashboard-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard-panel.component.html',
  styleUrl: './dashboard-panel.component.scss',
})
export class DashboardPanelComponent implements OnInit, OnDestroy {
  stats: DashboardStats | null = null;
  loading = true;
  configOpen = false;

  readonly currentDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  // Widget config
  allWidgets: DashboardWidget[] = [];
  visibleWidgets: DashboardWidget[] = [];

  // Data health entries
  healthEntries: HealthEntry[] = [];

  // Technique of the Day
  todTechnique: Technique | null = null;
  todTactic = '';
  todDescription = '';
  todMitigationCount = 0;

  private subs = new Subscription();
  private statsBuilt = false;

  constructor(
    private filterService: FilterService,
    private panelNav: PanelNavService,
    private dataService: DataService,
    private implService: ImplementationService,
    private timelineService: TimelineService,
    private attackCveService: AttackCveService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private htmlReportService: HtmlReportService,
    private dashboardConfig: DashboardConfigService,
    private sigmaService: SigmaService,
    private elasticService: ElasticService,
    private splunkContentService: SplunkContentService,
    private cveService: CveService,
    private mispService: MispService,
    private openctiService: OpenCtiService,
    private xlsxExportService: XlsxExportService,
    private customMitService: CustomMitigationService,
    private enrichment: EnrichmentService,
    private cdr: ChangeDetectorRef,
    private sources: SourceRegistryService,
  ) {}

  ngOnInit(): void {
    // Subscribe to widget config changes
    this.subs.add(
      this.dashboardConfig.widgets$.subscribe(widgets => {
        this.allWidgets = [...widgets].sort((a, b) => a.order - b.order);
        this.visibleWidgets = widgets
          .filter(w => w.visible)
          .sort((a, b) => a.order - b.order);
        this.cdr.markForCheck();
      }),
    );

    this.buildStats();

    // Refresh stats when impl status changes
    this.subs.add(
      this.implService.status$.subscribe(() => {
        this.statsBuilt = false;
        this.buildStats();
      }),
    );

    // Refresh stats when CVE data loads
    this.subs.add(
      this.attackCveService.loaded$.subscribe(loaded => {
        if (loaded) {
          this.statsBuilt = false;
          this.buildStats();
        }
      }),
    );

    // Build data-health entries
    this.initHealthEntries();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildStats(): void {
    this.loading = true;
    this.cdr.markForCheck();

    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const parentTechs = domain.techniques.filter(t => !t.isSubtechnique);
      const totalTechniques = parentTechs.length;
      // Cross-framework enrichment counts in a single pass — "coverage" here means
      // ≥1 defensive/framework signal, with per-framework counts kept alongside.
      const et = this.enrichment.totals(parentTechs, domain);
      const coveredTechniques = et.enriched;
      const coveragePct = totalTechniques > 0
        ? Math.round((coveredTechniques / totalTechniques) * 100)
        : 0;
      const uncoveredCount = totalTechniques - coveredTechniques;
      const mitigationCoveragePct = totalTechniques > 0
        ? Math.round((et.mitigation / totalTechniques) * 100)
        : 0;
      const controlCoveragePct = totalTechniques > 0
        ? Math.round((et.control / totalTechniques) * 100)
        : 0;

      // Implementation counts
      const implSummary = this.implService.summarize();
      const implementedCount = implSummary['implemented'] ?? 0;
      const inProgressCount = implSummary['in-progress'] ?? 0;
      const plannedCount = implSummary['planned'] ?? 0;
      const notStartedCount = implSummary['not-started'] ?? 0;
      const totalMitigations = domain.mitigations.length;

      // Detection coverage
      let withCarCount = 0;
      let withAtomicCount = 0;
      let withD3fendCount = 0;
      let withAnyDetection = 0;

      for (const tech of parentTechs) {
        const hasCar = this.carService.getAnalytics(tech.attackId).length > 0;
        const hasAtomic = this.atomicService.getTestCount(tech.attackId) > 0;
        const hasD3fend = this.d3fendService.getCountermeasures(tech.attackId).length > 0;
        if (hasCar) withCarCount++;
        if (hasAtomic) withAtomicCount++;
        if (hasD3fend) withD3fendCount++;
        if (hasCar || hasAtomic || hasD3fend) withAnyDetection++;
      }

      const detectionCoveragePct = totalTechniques > 0
        ? Math.round((withAnyDetection / totalTechniques) * 100)
        : 0;

      // Critical risk: threat-relevant (≥1 group) techniques with NO defensive
      // signal of ANY kind — no mitigation AND no detection AND no control AND
      // no D3FEND countermeasure (atomic tests / CVE links don't count as defense).
      const criticalRiskTechs = parentTechs.filter(t => {
        const hasGroup = (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0;
        return hasGroup && !this.enrichment.hasDefensiveSignal(t, domain);
      });
      const criticalRiskCount = criticalRiskTechs.length;

      // KEV-exposed gaps: KEV-mapped techniques that are wholly undefended.
      const kevExposedGapCount = parentTechs.filter(t => {
        const hasKev = this.attackCveService.getKevCvesForTechnique(t.attackId).length > 0;
        return hasKev && !this.enrichment.hasDefensiveSignal(t, domain);
      }).length;

      // Top 10 risk techniques sorted by threat group count (expanded for gap widget)
      const topRiskTechniques = [...criticalRiskTechs]
        .sort((a, b) => {
          const ga = (domain.groupsByTechnique.get(a.id) ?? []).length;
          const gb = (domain.groupsByTechnique.get(b.id) ?? []).length;
          return gb - ga;
        })
        .slice(0, 10)
        .map(t => ({
          attackId: t.attackId,
          name: t.name,
          threatGroupCount: (domain.groupsByTechnique.get(t.id) ?? []).length,
        }));

      // CVE exposed: parent techniques that have CVE mappings
      const cveExposedCount = parentTechs.filter(
        t => this.attackCveService.getCvesForTechnique(t.attackId).length > 0,
      ).length;

      // Trend from snapshots
      const snapshots = this.timelineService.getAll();
      let coverageTrend = 0;
      let hasTrendData = false;
      if (snapshots.length >= 2) {
        const last = snapshots[snapshots.length - 1];
        const prev = snapshots[snapshots.length - 2];
        // A change of count basis (an older mitigations-only snapshot next to a
        // 'mapped' one) is not progress: no trend until both share a basis.
        if ((last.basis ?? null) === (prev.basis ?? null)) {
          coverageTrend = last.coveragePct - prev.coveragePct;
          hasTrendData = true;
        }
      }

      // Per-tactic coverage, sorted ascending (worst first)
      const tacticStats = domain.tacticColumns
        .map(col => {
          const parents = col.techniques.filter(t => !t.isSubtechnique);
          // Enrichment-based coverage (≥1 framework), matching the dashboard
          // headline + stats-bar/analytics/tactic-summary — NOT mitigation-only,
          // so the Tactic Breakdown bars and Radar agree with the Coverage stat.
          const covered = parents.filter(
            t => this.enrichment.isEnriched(t, domain),
          ).length;
          const total = parents.length;
          const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
          return { name: col.tactic.name, shortname: col.tactic.shortname, pct, covered, total };
        })
        .sort((a, b) => a.pct - b.pct);

      // Average mitigations per covered technique
      let mitSum = 0;
      let covCount = 0;
      for (const tech of parentTechs) {
        const mits = domain.mitigationsByTechnique.get(tech.id)?.length ?? 0;
        if (mits > 0) {
          mitSum += mits;
          covCount++;
        }
      }
      const avgMitigations = covCount > 0 ? Math.round((mitSum / covCount) * 10) / 10 : 0;

      // Detection rule counts
      let sigmaRuleCount = 0;
      let elasticRuleCount = 0;
      let splunkRuleCount = 0;
      for (const tech of parentTechs) {
        sigmaRuleCount += this.sigmaService.getRuleCount(tech.attackId);
        elasticRuleCount += this.elasticService.getRuleCount(tech.attackId);
        splunkRuleCount += this.splunkContentService.getRuleCount(tech.attackId);
      }

      // Intel summary
      const threatGroupCount = domain.groups.length;

      // Recent KEV entries (most recent 5 by dateAdded)
      const recentKevEntries = this.getRecentKevEntries();

      // Legacy composite (0–100), kept computed for the E0.2 characterization
      // pin only and NOT rendered (E1.5, D6 hide-before-delete). It is not a
      // Known-rung number: 25% of its weight is threat input (KEV exposure and
      // group-used techniques, both inverted), so adding a group that uses an
      // unmitigated technique lowers it. Threat is a separate dimension, never a
      // posture rung (plan 4.1), so no label, grade or risk verdict is derived
      // from it; the defensive-only Known view is the Reference depth lens.
      //   mitigation coverage       0.20
      //   detection coverage        0.20
      //   control coverage          0.20
      //   D3FEND coverage           0.15
      //   KEV exposure (inverted)   0.15
      //   threat pressure (inverted)0.10
      const frac = (n: number) => (totalTechniques > 0 ? n / totalTechniques : 0);
      const postureScore = Math.round(100 * (
        0.20 * frac(et.mitigation) +
        0.20 * frac(et.detection) +        // Sigma+CAR analytics only; D3FEND is its own term below (no double-count, atomic excluded)
        0.20 * frac(et.control) +
        0.15 * frac(et.d3fend) +
        0.15 * (1 - frac(kevExposedGapCount)) +
        0.10 * (1 - frac(criticalRiskCount))
      ));

      this.stats = {
        totalTechniques,
        coveredTechniques,
        coveragePct,
        uncoveredCount,
        mitigationCoveragePct,
        controlCoveragePct,
        postureScore,
        implementedCount,
        inProgressCount,
        plannedCount,
        notStartedCount,
        totalMitigations,
        withCarCount,
        withAtomicCount,
        withD3fendCount,
        detectionCoveragePct,
        criticalRiskCount,
        cveExposedCount,
        coverageTrend,
        hasTrendData,
        tacticStats,
        topRiskTechniques,
        avgMitigations,
        sigmaRuleCount,
        elasticRuleCount,
        splunkRuleCount,
        mispClusterCount: 0,
        openctiConnected: false,
        threatGroupCount,
        recentKevEntries,
      };

      this.statsBuilt = true;
      this.loading = false;

      // Technique of the Day: seeded random pick based on date
      this.computeTechniqueOfDay(parentTechs, domain);

      this.cdr.markForCheck();

      // Async enrichment for MISP / OpenCTI after initial render
      this.enrichIntelStats();
    });
  }

  private enrichIntelStats(): void {
    this.subs.add(
      this.mispService.total$.subscribe(total => {
        if (this.stats) {
          this.stats = { ...this.stats, mispClusterCount: total };
          this.cdr.markForCheck();
        }
      }),
    );
    this.subs.add(
      this.openctiService.connected$.subscribe(connected => {
        if (this.stats) {
          this.stats = { ...this.stats, openctiConnected: connected };
          this.cdr.markForCheck();
        }
      }),
    );
  }

  private getRecentKevEntries(): KevEntry[] {
    // CveService stores KEV entries in a private BehaviorSubject.
    // We use getKevEntry indirectly - try to get entries from cached data.
    // Since we can't iterate the private map, we rely on known CVE IDs from attack mappings.
    const entries: KevEntry[] = [];
    // Pull from the attackCveService which maps techniques to CVEs
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const parentTechs = domain.techniques.filter(t => !t.isSubtechnique);
      const seen = new Set<string>();
      for (const tech of parentTechs) {
        const cves = this.attackCveService.getCvesForTechnique(tech.attackId);
        for (const cve of cves) {
          if (seen.has(cve.cveId)) continue;
          seen.add(cve.cveId);
          const kevEntry = this.cveService.getKevEntry(cve.cveId);
          if (kevEntry) {
            entries.push(kevEntry);
          }
        }
      }
    });
    // Sort by dateAdded descending, take 5
    return entries
      .sort((a, b) => (b.dateAdded ?? '').localeCompare(a.dateAdded ?? ''))
      .slice(0, 5);
  }

  /**
   * The registry's verdict for a health entry backed by one or more sources: 'failed'
   * (or 'empty') only when every one of them failed (or returned nothing), so an entry
   * that still has some data is not painted red. Same rule as the data-health ribbon.
   */
  private registryVerdict$(ids: string[]): Observable<RegistryVerdict | null> {
    return this.sources.records$.pipe(
      map(records => {
        const mine = records.filter(r => ids.includes(r.id));
        if (!mine.length) return null;
        if (mine.every(r => r.status === 'failed' || r.status === 'empty')) {
          const failed = mine.filter(r => r.status === 'failed');
          if (failed.length) {
            return { status: 'failed' as const, detail: failed.map(r => r.lastError ?? 'failed').join('; ') };
          }
          return { status: 'empty' as const, detail: 'the source returned no usable rows' };
        }
        return null;
      }),
      distinctUntilChanged((a, b) => a?.status === b?.status && a?.detail === b?.detail),
    );
  }

  private initHealthEntries(): void {
    // `ids` name the SourceRegistry records behind an entry (E1.3), the same mapping as the
    // data-health ribbon: a loader that fails (or answers with 0 rows) no longer reports
    // loaded, so the registry is what turns the entry 'failed' (or 'empty') instead of
    // leaving it 'loading' for the whole session.
    const sources: { name: string; loaded$: Observable<boolean>; ids: string[] }[] = [
      { name: 'Atomic Red Team', loaded$: this.atomicService.loaded$, ids: ['atomic-layer'] },
      { name: 'Sigma Rules', loaded$: this.sigmaService.loaded$, ids: ['sigmahq-coverage'] },
      { name: 'ATT&CK CVE', loaded$: this.attackCveService.loaded$, ids: ['ctid-attack-to-cve', 'ctid-kev'] },
      { name: 'MISP Galaxy', loaded$: this.mispService.loaded$, ids: ['misp-galaxy'] },
      { name: 'D3FEND', loaded$: this.d3fendService.loaded$, ids: ['d3fend-ontology'] },
      { name: 'CAR Analytics', loaded$: this.carService.loaded$, ids: ['car-layer'] },
      { name: 'Elastic Rules', loaded$: this.elasticService.loaded$, ids: ['elastic-tree'] },
      { name: 'Splunk Content', loaded$: this.splunkContentService.loaded$, ids: ['splunk-tree'] },
    ];
    this.healthEntries = sources.map(s => ({ name: s.name, status: 'loading' as const }));
    const setEntry = (i: number, entry: HealthEntry) => {
      this.healthEntries = [...this.healthEntries];
      this.healthEntries[i] = entry;
      this.cdr.markForCheck();
    };
    sources.forEach((src, i) => {
      this.subs.add(
        src.loaded$.subscribe((loaded: boolean) => {
          // A failed or empty source keeps its verdict until the registry clears it (a retry started).
          const status = this.healthEntries[i].status;
          if (!loaded && (status === 'failed' || status === 'empty')) return;
          setEntry(i, { name: src.name, status: loaded ? 'loaded' : 'loading' });
        }),
      );
      this.subs.add(
        this.registryVerdict$(src.ids).subscribe(verdict => {
          if (this.healthEntries[i].status === 'loaded') return;
          setEntry(i, verdict
            ? { name: src.name, status: verdict.status, detail: verdict.detail }
            : { name: src.name, status: 'loading' });
        }),
      );
    });
  }

  // ─── Radar chart computation (ported from AnalyticsPanelComponent) ──────
  get radarChart(): RadarChart {
    const cx = 130, cy = 130, r = 100;
    const stats = this.stats?.tacticStats ?? [];
    const n = stats.length;
    if (n === 0) return { polygon: '', spokes: [], gridCircles: [] };

    const angle = (i: number) => (Math.PI * 2 * i / n) - Math.PI / 2;
    const pt = (i: number, pct: number) => ({
      x: cx + r * (pct / 100) * Math.cos(angle(i)),
      y: cy + r * (pct / 100) * Math.sin(angle(i)),
    });

    const polygon = stats
      .map((ts, i) => { const p = pt(i, ts.pct); return `${p.x.toFixed(1)},${p.y.toFixed(1)}`; })
      .join(' ');

    const spokes: RadarSpoke[] = stats.map((ts, i) => {
      const a = angle(i);
      const labelR = r + 18;
      const lx = cx + labelR * Math.cos(a);
      const ly = cy + labelR * Math.sin(a);
      const anchor = Math.abs(Math.cos(a)) < 0.3 ? 'middle' : Math.cos(a) > 0 ? 'start' : 'end';
      return {
        x1: cx, y1: cy,
        x2: cx + r * Math.cos(a), y2: cy + r * Math.sin(a),
        labelX: lx, labelY: ly,
        label: ts.shortname.slice(0, 4).toUpperCase(),
        pct: ts.pct,
        anchor,
      };
    });

    return { polygon, spokes, gridCircles: [25, 50, 75, 100] };
  }

  // ─── Donut chart for implementation status ─────────────────────────────
  get implDonutSegments(): Array<{ label: string; count: number; color: string; offset: number; pct: number }> {
    if (!this.stats) return [];
    const total = this.stats.totalMitigations || 1;
    const segments = [
      { label: 'Implemented', count: this.stats.implementedCount, color: 'var(--success)' },
      { label: 'In Progress', count: this.stats.inProgressCount, color: 'var(--accent-warm)' },
      { label: 'Planned', count: this.stats.plannedCount, color: '#60a5fa' },
      { label: 'Not Started', count: this.stats.notStartedCount, color: 'var(--danger)' },
      {
        label: 'Untracked',
        count: total - this.stats.implementedCount - this.stats.inProgressCount - this.stats.plannedCount - this.stats.notStartedCount,
        color: 'var(--text-faint)',
      },
    ];
    let offset = 0;
    return segments.map(s => {
      const pct = Math.round((s.count / total) * 100);
      const seg = { ...s, offset, pct };
      offset += pct;
      return seg;
    });
  }

  // ─── Widget config actions ─────────────────────────────────────────────
  toggleConfig(): void {
    this.configOpen = !this.configOpen;
  }

  toggleWidget(id: string): void {
    this.dashboardConfig.toggleWidget(id);
  }

  moveWidget(id: string, direction: 'up' | 'down'): void {
    this.dashboardConfig.moveWidget(id, direction);
  }

  resetWidgets(): void {
    this.dashboardConfig.resetDefaults();
  }

  isWidgetVisible(id: string): boolean {
    return this.visibleWidgets.some(w => w.id === id);
  }

  // ─── Navigation and export actions ─────────────────────────────────────
  openPanel(panel: string): void {
    this.configOpen = false;
    this.panelNav.open(panel);
  }

  exportReport(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.htmlReportService.generateAndOpen(domain, this.implService.getStatusMap());
    });
  }

  exportCsv(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.xlsxExportService.exportWorkbook(
        domain,
        this.implService.getStatusMap(),
        this.customMitService.all,
        this.timelineService.getAll(),
      );
    });
  }

  clearFilters(): void {
    this.filterService.clearAll();
  }

  // ─── Display helpers ───────────────────────────────────────────────────
  // E1.5 removed the letter grade (overallGrade/gradeColor) and the risk
  // verdict badge (riskLevel, which read 'LOW RISK' on reference data alone).
  // Plan 4.1 bans both; the header now names the rung of these numbers.
  readonly rungBadgeText = 'KNOWN · reference data';
  readonly rungBadgeTitle =
    'Known rung (plan 4.1): what the world has mapped for each technique. ' +
    'No claim about your environment, and no risk rating.';

  tacticBarColor(pct: number): string {
    if (pct >= 70) return 'var(--success)';
    if (pct >= 50) return 'var(--success)';
    if (pct >= 35) return 'var(--accent-warm)';
    if (pct >= 20) return 'var(--accent-warm)';
    return 'var(--danger)';
  }

  trendSign(trend: number): string {
    if (trend > 0) return '+';
    if (trend < 0) return '-';
    return '';
  }

  implBarPct(count: number): number {
    const total = this.stats?.totalMitigations ?? 1;
    return Math.round((count / total) * 100);
  }

  detectionBarPct(count: number): number {
    const total = this.stats?.totalTechniques ?? 1;
    return Math.round((count / total) * 100);
  }

  trackWidget(_index: number, widget: DashboardWidget): string {
    return widget.id;
  }

  // ─── Technique of the Day ─────────────────────────────────────────────
  private computeTechniqueOfDay(parentTechs: Technique[], domain: any): void {
    if (parentTechs.length === 0) return;

    // Seed based on current date so it's consistent within the same day
    const today = new Date();
    const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
    // Simple hash-based pseudo-random from seed
    let hash = seed;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    const index = Math.abs(hash) % parentTechs.length;

    const tech = parentTechs[index];
    this.todTechnique = tech;
    this.todTactic = tech.tacticShortnames.join(', ') || 'N/A';

    // Strip HTML tags from description and truncate to 100 chars
    const rawDesc = (tech.description || '').replace(/<[^>]*>/g, '').replace(/\(Citation:[^)]*\)/g, '').trim();
    this.todDescription = rawDesc.length > 100 ? rawDesc.slice(0, 100) + '...' : rawDesc;

    const mits = domain.mitigationsByTechnique.get(tech.id);
    this.todMitigationCount = mits?.length ?? 0;
  }

  viewTechniqueOfDay(): void {
    if (!this.todTechnique) return;
    // The technique sidebar is a global overlay — open it over the matrix and
    // keep the selection this flow makes for it.
    this.panelNav.open('matrix', { keepTechniqueSelection: true });
    this.filterService.selectTechnique(this.todTechnique);
  }
}

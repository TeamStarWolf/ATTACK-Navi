import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription, combineLatest, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
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
import { KevEntry } from '../../models/cve';

export interface DashboardStats {
  // Coverage
  totalTechniques: number;
  coveredTechniques: number;
  coveragePct: number;
  uncoveredCount: number;

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
  status: 'loading' | 'loaded' | 'failed';
}

@Component({
  selector: 'app-dashboard-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard-panel.component.html',
  styleUrl: './dashboard-panel.component.scss',
})
export class DashboardPanelComponent implements OnInit, OnDestroy {
  visible = false;
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

  private subs = new Subscription();
  private statsBuilt = false;

  constructor(
    private filterService: FilterService,
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
    private cdr: ChangeDetectorRef,
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

    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'dashboard';
        if (this.visible && !this.statsBuilt) {
          this.buildStats();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh stats when impl status changes (if already visible)
    this.subs.add(
      this.implService.status$.subscribe(() => {
        if (this.visible) {
          this.statsBuilt = false;
          this.buildStats();
        }
      }),
    );

    // Refresh stats when CVE data loads
    this.subs.add(
      this.attackCveService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
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
      const coveredTechniques = parentTechs.filter(
        t => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0,
      ).length;
      const coveragePct = totalTechniques > 0
        ? Math.round((coveredTechniques / totalTechniques) * 100)
        : 0;
      const uncoveredCount = totalTechniques - coveredTechniques;

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

      // Risk: techniques with no mitigation and at least 1 threat group
      const criticalRiskTechs = parentTechs.filter(t => {
        const hasMit = (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0;
        const hasGroup = (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0;
        return !hasMit && hasGroup;
      });
      const criticalRiskCount = criticalRiskTechs.length;

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
        coverageTrend = last.coveragePct - prev.coveragePct;
        hasTrendData = true;
      }

      // Per-tactic coverage, sorted ascending (worst first)
      const tacticStats = domain.tacticColumns
        .map(col => {
          const parents = col.techniques.filter(t => !t.isSubtechnique);
          const covered = parents.filter(
            t => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0,
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

      this.stats = {
        totalTechniques,
        coveredTechniques,
        coveragePct,
        uncoveredCount,
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

  private initHealthEntries(): void {
    const sources: { name: string; loaded$: any }[] = [
      { name: 'Atomic Red Team', loaded$: this.atomicService.loaded$ },
      { name: 'Sigma Rules', loaded$: this.sigmaService.loaded$ },
      { name: 'ATT&CK CVE', loaded$: this.attackCveService.loaded$ },
      { name: 'MISP Galaxy', loaded$: this.mispService.loaded$ },
      { name: 'D3FEND', loaded$: this.d3fendService.loaded$ },
      { name: 'CAR Analytics', loaded$: this.carService.loaded$ },
      { name: 'Elastic Rules', loaded$: this.elasticService.loaded$ },
      { name: 'Splunk Content', loaded$: this.splunkContentService.loaded$ },
    ];
    this.healthEntries = sources.map(s => ({ name: s.name, status: 'loading' as const }));
    sources.forEach((src, i) => {
      this.subs.add(
        src.loaded$.subscribe((loaded: boolean) => {
          this.healthEntries = [...this.healthEntries];
          this.healthEntries[i] = { name: src.name, status: loaded ? 'loaded' : 'loading' };
          this.cdr.markForCheck();
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
      { label: 'Implemented', count: this.stats.implementedCount, color: '#4ade80' },
      { label: 'In Progress', count: this.stats.inProgressCount, color: '#fb923c' },
      { label: 'Planned', count: this.stats.plannedCount, color: '#60a5fa' },
      { label: 'Not Started', count: this.stats.notStartedCount, color: '#f87171' },
      {
        label: 'Untracked',
        count: total - this.stats.implementedCount - this.stats.inProgressCount - this.stats.plannedCount - this.stats.notStartedCount,
        color: '#4a6080',
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
  close(): void {
    this.configOpen = false;
    this.filterService.setActivePanel(null);
  }

  openPanel(panel: string): void {
    this.close();
    setTimeout(() => this.filterService.setActivePanel(panel as any), 100);
  }

  exportReport(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.close();
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

  // ─── Display helpers (preserved from original) ─────────────────────────
  get overallGrade(): string {
    const pct = this.stats?.coveragePct ?? 0;
    if (pct >= 80) return 'A';
    if (pct >= 65) return 'B';
    if (pct >= 50) return 'C';
    if (pct >= 35) return 'D';
    return 'F';
  }

  get gradeColor(): string {
    switch (this.overallGrade) {
      case 'A': return '#4ade80';
      case 'B': return '#86efac';
      case 'C': return '#facc15';
      case 'D': return '#fb923c';
      case 'F': return '#f87171';
      default:  return '#4a6080';
    }
  }

  get riskLevel(): 'critical' | 'high' | 'medium' | 'low' {
    const pct = this.stats?.coveragePct ?? 0;
    const crit = this.stats?.criticalRiskCount ?? 0;
    if (pct < 35 || crit > 50) return 'critical';
    if (pct < 50 || crit > 25) return 'high';
    if (pct < 65 || crit > 10) return 'medium';
    return 'low';
  }

  get riskLevelColor(): string {
    switch (this.riskLevel) {
      case 'critical': return '#f87171';
      case 'high':     return '#fb923c';
      case 'medium':   return '#facc15';
      case 'low':      return '#4ade80';
      default:         return '#4a6080';
    }
  }

  tacticBarColor(pct: number): string {
    if (pct >= 70) return '#4ade80';
    if (pct >= 50) return '#86efac';
    if (pct >= 35) return '#facc15';
    if (pct >= 20) return '#fb923c';
    return '#f87171';
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
}

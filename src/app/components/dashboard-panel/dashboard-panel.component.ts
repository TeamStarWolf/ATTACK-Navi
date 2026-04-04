import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import { HtmlReportService } from '../../services/html-report.service';

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
  tacticStats: Array<{ name: string; pct: number; covered: number; total: number }>;

  // Top risk techniques
  topRiskTechniques: Array<{ attackId: string; name: string; threatGroupCount: number }>;
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
  readonly currentDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  private subs = new Subscription();
  private statsBuilt = false;

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private timelineService: TimelineService,
    private cveService: AttackCveService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private htmlReportService: HtmlReportService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
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
      this.cveService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.statsBuilt = false;
          this.buildStats();
        }
      }),
    );
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

      // Top 5 risk techniques sorted by threat group count
      const topRiskTechniques = [...criticalRiskTechs]
        .sort((a, b) => {
          const ga = (domain.groupsByTechnique.get(a.id) ?? []).length;
          const gb = (domain.groupsByTechnique.get(b.id) ?? []).length;
          return gb - ga;
        })
        .slice(0, 5)
        .map(t => ({
          attackId: t.attackId,
          name: t.name,
          threatGroupCount: (domain.groupsByTechnique.get(t.id) ?? []).length,
        }));

      // CVE exposed: parent techniques that have CVE mappings
      const cveExposedCount = parentTechs.filter(
        t => this.cveService.getCvesForTechnique(t.attackId).length > 0,
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
          return { name: col.tactic.name, pct, covered, total };
        })
        .sort((a, b) => a.pct - b.pct);

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
      };

      this.statsBuilt = true;
      this.loading = false;
      this.cdr.markForCheck();
    });
  }

  close(): void {
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
}

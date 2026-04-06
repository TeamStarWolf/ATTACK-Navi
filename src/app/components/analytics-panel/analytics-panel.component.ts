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
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { SigmaService } from '../../services/sigma.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { Domain } from '../../models/domain';

interface TacticStat {
  name: string;
  shortname: string;
  total: number;
  covered: number;
  pct: number;
  avgRisk: number;
}

interface TopGap {
  attackId: string;
  name: string;
  tacticName: string;
  groupCount: number;
  kevCount: number;
  riskScore: number;
  mitigationCount: number;
}

interface TopMitigation {
  attackId: string;
  name: string;
  impactScore: number;
  techniqueCount: number;
  groupsCovered: number;
}

@Component({
  selector: 'app-analytics-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './analytics-panel.component.html',
  styleUrl: './analytics-panel.component.scss',
})
export class AnalyticsPanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  tacticStats: TacticStat[] = [];
  implSummary: Record<string, number> = {};
  topGaps: TopGap[] = [];
  topMitigations: TopMitigation[] = [];
  coveragePct = 0;
  totalTechs = 0;
  coveredTechs = 0;
  kevExposureCount = 0;
  kevScores: Map<string, number> = new Map();
  sigmaTotal = 0;
  sigmaCoveredTechs = 0;
  nistTotal = 0;
  nistCoveredTechs = 0;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cveService: CveService,
    private sigmaService: SigmaService,
    private nistMappingService: NistMappingService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.open = p === 'analytics';
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.dataService.domain$.subscribe(d => {
        this.domain = d;
        this.computeStats();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.implService.status$.subscribe(() => {
        this.implSummary = this.implService.summarize();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.cveService.kevTechScores$.subscribe(scores => {
        this.kevScores = scores;
        this.computeStats();
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  computeStats(): void {
    if (!this.domain) return;

    // Only parent techniques (not sub-techniques)
    const parentTechs = this.domain.techniques.filter(t => !t.isSubtechnique);
    this.totalTechs = parentTechs.length;
    this.coveredTechs = parentTechs.filter(t => t.mitigationCount > 0).length;
    this.coveragePct = this.totalTechs > 0
      ? Math.round(100 * this.coveredTechs / this.totalTechs)
      : 0;

    // Sigma coverage
    this.sigmaTotal = 0;
    this.sigmaCoveredTechs = 0;
    for (const t of parentTechs) {
      const count = this.sigmaService.getRuleCount(t.attackId);
      this.sigmaTotal += count;
      if (count > 0) this.sigmaCoveredTechs++;
    }

    // NIST coverage
    this.nistTotal = 0;
    this.nistCoveredTechs = 0;
    for (const t of parentTechs) {
      const count = this.nistMappingService.getControlCount(t.attackId);
      this.nistTotal += count;
      if (count > 0) this.nistCoveredTechs++;
    }

    // Impl summary
    this.implSummary = this.implService.summarize();

    // Tactic stats
    this.tacticStats = this.domain.tacticColumns.map(col => {
      const total = col.techniques.length;
      const covered = col.techniques.filter(t => t.mitigationCount > 0).length;
      const avgRisk = col.techniques.reduce((sum, t) => {
        const g = (this.domain!.groupsByTechnique.get(t.id) ?? []).length;
        return sum + g * (1 + 1 / (t.mitigationCount + 1));
      }, 0) / (total || 1);
      return {
        name: col.tactic.name,
        shortname: col.tactic.shortname,
        total,
        covered,
        pct: total > 0 ? Math.round(100 * covered / total) : 0,
        avgRisk: Math.round(avgRisk * 10) / 10,
      };
    });

    // Top gaps: uncovered parent techniques, sorted by risk
    const gaps: TopGap[] = parentTechs
      .filter(t => t.mitigationCount === 0)
      .map(t => {
        const groups = this.domain!.groupsByTechnique.get(t.id) ?? [];
        const kev = this.kevScores.get(t.attackId) ?? 0;
        const risk = groups.length * (1 + 1 / (t.mitigationCount + 1));
        return {
          attackId: t.attackId,
          name: t.name,
          tacticName: t.tacticShortnames[0] ?? '',
          groupCount: groups.length,
          kevCount: kev,
          riskScore: Math.round(risk * 10) / 10,
          mitigationCount: t.mitigationCount,
        };
      })
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 10);
    this.topGaps = gaps;

    // KEV exposure: unique techniques with kev score > 0 and 0 mitigations
    this.kevExposureCount = [...this.kevScores.entries()]
      .filter(([, count]) => count > 0)
      .filter(([attackId]) => {
        const tech = this.domain!.techniques.find(t => t.attackId === attackId);
        return tech && tech.mitigationCount === 0;
      }).length;

    // Top mitigations by impact: coverage of threat-active techniques
    const mitScores = new Map<string, {
      attackId: string;
      name: string;
      score: number;
      techCount: number;
      groupsCovered: number;
    }>();

    for (const t of parentTechs) {
      const groups = (this.domain!.groupsByTechnique.get(t.id) ?? []).length;
      if (groups === 0) continue;
      const mits = this.domain!.mitigationsByTechnique.get(t.id) ?? [];
      for (const mr of mits) {
        const m = mr.mitigation;
        if (!mitScores.has(m.id)) {
          mitScores.set(m.id, {
            attackId: m.attackId,
            name: m.name,
            score: 0,
            techCount: 0,
            groupsCovered: 0,
          });
        }
        const entry = mitScores.get(m.id)!;
        entry.score += groups;
        entry.techCount += 1;
        entry.groupsCovered = Math.max(entry.groupsCovered, groups);
      }
    }

    this.topMitigations = [...mitScores.values()]
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map(m => ({
        attackId: m.attackId,
        name: m.name,
        impactScore: m.score,
        techniqueCount: m.techCount,
        groupsCovered: m.groupsCovered,
      }));

    this.cdr.markForCheck();
  }

  selectTechnique(attackId: string): void {
    if (!this.domain) return;
    const tech = this.domain.techniques.find(t => t.attackId === attackId);
    if (tech) {
      this.filterService.selectTechnique(tech);
      this.close();
    }
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  get implTotal(): number {
    return Object.values(this.implSummary).reduce((s, v) => s + v, 0);
  }

  get hasImplData(): boolean {
    return this.implTotal > 0;
  }

  barColor(pct: number): string {
    if (pct < 50) return '#d32f2f';
    if (pct < 80) return '#f57c00';
    return '#4caf50';
  }

  implBarWidth(key: string): number {
    const total = this.implTotal;
    if (!total) return 0;
    return Math.round(100 * (this.implSummary[key] ?? 0) / total);
  }

  /** Compute SVG radar chart data for the tactic coverage polygon. */
  get radarChart(): { polygon: string; spokes: { x1: number; y1: number; x2: number; y2: number; labelX: number; labelY: number; label: string; pct: number; anchor: string }[]; gridCircles: number[] } {
    const cx = 130, cy = 130, r = 100;
    const n = this.tacticStats.length;
    if (n === 0) return { polygon: '', spokes: [], gridCircles: [] };

    const angle = (i: number) => (Math.PI * 2 * i / n) - Math.PI / 2;
    const pt = (i: number, pct: number) => ({
      x: cx + r * (pct / 100) * Math.cos(angle(i)),
      y: cy + r * (pct / 100) * Math.sin(angle(i)),
    });

    const polygon = this.tacticStats
      .map((ts, i) => { const p = pt(i, ts.pct); return `${p.x.toFixed(1)},${p.y.toFixed(1)}`; })
      .join(' ');

    const spokes = this.tacticStats.map((ts, i) => {
      const a = angle(i);
      const labelR = r + 18;
      const lx = cx + labelR * Math.cos(a);
      const ly = cy + labelR * Math.sin(a);
      // Text anchor: left side = start, right side = end, top/bottom = middle
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
}

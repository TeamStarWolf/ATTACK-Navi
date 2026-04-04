import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';

export type TechniqueOutcome = 'blocked' | 'detected' | 'vulnerable' | 'unknown';

interface RadarPoint { tactic: string; pct: number; index: number; total: number; }

interface ScenarioTechnique {
  technique: Technique;
  outcome: TechniqueOutcome;
  mitigationCount: number;
  implementedMitigations: number;
  hasDetection: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  reasoning: string;
}

interface SimulationResult {
  group: ThreatGroup;
  techniques: ScenarioTechnique[];
  blockedCount: number;
  detectedCount: number;
  vulnerableCount: number;
  unknownCount: number;
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  overallScore: number;
}

@Component({
  selector: 'app-scenario-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './scenario-panel.component.html',
  styleUrl: './scenario-panel.component.scss',
})
export class ScenarioPanelComponent implements OnInit, OnDestroy {
  visible = false;
  groups: ThreatGroup[] = [];
  selectedGroup: ThreatGroup | null = null;
  result: SimulationResult | null = null;
  searchText = '';
  filterOutcome: TechniqueOutcome | 'all' = 'all';
  activeTab: 'summary' | 'techniques' | 'plan' = 'summary';
  isSimulating = false;
  groupSearch = '';

  private cachedDomain: any = null;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'scenario';
        if (this.visible && this.groups.length === 0) {
          this.loadGroups();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  loadGroups(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.cachedDomain = domain;
      this.groups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
      this.cdr.markForCheck();
    });
  }

  get filteredGroups(): ThreatGroup[] {
    const q = this.groupSearch.trim().toLowerCase();
    if (!q) return this.groups;
    return this.groups.filter(g =>
      g.name.toLowerCase().includes(q) ||
      g.attackId.toLowerCase().includes(q) ||
      g.aliases.some(a => a.toLowerCase().includes(q)),
    );
  }

  selectGroup(group: ThreatGroup): void {
    this.selectedGroup = group;
    this.result = null;
    this.runSimulation(group);
  }

  runSimulation(group: ThreatGroup): void {
    this.isSimulating = true;
    this.cdr.markForCheck();

    const doCompute = (domain: any) => {
      setTimeout(() => {
        this.result = this.computeResult(group, domain);
        this.isSimulating = false;
        this.activeTab = 'summary';
        this.filterOutcome = 'all';
        this.searchText = '';
        this.cdr.markForCheck();
      }, 300);
    };

    if (this.cachedDomain) {
      doCompute(this.cachedDomain);
    } else {
      this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(d => {
        this.cachedDomain = d;
        doCompute(d);
      });
    }
  }

  private computeResult(group: ThreatGroup, domain: any): SimulationResult {
    const techniques = this.dataService.getTechniquesForGroup(group.id);
    const statusMap = this.implService.getStatusMap();
    const scenarioTechniques: ScenarioTechnique[] = [];

    for (const tech of techniques) {
      const mitRels = domain.mitigationsByTechnique?.get(tech.id) ?? [];
      const mitigationCount = mitRels.length;

      let implementedMitigations = 0;
      for (const rel of mitRels) {
        const s = statusMap.get(rel.mitigation.id);
        if (s === 'implemented') implementedMitigations++;
      }

      const carCount = this.carService.getAnalytics(tech.attackId).length;
      const atomicCount = this.atomicService.getTestCount(tech.attackId);
      const d3fendCount = this.d3fendService.getCountermeasures(tech.attackId).length;
      const hasDetection = (carCount + atomicCount + d3fendCount) > 0;

      let outcome: TechniqueOutcome;
      if (implementedMitigations >= 2) {
        outcome = 'blocked';
      } else if (implementedMitigations >= 1 && hasDetection) {
        outcome = 'detected';
      } else if (implementedMitigations >= 1) {
        outcome = 'detected';
      } else if (hasDetection) {
        outcome = 'detected';
      } else if (mitigationCount > 0) {
        outcome = 'vulnerable';
      } else {
        outcome = 'unknown';
      }

      let riskLevel: 'critical' | 'high' | 'medium' | 'low';
      if (outcome === 'unknown') riskLevel = 'critical';
      else if (outcome === 'vulnerable') riskLevel = 'high';
      else if (outcome === 'detected') riskLevel = 'medium';
      else riskLevel = 'low';

      let reasoning: string;
      if (outcome === 'blocked') {
        reasoning = `${implementedMitigations} mitigation${implementedMitigations !== 1 ? 's' : ''} implemented`;
        if (hasDetection) {
          const parts: string[] = [];
          if (carCount > 0) parts.push(`CAR analytics`);
          if (atomicCount > 0) parts.push(`Atomic tests`);
          if (d3fendCount > 0) parts.push(`D3FEND`);
          if (parts.length) reasoning += ` + ${parts.join(', ')}`;
        }
      } else if (outcome === 'detected') {
        if (implementedMitigations > 0) {
          reasoning = `${implementedMitigations} mitigation${implementedMitigations !== 1 ? 's' : ''} implemented`;
          const parts: string[] = [];
          if (carCount > 0) parts.push('CAR analytics');
          if (d3fendCount > 0) parts.push('D3FEND');
          if (atomicCount > 0) parts.push('Atomic tests');
          if (parts.length) reasoning += ` + ${parts[0]}`;
        } else {
          const parts: string[] = [];
          if (carCount > 0) parts.push(`${carCount} CAR analytic${carCount !== 1 ? 's' : ''}`);
          if (d3fendCount > 0) parts.push(`${d3fendCount} D3FEND countermeasure${d3fendCount !== 1 ? 's' : ''}`);
          if (atomicCount > 0) parts.push(`${atomicCount} Atomic test${atomicCount !== 1 ? 's' : ''}`);
          reasoning = 'No mitigation — ' + parts.join(', ');
        }
      } else if (outcome === 'vulnerable') {
        reasoning = `${mitigationCount} mitigation${mitigationCount !== 1 ? 's' : ''} available but not implemented`;
      } else {
        reasoning = 'No mitigations or detections';
      }

      scenarioTechniques.push({
        technique: tech,
        outcome,
        mitigationCount,
        implementedMitigations,
        hasDetection,
        riskLevel,
        reasoning,
      });
    }

    const blockedCount = scenarioTechniques.filter(t => t.outcome === 'blocked').length;
    const detectedCount = scenarioTechniques.filter(t => t.outcome === 'detected').length;
    const vulnerableCount = scenarioTechniques.filter(t => t.outcome === 'vulnerable').length;
    const unknownCount = scenarioTechniques.filter(t => t.outcome === 'unknown').length;
    const total = scenarioTechniques.length || 1;

    const overallScore = Math.round((blockedCount * 100 + detectedCount * 60) / total);

    let overallRisk: 'critical' | 'high' | 'medium' | 'low';
    const criticalPct = unknownCount / total;
    const highPct = vulnerableCount / total;
    if (criticalPct > 0.3) overallRisk = 'critical';
    else if (criticalPct > 0.15 || highPct > 0.3) overallRisk = 'high';
    else if (criticalPct > 0 || highPct > 0.15) overallRisk = 'medium';
    else overallRisk = 'low';

    return {
      group,
      techniques: scenarioTechniques.sort((a, b) => {
        const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return riskOrder[a.riskLevel] - riskOrder[b.riskLevel];
      }),
      blockedCount,
      detectedCount,
      vulnerableCount,
      unknownCount,
      overallRisk,
      overallScore,
    };
  }

  get filteredTechniques(): ScenarioTechnique[] {
    if (!this.result) return [];
    let list = this.result.techniques;
    if (this.filterOutcome !== 'all') {
      list = list.filter(t => t.outcome === this.filterOutcome);
    }
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      list = list.filter(t =>
        t.technique.name.toLowerCase().includes(q) ||
        t.technique.attackId.toLowerCase().includes(q) ||
        t.technique.tacticShortnames.some(s => s.toLowerCase().includes(q)),
      );
    }
    return list;
  }

  get remediationPlan(): ScenarioTechnique[] {
    if (!this.result) return [];
    return this.result.techniques
      .filter(t => t.outcome === 'vulnerable' || (t.outcome === 'detected' && t.implementedMitigations === 0))
      .sort((a, b) => b.mitigationCount - a.mitigationCount);
  }

  get scoreGrade(): string {
    const s = this.result?.overallScore ?? 0;
    if (s >= 90) return 'A';
    if (s >= 75) return 'B';
    if (s >= 60) return 'C';
    if (s >= 40) return 'D';
    return 'F';
  }

  get donutGradient(): string {
    if (!this.result) return '';
    const total = this.result.techniques.length || 1;
    const b = this.result.blockedCount / total;
    const d = this.result.detectedCount / total;
    const v = this.result.vulnerableCount / total;
    const u = this.result.unknownCount / total;

    const blockedEnd = Math.round(b * 360);
    const detectedEnd = Math.round((b + d) * 360);
    const vulnerableEnd = Math.round((b + d + v) * 360);

    const parts: string[] = [];
    if (b > 0) parts.push(`#4ade80 0deg ${blockedEnd}deg`);
    if (d > 0) parts.push(`#fbbf24 ${blockedEnd}deg ${detectedEnd}deg`);
    if (v > 0) parts.push(`#f97316 ${detectedEnd}deg ${vulnerableEnd}deg`);
    if (u > 0) parts.push(`#f87171 ${vulnerableEnd}deg 360deg`);
    if (parts.length === 0) parts.push('#1a3448 0deg 360deg');

    return `conic-gradient(${parts.join(', ')})`;
  }

  get remediationScoreImpact(): number {
    if (!this.result) return 0;
    const total = this.result.techniques.length || 1;
    const quickWins = this.remediationPlan.length;
    return Math.round((quickWins * 60) / total);
  }

  get radarData(): RadarPoint[] {
    if (!this.result) return [];

    const tacticMap = new Map<string, { blocked: number; total: number }>();

    for (const st of this.result.techniques) {
      for (const tactic of st.technique.tacticShortnames ?? []) {
        if (!tacticMap.has(tactic)) tacticMap.set(tactic, { blocked: 0, total: 0 });
        const entry = tacticMap.get(tactic)!;
        entry.total++;
        if (st.outcome === 'blocked' || st.outcome === 'detected') entry.blocked++;
      }
    }

    const points: RadarPoint[] = [];
    let i = 0;
    for (const [tactic, stats] of tacticMap) {
      points.push({
        tactic,
        pct: stats.total > 0 ? Math.round((stats.blocked / stats.total) * 100) : 0,
        index: i++,
        total: tacticMap.size,
      });
    }
    return points;
  }

  get radarSvgPath(): string {
    const points = this.radarData;
    if (points.length < 3) return '';

    const cx = 120, cy = 120, r = 90;
    const coords = points.map((p, i) => {
      const angle = (i / points.length) * 2 * Math.PI - Math.PI / 2;
      const dist = (p.pct / 100) * r;
      return {
        x: cx + Math.cos(angle) * dist,
        y: cy + Math.sin(angle) * dist,
      };
    });

    return coords.map((c, i) => `${i === 0 ? 'M' : 'L'} ${c.x.toFixed(1)} ${c.y.toFixed(1)}`).join(' ') + ' Z';
  }

  get radarSvgCoords(): { x: number; y: number; labelX: number; labelY: number; gridX: number; gridY: number; tactic: string; pct: number }[] {
    const points = this.radarData;
    if (points.length < 3) return [];
    const cx = 120, cy = 120, r = 90;
    return points.map((p, i) => {
      const angle = (i / points.length) * 2 * Math.PI - Math.PI / 2;
      const dist = (p.pct / 100) * r;
      return {
        x: cx + Math.cos(angle) * dist,
        y: cy + Math.sin(angle) * dist,
        labelX: cx + Math.cos(angle) * (r + 20),
        labelY: cy + Math.sin(angle) * (r + 20),
        gridX: cx + Math.cos(angle) * r,
        gridY: cy + Math.sin(angle) * r,
        tactic: p.tactic,
        pct: p.pct,
      };
    });
  }

  selectTechnique(tech: ScenarioTechnique): void {
    this.filterService.selectTechnique(tech.technique);
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}

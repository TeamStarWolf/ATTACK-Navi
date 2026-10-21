// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Threat Scenario Simulator (Phase 2 design §3 P2-12a, E2.6-b3).
// Both flows run on the shared threat-profile picker: the single simulation picks
// one actor (mode="single"); the profile simulation edits the shared profile
// (mode="profile") and runs ThreatSimulationService over it — the former
// multi-actor overlay collapses to that one profile result (actor-vs-actor moves
// to #/intel/compare in P2-12b).
//
// Outcomes are posture buckets, not the old blocked/detected/vulnerable/unknown:
// reference content alone no longer counts as covered or detected. Each technique
// takes its bucket from PostureService.stateFor; the cards, table, pills, plan,
// donut and radar all read those buckets. Covered/Proven surfaces render only
// under ownerWords(); a fresh profile shows Known only + None. Every rung word
// comes from the vocabulary module (scenarioOutcomeLabel).
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  inject,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { PostureService } from '../../services/posture.service';
import { ThreatSimulationService, SimulationResult as ThreatSimResult } from '../../services/threat-simulation.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';
import { PostureBucket } from '../../models/posture/posture.types';
import { scenarioOutcomeLabel } from '../../models/posture/posture-vocabulary';
import { csvRow } from '../../utils/csv';

/** The scenario card / pill a bucket is counted under. 'stale' folds into 'proven' (aged Proven). */
export type ScenarioOutcome = 'proven' | 'covered' | 'partial' | 'known' | 'none';

interface RadarPoint { tactic: string; pct: number; index: number; total: number; }

interface ScenarioTechnique {
  technique: Technique;
  bucket: PostureBucket;
  outcome: ScenarioOutcome;
  mitigationCount: number;
  reasoning: string;
}

interface SimulationResult {
  group: ThreatGroup;
  techniques: ScenarioTechnique[];
  proven: number;    // bucket proven + stale
  covered: number;   // bucket covered
  partial: number;   // bucket partial — its own number, never summed into covered
  known: number;     // bucket known
  none: number;      // bucket none
  total: number;
  knownOnlyShare: number;   // known / total, as a percentage
  hasOwnerWords: boolean;   // Covered/Proven surfaces render only when true
}

/** Map a posture bucket to the scenario outcome it is counted under. */
function outcomeOf(bucket: PostureBucket): ScenarioOutcome {
  switch (bucket) {
    case 'proven':
    case 'stale': return 'proven';
    case 'covered': return 'covered';
    case 'partial': return 'partial';
    case 'known': return 'known';
    default: return 'none';
  }
}

@Component({
  selector: 'app-scenario-panel',
  standalone: true,
  imports: [CommonModule, FormsModule, ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './scenario-panel.component.html',
  styleUrl: './scenario-panel.component.scss',
})
export class ScenarioPanelComponent implements OnInit, OnDestroy {
  selectedGroup: ThreatGroup | null = null;
  result: SimulationResult | null = null;
  searchText = '';
  filterBucket: ScenarioOutcome | 'all' = 'all';
  activeTab: 'summary' | 'techniques' | 'plan' = 'summary';
  isSimulating = false;

  // ─── Profile simulation (the collapsed overlay) ─────────────────────────
  profileSimResult: ThreatSimResult | null = null;
  showThreatSim = false;

  /** The fresh-profile prompt; shown when the owner has recorded no posture yet. */
  readonly freshMessage = 'Record a run or mark a mitigation implemented to see your outcomes';
  readonly outcomeLabel = scenarioOutcomeLabel;

  private domain: any = null;
  private subs = new Subscription();

  private readonly posture = inject(PostureService);

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private threatSimService: ThreatSimulationService,
    private emulationPlanService: EmulationPlanService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Follow the loaded domain for the panel's life (a domain switch re-scopes both flows).
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (!domain) {
        this.selectedGroup = null;
        this.result = null;
        this.profileSimResult = null;
        this.showThreatSim = false;
      } else if (this.selectedGroup) {
        // Re-resolve the selected actor against the new domain; drop it (and the result) if gone.
        const still = domain.groups.find((g: ThreatGroup) => g.id === this.selectedGroup!.id);
        this.selectedGroup = still ?? null;
        if (!still) this.result = null;
      }
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  /** From the single-mode picker: the chosen actor's STIX id. */
  onGroupPicked(stixId: string): void {
    const group = this.domain?.groups.find((g: ThreatGroup) => g.id === stixId) ?? null;
    if (!group) return;
    this.selectedGroup = group;
    this.result = null;
    this.runSimulation(group);
  }

  runSimulation(group: ThreatGroup): void {
    if (!this.domain) return;
    this.isSimulating = true;
    this.cdr.markForCheck();
    setTimeout(() => {
      this.result = this.computeResult(group, this.domain);
      this.isSimulating = false;
      this.activeTab = 'summary';
      this.filterBucket = 'all';
      this.searchText = '';
      this.cdr.markForCheck();
    }, 150);
  }

  private computeResult(group: ThreatGroup, domain: any): SimulationResult {
    const techniques: Technique[] = this.dataService.getTechniquesForGroup(group.id);
    const scenarioTechniques: ScenarioTechnique[] = techniques.map(tech => {
      const bucket = this.posture.stateFor(tech).bucket;
      const mitigationCount = (domain.mitigationsByTechnique?.get(tech.id) ?? []).length;
      return { technique: tech, bucket, outcome: outcomeOf(bucket), mitigationCount, reasoning: this.reasoningFor(bucket, mitigationCount) };
    });

    const count = (o: ScenarioOutcome) => scenarioTechniques.filter(t => t.outcome === o).length;
    const proven = count('proven');
    const covered = count('covered');
    const partial = count('partial');
    const known = count('known');
    const none = count('none');
    const total = scenarioTechniques.length;
    const order: Record<ScenarioOutcome, number> = { none: 0, known: 1, partial: 2, covered: 3, proven: 4 };

    return {
      group,
      techniques: scenarioTechniques.sort((a, b) => order[a.outcome] - order[b.outcome]),
      proven, covered, partial, known, none, total,
      knownOnlyShare: total > 0 ? Math.round((known / total) * 100) : 0,
      hasOwnerWords: this.posture.ownerWords(),
    };
  }

  private reasoningFor(bucket: PostureBucket, mitigationCount: number): string {
    switch (bucket) {
      case 'proven': return 'A named detection fired or the technique was blocked on a recorded run';
      case 'stale': return 'A recorded run that has aged past its window';
      case 'covered': return 'You recorded a mitigation, control, confirmation or run (self-attested)';
      case 'partial': return 'Partly recorded: a broad mitigation marked implemented, not confirmed per technique';
      case 'known': return mitigationCount > 0
        ? `${mitigationCount} mitigation${mitigationCount !== 1 ? 's' : ''} mapped; none recorded as deployed`
        : 'Mapped by a public source; nothing recorded as deployed';
      default: return 'No reference mapping and nothing recorded';
    }
  }

  // ─── Derived views ──────────────────────────────────────────────────────

  get filteredTechniques(): ScenarioTechnique[] {
    if (!this.result) return [];
    let list = this.result.techniques;
    if (this.filterBucket !== 'all') list = list.filter(t => t.outcome === this.filterBucket);
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

  /** Gaps to close: not yet covered/proven (none, known or partial), most-mapped first. */
  get remediationPlan(): ScenarioTechnique[] {
    if (!this.result) return [];
    return this.result.techniques
      .filter(t => t.outcome === 'none' || t.outcome === 'known' || t.outcome === 'partial')
      .sort((a, b) => b.mitigationCount - a.mitigationCount);
  }

  bucketLabel(o: ScenarioOutcome): string {
    switch (o) {
      case 'proven': return scenarioOutcomeLabel('proven');
      case 'covered': return scenarioOutcomeLabel('covered');
      case 'partial': return 'partial';
      case 'known': return scenarioOutcomeLabel('known');
      default: return scenarioOutcomeLabel('none');
    }
  }

  get donutGradient(): string {
    if (!this.result) return '';
    const total = this.result.total || 1;
    const segs: [number, string][] = [
      [this.result.proven, '#4ade80'],
      [this.result.covered, '#22d3ee'],
      [this.result.partial, '#fbbf24'],
      [this.result.known, '#60a5fa'],
      [this.result.none, '#f87171'],
    ];
    const parts: string[] = [];
    let acc = 0;
    for (const [n, color] of segs) {
      if (n <= 0) continue;
      const start = Math.round((acc / total) * 360);
      acc += n;
      const end = Math.round((acc / total) * 360);
      parts.push(`${color} ${start}deg ${end}deg`);
    }
    if (parts.length === 0) parts.push('#27272a 0deg 360deg');
    return `conic-gradient(${parts.join(', ')})`;
  }

  get radarData(): RadarPoint[] {
    if (!this.result) return [];
    const tacticMap = new Map<string, { covered: number; total: number }>();
    for (const st of this.result.techniques) {
      const isCovered = st.outcome === 'covered' || st.outcome === 'proven';
      for (const tactic of st.technique.tacticShortnames ?? []) {
        if (!tacticMap.has(tactic)) tacticMap.set(tactic, { covered: 0, total: 0 });
        const e = tacticMap.get(tactic)!;
        e.total++;
        if (isCovered) e.covered++;
      }
    }
    const points: RadarPoint[] = [];
    let i = 0;
    for (const [tactic, stats] of tacticMap) {
      points.push({ tactic, pct: stats.total > 0 ? Math.round((stats.covered / stats.total) * 100) : 0, index: i++, total: tacticMap.size });
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
      return { x: cx + Math.cos(angle) * dist, y: cy + Math.sin(angle) * dist };
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

  selectGapTechnique(technique: Technique): void {
    this.filterService.selectTechnique(technique);
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  // ─── Profile simulation ─────────────────────────────────────────────────

  runProfileSimulation(): void {
    if (!this.domain) return;
    this.isSimulating = true;
    this.showThreatSim = true;
    this.profileSimResult = null;
    this.cdr.markForCheck();
    setTimeout(() => {
      this.profileSimResult = this.threatSimService.simulate(this.domain);
      this.isSimulating = false;
      this.cdr.markForCheck();
    }, 150);
  }

  get threatSimTacticBars(): { tactic: string; covered: number; total: number; pct: number }[] {
    if (!this.profileSimResult) return [];
    return this.profileSimResult.tacticBreakdown.map(t => ({ ...t, pct: t.total > 0 ? Math.round((t.covered / t.total) * 100) : 0 }));
  }

  closeThreatSim(): void {
    this.showThreatSim = false;
    this.profileSimResult = null;
    this.cdr.markForCheck();
  }

  exportSimulationCsv(): void {
    const result = this.profileSimResult;
    if (!result) return;
    const rows: string[] = ['Priority,ATT&CK ID,Technique Name,Tactic,KEV Count,Has Exploit,EPSS Avg'];
    for (const gap of result.gaps) {
      rows.push(csvRow([
        gap.priority.toUpperCase(),
        gap.technique.attackId,
        gap.technique.name,
        gap.tactic,
        gap.kevCount,
        gap.hasExploit ? 'Yes' : 'No',
        gap.epssAvg !== null ? gap.epssAvg.toFixed(4) : '',
      ]));
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'profile-simulation-gaps.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  exportCalderaProfile(): void {
    if (!this.selectedGroup || !this.domain) return;
    const plan = this.emulationPlanService.generatePlan(this.selectedGroup.id, this.domain);
    if (plan.steps.length === 0) return;
    this.emulationPlanService.exportCalderaProfile(plan);
  }

  priorityColor(priority: string): string {
    switch (priority) {
      case 'critical': return '#f87171';
      case 'high':     return '#f97316';
      case 'medium':   return '#fbbf24';
      case 'low':      return '#4ade80';
      default:         return 'var(--text-faint)';
    }
  }
}

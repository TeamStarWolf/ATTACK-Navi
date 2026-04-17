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
import { D3fendService, D3fendTechnique } from '../../services/d3fend.service';
import { EngageService, EngageActivity } from '../../services/engage.service';
import { CARService, CarAnalytic } from '../../services/car.service';
import { AtomicService, AtomicTest } from '../../services/atomic.service';
import { DataService } from '../../services/data.service';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

interface TechniqueScore {
  technique: Technique;
  d3fendCount: number;
  engageCount: number;
  carCount: number;
  atomicCount: number;
  totalScore: number;
  coverageRating: 'excellent' | 'good' | 'partial' | 'poor' | 'none';
}

@Component({
  selector: 'app-purple-team-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './purple-team-panel.component.html',
  styleUrl: './purple-team-panel.component.scss',
})
export class PurpleTeamPanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  selectedTech: Technique | null = null;

  // Per-technique view (when a technique is selected)
  d3fendMeasures: D3fendTechnique[] = [];
  engageActivities: EngageActivity[] = [];
  carAnalytics: CarAnalytic[] = [];
  atomicTests: AtomicTest[] = [];

  // Top gaps view
  topGaps: TechniqueScore[] = [];
  topCovered: TechniqueScore[] = [];
  viewMode: 'selected' | 'gaps' | 'covered' = 'selected';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private d3fendService: D3fendService,
    private engageService: EngageService,
    private carService: CARService,
    private atomicService: AtomicService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(panel => {
        this.open = panel === 'purple';
        if (this.open && this.domain) this.computeOverview();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        this.domain = domain;
        if (this.open && domain) this.computeOverview();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.selectedTechnique$.subscribe(tech => {
        this.selectedTech = tech;
        if (tech) {
          this.d3fendMeasures = this.d3fendService.getCountermeasures(tech.attackId, true);
          this.engageActivities = this.engageService.getActivities(tech.attackId);
          this.carAnalytics = this.carService.getAnalytics(tech.attackId);
          this.atomicTests = this.atomicService.getTests(tech.attackId);
        }
        this.cdr.markForCheck();
      }),
    );
  }

  close(): void { this.filterService.setActivePanel(null); }

  setViewMode(mode: 'selected' | 'gaps' | 'covered'): void {
    this.viewMode = mode;
    this.cdr.markForCheck();
  }

  private computeOverview(): void {
    if (!this.domain) return;
    const scores: TechniqueScore[] = this.domain.techniques
      .filter(t => !t.isSubtechnique)
      .map(t => {
        const d = this.d3fendService.getCountermeasures(t.attackId).length;
        const e = this.engageService.getActivities(t.attackId).length;
        const c = this.carService.getAnalytics(t.attackId).length;
        const a = this.atomicService.getTests(t.attackId).length;
        const total = d + e + c + a;
        const rating: TechniqueScore['coverageRating'] =
          total >= 12 ? 'excellent' :
          total >= 7  ? 'good' :
          total >= 3  ? 'partial' :
          total >= 1  ? 'poor' : 'none';
        return { technique: t, d3fendCount: d, engageCount: e, carCount: c, atomicCount: a, totalScore: total, coverageRating: rating };
      });
    this.topGaps    = scores.filter(s => s.totalScore === 0 || s.coverageRating === 'poor').sort((a, b) => a.totalScore - b.totalScore).slice(0, 15);
    this.topCovered = [...scores].sort((a, b) => b.totalScore - a.totalScore).slice(0, 15);
  }

  get techScoreBar(): { label: string; count: number; color: string; mode: string }[] {
    if (!this.selectedTech) return [];
    return [
      { label: 'D3FEND',   count: this.d3fendMeasures.length,   color: '#4caf50', mode: 'd3fend' },
      { label: 'Engage',   count: this.engageActivities.length,  color: '#f0a040', mode: 'engage' },
      { label: 'CAR',      count: this.carAnalytics.length,      color: '#58a6ff', mode: 'car' },
      { label: 'Atomic',   count: this.atomicTests.length,       color: '#e08030', mode: 'atomic' },
    ];
  }

  setHeatmapMode(mode: string): void {
    this.filterService.setHeatmapMode(mode as any);
  }

  selectTech(tech: Technique): void {
    this.filterService.selectTechnique(tech);
    this.viewMode = 'selected';
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }
}

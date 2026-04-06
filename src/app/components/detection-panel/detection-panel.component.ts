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
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';

export interface DetectionRow {
  id: string;
  name: string;
  attackId: string;
  tactic: string;
  carCount: number;
  atomicCount: number;
  d3fendCount: number;
  score: number;
}

interface TacticGroup {
  tactic: string;
  rows: DetectionRow[];
  avgScore: number;
  expanded: boolean;
}

@Component({
  selector: 'app-detection-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './detection-panel.component.html',
  styleUrl: './detection-panel.component.scss',
})
export class DetectionPanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'overview' | 'gaps' | 'top' | 'tactic' = 'overview';
  searchText = '';
  sortBy: 'score' | 'name' | 'tactic' = 'score';
  detectionRows: DetectionRow[] = [];

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'detection';
        if (this.visible && this.detectionRows.length === 0) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildRows(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const rows: DetectionRow[] = [];
      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;
        const carCount = this.carService.getAnalytics(tech.attackId).length;
        const atomicCount = this.atomicService.getTestCount(tech.attackId);
        const d3fendCount = this.d3fendService.getCountermeasures(tech.attackId).length;
        const score = carCount * 3 + atomicCount * 1 + d3fendCount * 2;
        rows.push({
          id: tech.id,
          name: tech.name,
          attackId: tech.attackId,
          tactic: tech.tacticShortnames[0] ?? '',
          carCount,
          atomicCount,
          d3fendCount,
          score,
        });
      }
      this.detectionRows = rows;
      this.cdr.markForCheck();
    });
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  setTab(tab: 'overview' | 'gaps' | 'top' | 'tactic'): void {
    this.activeTab = tab;
    this.searchText = '';
  }

  get filteredRows(): DetectionRow[] {
    let rows = this.detectionRows;
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      rows = rows.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.attackId.toLowerCase().includes(q) ||
        r.tactic.toLowerCase().includes(q),
      );
    }
    return this.sortRows(rows);
  }

  get gapRows(): DetectionRow[] {
    let rows = this.detectionRows.filter(r => r.score === 0);
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      rows = rows.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.attackId.toLowerCase().includes(q) ||
        r.tactic.toLowerCase().includes(q),
      );
    }
    return rows.sort((a, b) => a.name.localeCompare(b.name));
  }

  get topRows(): DetectionRow[] {
    return [...this.detectionRows]
      .sort((a, b) => b.score - a.score)
      .slice(0, 20);
  }

  get tacticGroups(): TacticGroup[] {
    const map = new Map<string, DetectionRow[]>();
    for (const row of this.detectionRows) {
      const key = row.tactic || 'Unknown';
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(row);
    }
    return [...map.entries()].map(([tactic, rows]) => {
      const avgScore = rows.length
        ? Math.round((rows.reduce((s, r) => s + r.score, 0) / rows.length) * 10) / 10
        : 0;
      return { tactic, rows: rows.sort((a, b) => b.score - a.score), avgScore, expanded: false };
    }).sort((a, b) => b.avgScore - a.avgScore);
  }

  get maxScore(): number {
    return this.detectionRows.reduce((max, r) => Math.max(max, r.score), 0) || 1;
  }

  get scoreDistribution(): number[] {
    const counts = [0, 0, 0, 0, 0];
    for (const r of this.detectionRows) {
      if (r.score === 0) counts[0]++;
      else if (r.score <= 3) counts[1]++;
      else if (r.score <= 6) counts[2]++;
      else if (r.score <= 9) counts[3]++;
      else counts[4]++;
    }
    return counts;
  }

  get totalWithDetection(): number {
    return this.detectionRows.filter(r => r.score > 0).length;
  }

  scoreBracket(score: number): 'none' | 'low' | 'medium' | 'high' | 'excellent' {
    if (score === 0) return 'none';
    if (score <= 3) return 'low';
    if (score <= 6) return 'medium';
    if (score <= 9) return 'high';
    return 'excellent';
  }

  scoreBarWidth(score: number): number {
    return Math.round((score / this.maxScore) * 100);
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  toggleTacticGroup(group: TacticGroup): void {
    group.expanded = !group.expanded;
    this.cdr.markForCheck();
  }

  private sortRows(rows: DetectionRow[]): DetectionRow[] {
    switch (this.sortBy) {
      case 'name':
        return [...rows].sort((a, b) => a.name.localeCompare(b.name));
      case 'tactic':
        return [...rows].sort((a, b) => a.tactic.localeCompare(b.tactic) || b.score - a.score);
      case 'score':
      default:
        return [...rows].sort((a, b) => b.score - a.score);
    }
  }
}

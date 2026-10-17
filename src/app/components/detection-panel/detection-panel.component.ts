// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { filter, take } from 'rxjs';
import { DataService } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import {
  ReferenceDepthBand,
  REFERENCE_DEPTH_BAND_LABELS,
  REFERENCE_DEPTH_BANDS,
  referenceDepthBand,
} from '../../models/reference-depth';

/**
 * Lowest weighted score (CAR×3 + D3FEND×2 + Atomic×1) for the thin, some,
 * deep and deepest reference-depth bands. These are the old Low / Medium /
 * High / Excellent grade boundaries; only the words changed (plan 4.1: no
 * grades on Known data).
 */
export const DETECTION_DEPTH_FLOORS = [1, 4, 7, 10] as const;

/** Range text shown next to each band in the summary bar. */
const DETECTION_BAND_RANGES: Readonly<Record<ReferenceDepthBand, string>> = {
  none: '0',
  thin: '1–3',
  some: '4–6',
  deep: '7–9',
  deepest: '10+',
};

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
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './detection-panel.component.html',
  styleUrl: './detection-panel.component.scss',
})
export class DetectionPanelComponent implements OnInit {
  activeTab: 'overview' | 'gaps' | 'top' | 'tactic' = 'overview';
  searchText = '';
  sortBy: 'score' | 'name' | 'tactic' = 'score';
  detectionRows: DetectionRow[] = [];
  readonly bands = REFERENCE_DEPTH_BANDS;
  readonly bandLabels = REFERENCE_DEPTH_BAND_LABELS;
  readonly bandRanges = DETECTION_BAND_RANGES;

  constructor(
    private dataService: DataService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private cdr: ChangeDetectorRef,
    private settingsService: SettingsService,
  ) {}

  ngOnInit(): void {
    this.buildRows();
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
      return { tactic, rows: rows.sort((a, b) => b.score - a.score), avgScore, expanded: this.settingsService.current.expandSectionsByDefault };
    }).sort((a, b) => b.avgScore - a.avgScore);
  }

  get maxScore(): number {
    return this.detectionRows.reduce((max, r) => Math.max(max, r.score), 0) || 1;
  }

  /** Techniques per reference-depth band, in REFERENCE_DEPTH_BANDS order. */
  get scoreDistribution(): number[] {
    const counts = this.bands.map(() => 0);
    for (const r of this.detectionRows) {
      counts[this.bands.indexOf(this.scoreBracket(r.score))]++;
    }
    return counts;
  }

  get totalWithDetection(): number {
    return this.detectionRows.filter(r => r.score > 0).length;
  }

  /** Reference-depth band of a weighted score. Known-rung wording, never a grade. */
  scoreBracket(score: number): ReferenceDepthBand {
    return referenceDepthBand(score, DETECTION_DEPTH_FLOORS);
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

import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  HostListener,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { TimelineService, CoverageSnapshot } from '../../services/timeline.service';

interface TacticDiff {
  tacticName: string;
  tacticId: string;
  oldCovered: number;
  oldTotal: number;
  oldPct: number;
  newCovered: number;
  newTotal: number;
  newPct: number;
  delta: number;
  deltaPct: number;
}

interface ImplDiff {
  label: string;
  oldCount: number;
  newCount: number;
  delta: number;
}

@Component({
  selector: 'app-coverage-diff-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './coverage-diff-panel.component.html',
  styleUrl: './coverage-diff-panel.component.scss',
})
export class CoverageDiffPanelComponent implements OnInit, OnDestroy {
  open = false;
  snapshots: CoverageSnapshot[] = [];

  selectedBaseId = '';
  selectedCompareId = '';

  tacticDiffs: TacticDiff[] = [];
  implDiffs: ImplDiff[] = [];

  baseSnap: CoverageSnapshot | null = null;
  compareSnap: CoverageSnapshot | null = null;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private timelineService: TimelineService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.open = p === 'coverage-diff';
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.timelineService.snapshots$.subscribe(snaps => {
        this.snapshots = snaps;
        if (snaps.length >= 2 && !this.selectedBaseId) {
          this.selectedBaseId = snaps[0].id;
          this.selectedCompareId = snaps[snaps.length - 1].id;
          this.compute();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  close(): void { this.filterService.setActivePanel(null); }

  onSelectionChange(): void { this.compute(); }

  compute(): void {
    this.baseSnap = this.snapshots.find(s => s.id === this.selectedBaseId) ?? null;
    this.compareSnap = this.snapshots.find(s => s.id === this.selectedCompareId) ?? null;

    if (!this.baseSnap || !this.compareSnap) {
      this.tacticDiffs = [];
      this.implDiffs = [];
      this.cdr.markForCheck();
      return;
    }

    const base = this.baseSnap;
    const comp = this.compareSnap;

    // Tactic diffs
    const tacticMap = new Map<string, { base?: CoverageSnapshot['tacticCoverage'][0]; comp?: CoverageSnapshot['tacticCoverage'][0] }>();
    for (const t of base.tacticCoverage) {
      tacticMap.set(t.tacticId, { base: t });
    }
    for (const t of comp.tacticCoverage) {
      const entry = tacticMap.get(t.tacticId) ?? {};
      entry.comp = t;
      tacticMap.set(t.tacticId, entry);
    }

    this.tacticDiffs = [...tacticMap.values()].map(entry => {
      const b = entry.base;
      const c = entry.comp;
      const name = b?.tacticName ?? c?.tacticName ?? 'Unknown';
      const id = b?.tacticId ?? c?.tacticId ?? '';
      const oldCovered = b?.covered ?? 0;
      const oldTotal = b?.total ?? 0;
      const oldPct = b?.pct ?? 0;
      const newCovered = c?.covered ?? 0;
      const newTotal = c?.total ?? 0;
      const newPct = c?.pct ?? 0;
      return {
        tacticName: name,
        tacticId: id,
        oldCovered, oldTotal, oldPct,
        newCovered, newTotal, newPct,
        delta: newCovered - oldCovered,
        deltaPct: newPct - oldPct,
      };
    }).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

    // Impl diffs
    const LABELS: Record<string, string> = {
      implemented: 'Implemented',
      inProgress: 'In Progress',
      planned: 'Planned',
      notStarted: 'Not Started',
    };
    this.implDiffs = Object.entries(LABELS).map(([key, label]) => ({
      label,
      oldCount: (base.implCounts as any)[key] ?? 0,
      newCount: (comp.implCounts as any)[key] ?? 0,
      delta: ((comp.implCounts as any)[key] ?? 0) - ((base.implCounts as any)[key] ?? 0),
    }));

    this.cdr.markForCheck();
  }

  get coverageDelta(): number {
    if (!this.baseSnap || !this.compareSnap) return 0;
    return this.compareSnap.coveragePct - this.baseSnap.coveragePct;
  }

  get techniqueDelta(): number {
    if (!this.baseSnap || !this.compareSnap) return 0;
    return this.compareSnap.coveredTechniques - this.baseSnap.coveredTechniques;
  }

  get isPositive(): boolean { return this.coverageDelta >= 0; }

  get maxTacticDelta(): number {
    return Math.max(1, ...this.tacticDiffs.map(t => Math.abs(t.delta)));
  }

  deltaBarWidth(delta: number): number {
    return (Math.abs(delta) / this.maxTacticDelta) * 100;
  }

  swapSnapshots(): void {
    const tmp = this.selectedBaseId;
    this.selectedBaseId = this.selectedCompareId;
    this.selectedCompareId = tmp;
    this.compute();
  }

  formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
    } catch { return iso; }
  }

  trackByTactic(_: number, t: TacticDiff): string { return t.tacticId; }

  @HostListener('document:keydown.escape')
  onEsc(): void { if (this.open) this.close(); }
}

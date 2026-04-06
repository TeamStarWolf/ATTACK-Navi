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
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService, CoverageSnapshot } from '../../services/timeline.service';

interface TrendPoint {
  snapshot: CoverageSnapshot;
  delta: number | null;
  implDelta: number | null;
}

interface ComparisonRow {
  tacticName: string;
  pctA: number;
  pctB: number;
  delta: number;
  coveredA: number;
  coveredB: number;
  total: number;
}

@Component({
  selector: 'app-timeline-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './timeline-panel.component.html',
  styleUrl: './timeline-panel.component.scss',
})
export class TimelinePanelComponent implements OnInit, OnDestroy {
  visible = false;
  snapshots: CoverageSnapshot[] = [];
  activeTab: 'timeline' | 'compare' | 'trends' = 'timeline';
  newLabel = '';
  newNotes = '';
  editingId: string | null = null;
  editLabel = '';
  editNotes = '';
  compareA: CoverageSnapshot | null = null;
  compareB: CoverageSnapshot | null = null;
  snapshotSuccess = false;

  private subs = new Subscription();
  private successTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private timelineService: TimelineService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'timeline';
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.timelineService.snapshots$.subscribe(snaps => {
        this.snapshots = snaps;
        // Reset compareA/compareB if they no longer exist
        if (this.compareA && !snaps.find(s => s.id === this.compareA!.id)) {
          this.compareA = null;
        }
        if (this.compareB && !snaps.find(s => s.id === this.compareB!.id)) {
          this.compareB = null;
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
    if (this.successTimer) clearTimeout(this.successTimer);
  }

  get snapshotsNewest(): CoverageSnapshot[] {
    return [...this.snapshots].reverse();
  }

  takeSnapshot(): void {
    if (!this.newLabel.trim()) return;
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const implMap = this.implService.getStatusMap();
      this.timelineService.takeSnapshot(this.newLabel, domain, implMap, this.newNotes);
      this.newLabel = '';
      this.newNotes = '';
      this.snapshotSuccess = true;
      this.cdr.markForCheck();
      if (this.successTimer) clearTimeout(this.successTimer);
      this.successTimer = setTimeout(() => {
        this.snapshotSuccess = false;
        this.cdr.markForCheck();
      }, 2500);
    });
  }

  deleteSnapshot(id: string): void {
    if (!confirm('Delete this snapshot? This cannot be undone.')) return;
    this.timelineService.deleteSnapshot(id);
    this.cdr.markForCheck();
  }

  startEdit(snapshot: CoverageSnapshot): void {
    this.editingId = snapshot.id;
    this.editLabel = snapshot.label;
    this.editNotes = snapshot.notes;
    this.cdr.markForCheck();
  }

  saveEdit(): void {
    if (!this.editingId || !this.editLabel.trim()) return;
    this.timelineService.updateLabel(this.editingId, this.editLabel);
    this.timelineService.updateNotes(this.editingId, this.editNotes);
    this.editingId = null;
    this.cdr.markForCheck();
  }

  cancelEdit(): void {
    this.editingId = null;
    this.cdr.markForCheck();
  }

  setQuickLabel(quarter: string): void {
    const year = new Date().getFullYear();
    this.newLabel = `${quarter} ${year}`;
    this.cdr.markForCheck();
  }

  setTab(tab: 'timeline' | 'compare' | 'trends'): void {
    this.activeTab = tab;
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  exportCsv(): void {
    this.timelineService.exportCsv();
  }

  setCompareA(id: string): void {
    this.compareA = this.snapshots.find(s => s.id === id) ?? null;
    this.cdr.markForCheck();
  }

  setCompareB(id: string): void {
    this.compareB = this.snapshots.find(s => s.id === id) ?? null;
    this.cdr.markForCheck();
  }

  formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return iso.slice(0, 10);
    }
  }

  /** Delta of coverage % between consecutive snapshots (ordered oldest→newest). */
  get trends(): TrendPoint[] {
    const sorted = [...this.snapshots]; // already oldest-first from service
    return sorted.map((snap, i) => {
      const prev = i > 0 ? sorted[i - 1] : null;
      const delta = prev != null ? snap.coveragePct - prev.coveragePct : null;
      const implDelta = prev != null
        ? snap.implCounts.implemented - prev.implCounts.implemented
        : null;
      return { snapshot: snap, delta, implDelta };
    });
  }

  get comparisonStats(): ComparisonRow[] | null {
    if (!this.compareA || !this.compareB) return null;
    const a = this.compareA;
    const b = this.compareB;

    // Build a map from tacticId → entry for each snapshot
    const mapA = new Map(a.tacticCoverage.map(t => [t.tacticId, t]));
    const mapB = new Map(b.tacticCoverage.map(t => [t.tacticId, t]));

    // Union of all tactic IDs
    const tacticIds = new Set([...mapA.keys(), ...mapB.keys()]);
    const rows: ComparisonRow[] = [];
    for (const tid of tacticIds) {
      const ta = mapA.get(tid);
      const tb = mapB.get(tid);
      rows.push({
        tacticName: (ta ?? tb)!.tacticName,
        pctA: ta?.pct ?? 0,
        pctB: tb?.pct ?? 0,
        delta: (tb?.pct ?? 0) - (ta?.pct ?? 0),
        coveredA: ta?.covered ?? 0,
        coveredB: tb?.covered ?? 0,
        total: Math.max(ta?.total ?? 0, tb?.total ?? 0),
      });
    }
    return rows.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
  }

  /** Biggest coverage % in all snapshots — for bar chart scaling. */
  get maxCoveragePct(): number {
    if (!this.snapshots.length) return 100;
    return Math.max(...this.snapshots.map(s => s.coveragePct), 1);
  }

  deltaClass(delta: number | null): string {
    if (delta == null) return '';
    if (delta > 0) return 'delta-pos';
    if (delta < 0) return 'delta-neg';
    return 'delta-zero';
  }

  deltaLabel(delta: number | null): string {
    if (delta == null) return '';
    if (delta > 0) return `+${delta}%`;
    if (delta < 0) return `${delta}%`;
    return '±0%';
  }
}

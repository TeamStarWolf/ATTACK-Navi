// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { ImplStatus } from './implementation.service';
// Type only: TimelineService sits in the initial bundle (export actions), so it
// must not pull EnrichmentService and its ten reference sources in with it.
import type { MappedRollup } from './enrichment.service';
import { csvRow } from '../utils/csv';

/**
 * What a snapshot's technique count means.
 * - 'reference-mapped' (E1.7 onwards): >=1 defensive reference input mapped,
 *   the Known-tier count from EnrichmentService.mappedRollup().
 * - absent: a snapshot saved before E1.7, which counted techniques with >=1
 *   ATT&CK mitigation only. Kept as saved; shown as 'mitigations only' and
 *   left out of the trend, so a change of basis never reads as progress.
 */
export type SnapshotBasis = 'reference-mapped';

export interface CoverageSnapshot {
  id: string;
  label: string;
  createdAt: string;
  totalTechniques: number;
  /** Techniques counted under `basis` (Known tier 'mapped' from E1.7). The name is the stored key. */
  coveredTechniques: number;
  coveragePct: number;
  basis?: SnapshotBasis;
  implCounts: {
    implemented: number;
    inProgress: number;
    planned: number;
    notStarted: number;
  };
  tacticCoverage: Array<{
    tacticName: string;
    tacticId: string;
    covered: number;
    total: number;
    pct: number;
  }>;
  notes: string;
}

/** Human label for a snapshot's count basis (CSV column, timeline and diff views). */
export function snapshotBasisLabel(s: Pick<CoverageSnapshot, 'basis'>): string {
  return s.basis === 'reference-mapped'
    ? 'mapped (defensive reference inputs)'
    : 'mitigations only (older snapshot)';
}

@Injectable({ providedIn: 'root' })
export class TimelineService {
  private readonly STORAGE_KEY = 'mitre-nav-timeline-v1';

  private snapshotsSubject = new BehaviorSubject<CoverageSnapshot[]>(this.load());
  snapshots$ = this.snapshotsSubject.asObservable();

  private load(): CoverageSnapshot[] {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed as CoverageSnapshot[];
    } catch {
      return [];
    }
  }

  private save(snapshots: CoverageSnapshot[]): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(snapshots));
    } catch { /* quota */ }
  }

  /**
   * Store a snapshot of the Known-tier 'mapped' rollup. The caller passes
   * EnrichmentService.mappedRollup(domain), the same rollup stats-bar,
   * tactic-summary, analytics-panel and roadmap-panel show (E1.7). P2 seam:
   * PostureService's Known / Covered / Proven rollup is stored here instead
   * (E9.2).
   */
  takeSnapshot(
    label: string,
    rollup: MappedRollup,
    implStatusMap: Map<string, ImplStatus>,
    notes = '',
  ): CoverageSnapshot {
    // Known tier ('mapped'): parent techniques with >=1 defensive reference input.
    const totalTechniques = rollup.overall.total;
    const coveredTechniques = rollup.overall.mapped;
    const coveragePct = rollup.overall.pct;

    // Count impl statuses for all mitigations that have been set
    let implemented = 0;
    let inProgress = 0;
    let planned = 0;
    let notStarted = 0;
    for (const status of implStatusMap.values()) {
      if (status === 'implemented') implemented++;
      else if (status === 'in-progress') inProgress++;
      else if (status === 'planned') planned++;
      else if (status === 'not-started') notStarted++;
    }

    // Per-tactic mapped counts (tactic columns hold parent techniques only)
    const tacticCoverage = rollup.byTactic.map(t => ({
      tacticName: t.tacticName,
      tacticId: t.tacticId,
      covered: t.mapped,
      total: t.total,
      pct: t.pct,
    }));

    const snapshot: CoverageSnapshot = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      label: label.trim(),
      createdAt: new Date().toISOString(),
      totalTechniques,
      coveredTechniques,
      coveragePct,
      basis: 'reference-mapped',
      implCounts: { implemented, inProgress, planned, notStarted },
      tacticCoverage,
      notes: notes.trim(),
    };

    const updated = [...this.snapshotsSubject.value, snapshot];
    this.save(updated);
    this.snapshotsSubject.next(updated);
    return snapshot;
  }

  deleteSnapshot(id: string): void {
    const updated = this.snapshotsSubject.value.filter(s => s.id !== id);
    this.save(updated);
    this.snapshotsSubject.next(updated);
  }

  updateLabel(id: string, label: string): void {
    const updated = this.snapshotsSubject.value.map(s =>
      s.id === id ? { ...s, label: label.trim() } : s,
    );
    this.save(updated);
    this.snapshotsSubject.next(updated);
  }

  updateNotes(id: string, notes: string): void {
    const updated = this.snapshotsSubject.value.map(s =>
      s.id === id ? { ...s, notes: notes.trim() } : s,
    );
    this.save(updated);
    this.snapshotsSubject.next(updated);
  }

  getAll(): CoverageSnapshot[] {
    return this.snapshotsSubject.value;
  }

  getStorageSizeKb(): number {
    const raw = localStorage.getItem(this.STORAGE_KEY) ?? '';
    return Math.round(raw.length / 1024);
  }

  getLatest(): CoverageSnapshot | null {
    const snaps = this.snapshotsSubject.value;
    return snaps.length > 0 ? snaps[snaps.length - 1] : null;
  }

  exportCsv(): void {
    const snapshots = this.snapshotsSubject.value;
    if (!snapshots.length) return;

    const header = 'ID,Label,Date,Total Techniques,Mapped Techniques,Mapped %,Count Basis,Implemented,In Progress,Planned,Not Started,Notes';
    const rows = snapshots.map(s => csvRow([
      s.id,
      s.label,
      s.createdAt,
      s.totalTechniques,
      s.coveredTechniques,
      s.coveragePct,
      snapshotBasisLabel(s),
      s.implCounts.implemented,
      s.implCounts.inProgress,
      s.implCounts.planned,
      s.implCounts.notStarted,
      s.notes,
    ]));

    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'coverage-timeline.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}

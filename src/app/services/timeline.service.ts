// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { Domain } from '../models/domain';
import { ImplStatus } from './implementation.service';

export interface CoverageSnapshot {
  id: string;
  label: string;
  createdAt: string;
  totalTechniques: number;
  coveredTechniques: number;
  coveragePct: number;
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

  takeSnapshot(
    label: string,
    domain: Domain,
    implStatusMap: Map<string, ImplStatus>,
    notes = '',
  ): CoverageSnapshot {
    const parentTechniques = domain.techniques.filter(t => !t.isSubtechnique);
    const totalTechniques = parentTechniques.length;

    // A technique is "covered" if it has at least one mitigation relationship
    const coveredTechniques = parentTechniques.filter(
      t => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0,
    ).length;

    const coveragePct = totalTechniques > 0
      ? Math.round((coveredTechniques / totalTechniques) * 100)
      : 0;

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

    // Per-tactic coverage
    const tacticCoverage = domain.tacticColumns.map(col => {
      const parents = col.techniques.filter(t => !t.isSubtechnique);
      const covered = parents.filter(
        t => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0,
      ).length;
      const total = parents.length;
      const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
      return {
        tacticName: col.tactic.name,
        tacticId: col.tactic.id,
        covered,
        total,
        pct,
      };
    });

    const snapshot: CoverageSnapshot = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      label: label.trim(),
      createdAt: new Date().toISOString(),
      totalTechniques,
      coveredTechniques,
      coveragePct,
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

  getLatest(): CoverageSnapshot | null {
    const snaps = this.snapshotsSubject.value;
    return snaps.length > 0 ? snaps[snaps.length - 1] : null;
  }

  exportCsv(): void {
    const snapshots = this.snapshotsSubject.value;
    if (!snapshots.length) return;

    const header = 'ID,Label,Date,Total Techniques,Covered Techniques,Coverage %,Implemented,In Progress,Planned,Not Started,Notes';
    const rows = snapshots.map(s => [
      s.id,
      `"${s.label.replace(/"/g, '""')}"`,
      s.createdAt,
      s.totalTechniques,
      s.coveredTechniques,
      s.coveragePct,
      s.implCounts.implemented,
      s.implCounts.inProgress,
      s.implCounts.planned,
      s.implCounts.notStarted,
      `"${s.notes.replace(/"/g, '""')}"`,
    ].join(','));

    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'coverage-timeline.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}

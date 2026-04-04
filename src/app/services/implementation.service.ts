import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export type ImplStatus = 'implemented' | 'in-progress' | 'planned' | 'not-started';

export const IMPL_STATUS_LABELS: Record<ImplStatus, string> = {
  'implemented': '✅ Implemented',
  'in-progress': '🔄 In Progress',
  'planned': '📋 Planned',
  'not-started': '❌ Not Started',
};

export const IMPL_STATUS_COLORS: Record<ImplStatus, string> = {
  'implemented': '#4caf50',
  'in-progress': '#ff9800',
  'planned': '#2196f3',
  'not-started': '#e53935',
};

const STORAGE_KEY = 'mitre-nav-impl-v1';

@Injectable({ providedIn: 'root' })
export class ImplementationService {
  private statusMapSubject = new BehaviorSubject<Map<string, ImplStatus>>(this.loadFromStorage());

  status$: Observable<Map<string, ImplStatus>> = this.statusMapSubject.asObservable();

  setStatus(mitigationId: string, status: ImplStatus | null): void {
    const next = new Map(this.statusMapSubject.value);
    if (status) next.set(mitigationId, status);
    else next.delete(mitigationId);
    this.statusMapSubject.next(next);
    this.saveToStorage(next);
  }

  getStatus(mitigationId: string): ImplStatus | null {
    return this.statusMapSubject.value.get(mitigationId) ?? null;
  }

  getImplementedIds(): Set<string> {
    const ids = new Set<string>();
    for (const [id, s] of this.statusMapSubject.value) {
      if (s === 'implemented') ids.add(id);
    }
    return ids;
  }

  getStatusMap(): Map<string, ImplStatus> {
    return this.statusMapSubject.value;
  }

  /** Count of mitigations by status */
  summarize(): Record<ImplStatus | 'untracked', number> {
    const counts: Record<string, number> = { implemented: 0, 'in-progress': 0, planned: 0, 'not-started': 0, untracked: 0 };
    for (const s of this.statusMapSubject.value.values()) counts[s]++;
    return counts as any;
  }

  exportJson(): string {
    return JSON.stringify([...this.statusMapSubject.value.entries()], null, 2);
  }

  importJson(json: string): void {
    const VALID_STATUSES = new Set<string>(['implemented', 'in-progress', 'planned', 'not-started']);
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) throw new Error('Invalid impl status data: expected array');
    const entries: [string, ImplStatus][] = parsed
      .filter((e) => Array.isArray(e) && e.length === 2 && typeof e[0] === 'string' && VALID_STATUSES.has(e[1]))
      .map((e) => [e[0], e[1] as ImplStatus]);
    const map = new Map(entries);
    this.statusMapSubject.next(map);
    this.saveToStorage(map);
  }

  resetAll(): void {
    this.statusMapSubject.next(new Map());
    localStorage.removeItem(STORAGE_KEY);
  }

  private loadFromStorage(): Map<string, ImplStatus> {
    const VALID_STATUSES = new Set<string>(['implemented', 'in-progress', 'planned', 'not-started']);
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return new Map();
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return new Map();
      const entries: [string, ImplStatus][] = parsed
        .filter((e: unknown) => Array.isArray(e) && (e as any[]).length === 2 && typeof (e as any[])[0] === 'string' && VALID_STATUSES.has((e as any[])[1]))
        .map((e: unknown) => [(e as any[])[0], (e as any[])[1] as ImplStatus]);
      return new Map(entries);
    } catch {
      return new Map();
    }
  }

  private saveToStorage(map: Map<string, ImplStatus>): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...map.entries()]));
    } catch { /* quota */ }
  }
}

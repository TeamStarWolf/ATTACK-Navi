import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface DashboardWidget {
  id: string;
  label: string;
  icon: string;
  visible: boolean;
  order: number;
}

const STORAGE_KEY = 'mitre-nav-dashboard-config-v1';

const DEFAULT_WIDGETS: DashboardWidget[] = [
  { id: 'coverage-summary',   label: 'Coverage Summary',   icon: '\u{1F6E1}',  visible: true,  order: 0 },
  { id: 'tactic-breakdown',   label: 'Tactic Breakdown',   icon: '\u{1F4CA}',  visible: true,  order: 1 },
  { id: 'radar-chart',        label: 'Radar Chart',        icon: '\u{1F3AF}',  visible: true,  order: 2 },
  { id: 'gap-summary',        label: 'Top Gaps',           icon: '\u26A0',     visible: true,  order: 3 },
  { id: 'data-health',        label: 'Data Source Health',  icon: '\u{1F49A}',  visible: true,  order: 4 },
  { id: 'intel-summary',      label: 'Intel Summary',      icon: '\u{1F9E0}',  visible: true,  order: 5 },
  { id: 'detection-summary',  label: 'Detection Coverage', icon: '\u{1F52C}',  visible: true,  order: 6 },
  { id: 'recent-cves',        label: 'Recent KEV CVEs',    icon: '\u{1F534}',  visible: true,  order: 7 },
  { id: 'impl-status',        label: 'Implementation Status', icon: '\u2705', visible: true,  order: 8 },
  { id: 'quick-actions',      label: 'Quick Actions',      icon: '\u26A1',     visible: false, order: 9 },
];

@Injectable({ providedIn: 'root' })
export class DashboardConfigService {
  private widgetsSubject: BehaviorSubject<DashboardWidget[]>;
  readonly widgets$: Observable<DashboardWidget[]>;

  constructor() {
    const saved = this.loadFromStorage();
    this.widgetsSubject = new BehaviorSubject<DashboardWidget[]>(saved ?? this.cloneDefaults());
    this.widgets$ = this.widgetsSubject.asObservable();
  }

  getWidgets(): DashboardWidget[] {
    return this.widgetsSubject.value;
  }

  getVisibleWidgets(): DashboardWidget[] {
    return this.widgetsSubject.value
      .filter(w => w.visible)
      .sort((a, b) => a.order - b.order);
  }

  toggleWidget(id: string): void {
    const widgets = this.widgetsSubject.value.map(w =>
      w.id === id ? { ...w, visible: !w.visible } : w,
    );
    this.update(widgets);
  }

  moveWidget(id: string, direction: 'up' | 'down'): void {
    const widgets = [...this.widgetsSubject.value].sort((a, b) => a.order - b.order);
    const idx = widgets.findIndex(w => w.id === id);
    if (idx < 0) return;

    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= widgets.length) return;

    // Swap orders
    const tmp = widgets[idx].order;
    widgets[idx] = { ...widgets[idx], order: widgets[swapIdx].order };
    widgets[swapIdx] = { ...widgets[swapIdx], order: tmp };

    this.update(widgets);
  }

  resetDefaults(): void {
    this.update(this.cloneDefaults());
  }

  private update(widgets: DashboardWidget[]): void {
    this.widgetsSubject.next(widgets);
    this.saveToStorage(widgets);
  }

  private cloneDefaults(): DashboardWidget[] {
    return DEFAULT_WIDGETS.map(w => ({ ...w }));
  }

  private loadFromStorage(): DashboardWidget[] | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as DashboardWidget[];
      if (!Array.isArray(parsed) || parsed.length === 0) return null;

      // Merge with defaults to pick up any new widgets added after the user saved
      const savedMap = new Map(parsed.map(w => [w.id, w]));
      const merged: DashboardWidget[] = DEFAULT_WIDGETS.map(def => {
        const saved = savedMap.get(def.id);
        return saved ? { ...def, visible: saved.visible, order: saved.order } : { ...def };
      });
      return merged;
    } catch {
      return null;
    }
  }

  private saveToStorage(widgets: DashboardWidget[]): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(widgets));
    } catch {
      // localStorage unavailable — ignore
    }
  }
}

// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface ReportSection {
  id: string;
  label: string;
  visible: boolean;
  order: number;
}

export interface ReportConfig {
  sections: ReportSection[];
}

const STORAGE_KEY = 'mitre-nav-report-config-v1';

// Section ids match the six <section>s the Report Builder renders
// (report-panel.component.html). The HTML exporter gates + orders its own six
// sections by these ids too, though two map to differently-titled export
// sections (control-docs → "Top 10 Best Covered Techniques", recommended-mits →
// "Mitigation Implementation Progress") — an approximate mapping documented on
// the PR; exec-summary / coverage-by-tactic / impl-status / exposure-gaps align.
const DEFAULT_SECTIONS: ReportSection[] = [
  { id: 'exec-summary',       label: 'Executive Summary',               visible: true, order: 0 },
  { id: 'impl-status',        label: 'Implementation Status Breakdown', visible: true, order: 1 },
  { id: 'coverage-by-tactic', label: 'Coverage by Tactic',              visible: true, order: 2 },
  { id: 'exposure-gaps',      label: 'Highest Exposure Gaps',           visible: true, order: 3 },
  { id: 'control-docs',       label: 'Security Control Documentation',  visible: true, order: 4 },
  { id: 'recommended-mits',   label: 'Recommended Next Mitigations',    visible: true, order: 5 },
];

export const DEFAULT_REPORT_CONFIG: ReportConfig = {
  sections: DEFAULT_SECTIONS.map(s => ({ ...s })),
};

@Injectable({ providedIn: 'root' })
export class ReportConfigService {
  private configSubject: BehaviorSubject<ReportConfig>;
  readonly config$: Observable<ReportConfig>;

  constructor() {
    const saved = this.loadFromStorage();
    this.configSubject = new BehaviorSubject<ReportConfig>(saved ?? this.cloneDefaults());
    this.config$ = this.configSubject.asObservable();
  }

  get current(): ReportConfig {
    return this.configSubject.value;
  }

  getSections(): ReportSection[] {
    return this.configSubject.value.sections;
  }

  orderedVisibleSections(): ReportSection[] {
    return this.configSubject.value.sections
      .filter(s => s.visible)
      .sort((a, b) => a.order - b.order);
  }

  toggleSection(id: string): void {
    const sections = this.configSubject.value.sections.map(s =>
      s.id === id ? { ...s, visible: !s.visible } : s,
    );
    this.update({ sections });
  }

  moveSection(id: string, direction: 'up' | 'down'): void {
    const sections = [...this.configSubject.value.sections].sort((a, b) => a.order - b.order);
    const idx = sections.findIndex(s => s.id === id);
    if (idx < 0) return;

    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= sections.length) return;

    // Swap orders
    const tmp = sections[idx].order;
    sections[idx] = { ...sections[idx], order: sections[swapIdx].order };
    sections[swapIdx] = { ...sections[swapIdx], order: tmp };

    this.update({ sections });
  }

  resetDefaults(): void {
    this.update(this.cloneDefaults());
  }

  private update(config: ReportConfig): void {
    this.configSubject.next(config);
    this.saveToStorage(config);
  }

  private cloneDefaults(): ReportConfig {
    return { sections: DEFAULT_SECTIONS.map(s => ({ ...s })) };
  }

  private loadFromStorage(): ReportConfig | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as ReportConfig;
      if (!parsed || !Array.isArray(parsed.sections) || parsed.sections.length === 0) return null;

      // Merge with defaults to pick up any new section added after the user saved
      const savedMap = new Map(parsed.sections.map(s => [s.id, s]));
      const merged: ReportSection[] = DEFAULT_SECTIONS.map(def => {
        const saved = savedMap.get(def.id);
        return saved ? { ...def, visible: saved.visible, order: saved.order } : { ...def };
      });
      return { sections: merged };
    } catch {
      return null;
    }
  }

  private saveToStorage(config: ReportConfig): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    } catch {
      // localStorage unavailable — ignore
    }
  }
}

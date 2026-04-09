// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface AppSettings {
  // Scoring weights (normalized to sum to 100)
  scoringWeights: {
    mitigations: number;  // default 40
    car: number;          // default 20
    atomic: number;       // default 15
    d3fend: number;       // default 15
    nist: number;         // default 10
  };

  // Display preferences
  matrixCellSize: 'compact' | 'normal' | 'large';  // default 'normal'
  showTechniqueIds: boolean;     // default true
  showMitigationCount: boolean;  // default true
  showSubtechniqueCount: boolean;// default true

  // Heatmap color theme
  heatmapColorTheme: 'default' | 'redgreen' | 'blueorange' | 'monochrome' | 'accessible';

  // Organization info for reports
  orgName: string;   // default ''
  orgLogo: string;   // base64 data URL, default ''

  // Data (read-only display)
  attackVersion: string;  // default ''

  // API integrations
  nvdApiKey: string;   // default ''
}

export const DEFAULT_SETTINGS: AppSettings = {
  scoringWeights: { mitigations: 40, car: 20, atomic: 15, d3fend: 15, nist: 10 },
  matrixCellSize: 'normal',
  showTechniqueIds: true,
  showMitigationCount: true,
  showSubtechniqueCount: true,
  heatmapColorTheme: 'default',
  orgName: '',
  orgLogo: '',
  attackVersion: '',
  nvdApiKey: '',
};

@Injectable({ providedIn: 'root' })
export class SettingsService {
  private readonly STORAGE_KEY = 'mitre-nav-settings-v1';
  private settingsSubject = new BehaviorSubject<AppSettings>(this.load());
  settings$ = this.settingsSubject.asObservable();

  readonly COLOR_THEMES: Record<string, string[]> = {
    default:    ['#d32f2f', '#e65100', '#f9a825', '#558b2f', '#1b5e20'],
    redgreen:   ['#dc2626', '#f97316', '#eab308', '#16a34a', '#15803d'],
    blueorange: ['#1d4ed8', '#2563eb', '#0ea5e9', '#f59e0b', '#d97706'],
    monochrome: ['#111827', '#374151', '#6b7280', '#9ca3af', '#e5e7eb'],
    accessible: ['#cc0000', '#ff6600', '#ffcc00', '#006600', '#003300'],
  };

  getCoverageColors(): string[] {
    return this.COLOR_THEMES[this.current.heatmapColorTheme ?? 'default'];
  }

  get current(): AppSettings {
    return this.settingsSubject.value;
  }

  update(partial: Partial<AppSettings>): void {
    const merged: AppSettings = {
      ...this.settingsSubject.value,
      ...partial,
      scoringWeights: partial.scoringWeights
        ? { ...this.settingsSubject.value.scoringWeights, ...partial.scoringWeights }
        : this.settingsSubject.value.scoringWeights,
    };
    this.save(merged);
    this.settingsSubject.next(merged);
  }

  setNvdApiKey(key: string): void {
    this.update({ nvdApiKey: key });
  }

  updateWeights(weights: Partial<AppSettings['scoringWeights']>): void {
    const merged: AppSettings['scoringWeights'] = {
      ...this.settingsSubject.value.scoringWeights,
      ...weights,
    };
    this.update({ scoringWeights: merged });
  }

  reset(): void {
    const resetSettings: AppSettings = {
      ...DEFAULT_SETTINGS,
      attackVersion: this.settingsSubject.value.attackVersion,
    };
    this.save(resetSettings);
    this.settingsSubject.next(resetSettings);
  }

  getNormalizedWeights(): AppSettings['scoringWeights'] {
    const w = this.settingsSubject.value.scoringWeights;
    const total = w.mitigations + w.car + w.atomic + w.d3fend + w.nist;
    if (total === 0) {
      return { mitigations: 20, car: 20, atomic: 20, d3fend: 20, nist: 20 };
    }
    const factor = 100 / total;
    return {
      mitigations: Math.round(w.mitigations * factor),
      car: Math.round(w.car * factor),
      atomic: Math.round(w.atomic * factor),
      d3fend: Math.round(w.d3fend * factor),
      nist: Math.round(w.nist * factor),
    };
  }

  private load(): AppSettings {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return { ...DEFAULT_SETTINGS };
      const parsed = JSON.parse(raw) as Partial<AppSettings>;
      return {
        ...DEFAULT_SETTINGS,
        ...parsed,
        scoringWeights: {
          ...DEFAULT_SETTINGS.scoringWeights,
          ...(parsed.scoringWeights ?? {}),
        },
      };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  private save(s: AppSettings): void {
    try {
      // Strip sensitive credentials before persisting
      const { nvdApiKey: _omit, ...safe } = s;
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(safe));
    } catch { /* quota exceeded — silently ignore */ }
  }
}

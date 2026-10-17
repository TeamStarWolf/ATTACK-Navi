// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { SAFE_COVERAGE } from '../models/safe-palette';

export interface AppSettings {
  // E1.5 removed the user-set 'scoringWeights' (plan 4.1: no Coverage Score and
  // no grade on reference data). A stored copy from an older version is
  // dropped on load and never written back.

  // Display preferences
  matrixCellSize: 'compact' | 'normal' | 'large';  // default 'normal'
  showTechniqueIds: boolean;     // default true
  showMitigationCount: boolean;  // default true
  showSubtechniqueCount: boolean;// default true
  expandSectionsByDefault: boolean; // default true — collapsible panel sections start expanded

  // Heatmap color theme
  heatmapColorTheme: 'default' | 'redgreen' | 'blueorange' | 'monochrome' | 'accessible';

  // Colorblind-safe heatmaps: swap ALL heatmap ramps for viridis (sequential)
  // and Okabe-Ito (categorical) — not just the coverage theme.
  colorblindSafe: boolean;   // default false

  // Organization info for reports
  orgName: string;   // default ''
  orgLogo: string;   // base64 data URL, default ''

  // Data (read-only display)
  attackVersion: string;  // default ''

  // ATT&CK data mode (decision D2): 'bundled' loads only the pinned bundle; 'live' also
  // checks MITRE for a newer release when data loads and offers it, never applying it
  // without a click. DataService follows this setting (see DataSourceMode).
  attackDataMode: 'bundled' | 'live';  // default 'bundled'

  // API integrations
  nvdApiKey: string;   // default ''
  // Credentials-proxy access token (server/ PROXY_AUTH_TOKEN). Sent as X-Proxy-Key
  // on every proxy-mode OpenCTI/MISP request. Session-only like the NVD key.
  proxyToken: string;  // default ''

  // Per-cell display toggles: choose which fields/badges render inside each
  // matrix technique cell. Every flag defaults true so cells look identical
  // to today (no visual regression). Personal preference — deliberately NOT
  // wired into shareable URL state.
  cellDisplay: {
    exposureBadge: boolean; softwareBadge: boolean; campaignBadge: boolean;
    metricBadge: boolean;   // the mode-gated d3fend/atomic/cri badge
    noteDot: boolean; annotationDot: boolean; watchIndicator: boolean;
  };
}

export const DEFAULT_SETTINGS: AppSettings = {
  matrixCellSize: 'normal',
  showTechniqueIds: true,
  showMitigationCount: true,
  showSubtechniqueCount: true,
  expandSectionsByDefault: true,
  heatmapColorTheme: 'default',
  colorblindSafe: false,
  orgName: '',
  orgLogo: '',
  attackVersion: '',
  attackDataMode: 'bundled',
  nvdApiKey: '',
  proxyToken: '',
  cellDisplay: {
    exposureBadge: true, softwareBadge: true, campaignBadge: true,
    metricBadge: true,
    noteDot: true, annotationDot: true, watchIndicator: true,
  },
};

@Injectable({ providedIn: 'root' })
export class SettingsService {
  private readonly STORAGE_KEY = 'mitre-nav-settings-v1';
  private settingsSubject = new BehaviorSubject<AppSettings>(this.load());
  settings$ = this.settingsSubject.asObservable();

  readonly COLOR_THEMES: Record<string, string[]> = {
    // #b45309 (was #e65100): the old orange was a contrast dead zone — neither
    // black nor white text reached WCAG AA on it (axe: 37 cells at 4.24:1).
    default:    ['#d32f2f', '#b45309', '#f9a825', '#558b2f', '#1b5e20'],
    redgreen:   ['#dc2626', '#f97316', '#eab308', '#16a34a', '#15803d'],
    blueorange: ['#1d4ed8', '#2563eb', '#0ea5e9', '#f59e0b', '#d97706'],
    monochrome: ['#111827', '#374151', '#6b7280', '#9ca3af', '#e5e7eb'],
    // Viridis: monotonic-luminance, CVD-safe. (The previous 'accessible'
    // values were a red→green ramp — the exact confusion axis for the most
    // common color-vision deficiency — i.e. mislabeled.)
    accessible: SAFE_COVERAGE,
  };

  getCoverageColors(): string[] {
    if (this.current.colorblindSafe) return SAFE_COVERAGE;
    return this.COLOR_THEMES[this.current.heatmapColorTheme ?? 'default'];
  }

  get current(): AppSettings {
    return this.settingsSubject.value;
  }

  update(partial: Partial<AppSettings>): void {
    const merged: AppSettings = {
      ...this.settingsSubject.value,
      ...partial,
    };
    this.save(merged);
    this.settingsSubject.next(merged);
  }

  setNvdApiKey(key: string): void {
    this.update({ nvdApiKey: key });
  }

  setProxyToken(token: string): void {
    this.update({ proxyToken: token.trim() });
  }

  reset(): void {
    const resetSettings: AppSettings = {
      ...DEFAULT_SETTINGS,
      attackVersion: this.settingsSubject.value.attackVersion,
    };
    this.save(resetSettings);
    this.settingsSubject.next(resetSettings);
  }

  private load(): AppSettings {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      const sessionKey = sessionStorage.getItem(this.STORAGE_KEY + '-key') ?? '';
      const sessionProxyToken = sessionStorage.getItem(this.STORAGE_KEY + '-proxy-token') ?? '';
      if (!raw) {
        return { ...DEFAULT_SETTINGS, nvdApiKey: sessionKey, proxyToken: sessionProxyToken };
      }
      // 'scoringWeights' is a retired key (E1.5): drop it so it is never saved again.
      const { scoringWeights: _retired, ...parsed } = JSON.parse(raw) as Partial<AppSettings> & { scoringWeights?: unknown };
      return {
        ...DEFAULT_SETTINGS,
        ...parsed,
        nvdApiKey: sessionKey,          // Always sourced from sessionStorage
        proxyToken: sessionProxyToken,  // Always sourced from sessionStorage
        cellDisplay: {
          ...DEFAULT_SETTINGS.cellDisplay,
          ...(parsed.cellDisplay ?? {}),
        },
      };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  private save(s: AppSettings): void {
    try {
      // Strip sensitive credentials from localStorage; persist them in sessionStorage
      // (survives page refresh but not browser restart, and never persists to disk)
      const { nvdApiKey, proxyToken, ...safe } = s;
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(safe));
      if (nvdApiKey) {
        sessionStorage.setItem(this.STORAGE_KEY + '-key', nvdApiKey);
      } else {
        sessionStorage.removeItem(this.STORAGE_KEY + '-key');
      }
      if (proxyToken) {
        sessionStorage.setItem(this.STORAGE_KEY + '-proxy-token', proxyToken);
      } else {
        sessionStorage.removeItem(this.STORAGE_KEY + '-proxy-token');
      }
    } catch { /* quota exceeded — silently ignore */ }
  }
}

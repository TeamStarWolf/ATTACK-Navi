// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

/**
 * Full-workspace export/import: every piece of user work-product the app
 * persists to localStorage, gathered into one portable JSON bundle. This is
 * the "move machines / share a complete setup / disaster backup" feature —
 * distinct from per-feature exports (layers, controls, state JSON).
 *
 * Values are carried as opaque strings (whatever each service serialized),
 * so this service needs no knowledge of individual schemas and stays
 * forward-compatible as services version their own keys.
 *
 * SECURITY: integration credentials are deliberately excluded — misp_config
 * and opencti_config are never exported, and the NVD API key is stripped
 * from the settings payload. A workspace bundle must be safe to hand to a
 * teammate.
 */
@Injectable({ providedIn: 'root' })
export class WorkspaceBundleService {
  /** User work-product + preferences. Order is cosmetic (export readability). */
  static readonly BUNDLED_KEYS: readonly string[] = [
    // Analysis state
    'mitre-nav-impl-v1',
    'mitre-nav-docs-tech-v1',
    'mitre-nav-docs-mit-v1',
    'mitre-nav-annotations-v1',
    'mitre-nav-tags-v1',
    'mitre-nav-watchlist-v1',
    // Coverage program
    'mitre-nav-controls-v1',
    'mitre-nav-custom-mitigations-v1',
    'mitre-nav-timeline-v1',
    'mitre-nav-assets-v1',
    'attacknavi.telemetry-coverage.v1',
    'attacknavi.validation-runs.v1',
    // Custom entities & plans
    'mitre-nav-custom-techniques-v1',
    'mitre-nav-custom-groups-v1',
    'mitre-nav-emulation-plans',
    // Saved work
    'mitre-nav-layers-v1',
    'mitre-nav-views-v1',
    'mitre-nav-dashboard-config-v1',
    'mitre-nav-taxii-v1',
    // Preferences & UX state
    'mitre-nav-settings-v1',           // NVD key stripped on export
    'mitre-nav-theme',
    'matrix-context-strip',
    'mitre-nav-quick-filters-expanded',
    'palette-frecency-v1',
    'onboarding-completed',
  ];

  exportBundle(): string {
    const data: Record<string, string> = {};
    for (const key of WorkspaceBundleService.BUNDLED_KEYS) {
      const value = localStorage.getItem(key);
      if (value === null) continue;
      data[key] = key === 'mitre-nav-settings-v1' ? this.stripSecrets(value) : value;
    }
    return JSON.stringify(
      {
        format: 'attack-navi-workspace',
        version: 1,
        exported: new Date().toISOString(),
        keyCount: Object.keys(data).length,
        data,
      },
      null,
      2,
    );
  }

  /**
   * Restores a bundle. Returns the number of keys applied. The caller should
   * reload the app afterwards — services hydrate from storage at startup.
   * @throws Error on an unrecognized or malformed payload.
   */
  importBundle(json: string): number {
    let parsed: any;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('Not valid JSON.');
    }
    if (parsed?.format !== 'attack-navi-workspace' || typeof parsed.data !== 'object' || parsed.data === null) {
      throw new Error('Not an ATTACK-Navi workspace bundle.');
    }
    if (parsed.version !== 1) {
      throw new Error(`Unsupported bundle version: ${parsed.version}.`);
    }
    const allowed = new Set(WorkspaceBundleService.BUNDLED_KEYS);
    let applied = 0;
    for (const [key, value] of Object.entries(parsed.data)) {
      // Only whitelisted keys — a crafted bundle can't write arbitrary storage.
      if (!allowed.has(key) || typeof value !== 'string') continue;
      const cleaned = key === 'mitre-nav-settings-v1' ? this.stripSecrets(value) : value;
      localStorage.setItem(key, cleaned);
      applied++;
    }
    return applied;
  }

  downloadBundle(): void {
    const blob = new Blob([this.exportBundle()], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `attack-navi-workspace-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /** Remove credential material from a serialized settings payload. */
  private stripSecrets(settingsJson: string): string {
    try {
      const settings = JSON.parse(settingsJson);
      delete settings.nvdApiKey;
      return JSON.stringify(settings);
    } catch {
      return settingsJson;
    }
  }
}

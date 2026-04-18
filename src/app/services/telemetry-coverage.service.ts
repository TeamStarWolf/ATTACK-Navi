// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { EventLoggingService, LogConfig } from './event-logging.service';

/** Stable key used for a (source, eventId) pair across techniques. */
export function telemetryKey(source: string, eventId: string): string {
  return `${source}::${eventId}`;
}

export interface TelemetrySourceRow {
  /** Stable key for set lookup. */
  key: string;
  source: string;
  eventId: string;
  description?: string;
  /** True when the operator has marked this source as configured in the SIEM. */
  configured: boolean;
  /** ATT&CK techniques that require this source. */
  techniques: string[];
}

interface PersistedShape {
  configured: string[];
}

const STORAGE_KEY = 'attacknavi.telemetry-coverage.v1';

/**
 * Tracks which Windows event-log sources the organisation has actually wired
 * into its SIEM. Powers the Telemetry Coverage Matrix in the Validation
 * Workbench so analysts can see — *before* running a single attack — whether
 * the necessary log streams exist to detect the techniques they care about.
 */
@Injectable({ providedIn: 'root' })
export class TelemetryCoverageService {
  private eventLog = inject(EventLoggingService);
  private configured = new Set<string>();

  private statusSubject = new BehaviorSubject<Set<string>>(new Set<string>());
  /** Emits whenever a source is toggled. Subscribers receive the *current* configured set. */
  readonly status$ = this.statusSubject.asObservable();

  constructor() {
    this.load();
  }

  /** Build the full matrix: every required log source, with the techniques that need it. */
  buildMatrix(): TelemetrySourceRow[] {
    const byKey = new Map<string, TelemetrySourceRow>();
    for (const techId of this.eventLog.getAllMappedTechniques()) {
      const configs = this.eventLog.getLoggingConfig(techId);
      for (const c of configs) {
        const key = telemetryKey(c.source, c.eventId);
        const row = byKey.get(key);
        if (row) {
          if (!row.techniques.includes(techId)) row.techniques.push(techId);
        } else {
          byKey.set(key, {
            key,
            source: c.source,
            eventId: c.eventId,
            description: c.description,
            configured: this.configured.has(key),
            techniques: [techId],
          });
        }
      }
    }
    // Sort: highest-impact (most techniques needing it) first; configured rows last when tied
    return [...byKey.values()].sort((a, b) =>
      b.techniques.length - a.techniques.length ||
      Number(a.configured) - Number(b.configured) ||
      a.source.localeCompare(b.source),
    );
  }

  /** True if the operator has marked this source as configured. */
  isConfigured(key: string): boolean {
    return this.configured.has(key);
  }

  /** Toggle a source on or off. Persists immediately. */
  toggle(key: string): void {
    if (this.configured.has(key)) this.configured.delete(key);
    else this.configured.add(key);
    this.persist();
  }

  /** Explicitly set a source's status. */
  setStatus(key: string, configured: boolean): void {
    if (configured) this.configured.add(key);
    else this.configured.delete(key);
    this.persist();
  }

  /** Reset all coverage to "not configured". */
  clearAll(): void {
    this.configured.clear();
    this.persist();
  }

  /**
   * Returns coverage stats over all distinct (source, eventId) pairs that any
   * mapped technique requires.
   */
  summary(): { total: number; configured: number; pct: number } {
    const matrix = this.buildMatrix();
    const total = matrix.length;
    const configured = matrix.filter(r => r.configured).length;
    return { total, configured, pct: total === 0 ? 0 : Math.round((configured / total) * 100) };
  }

  /**
   * Per-technique coverage: how many of the technique's required sources are configured.
   * Returns 1.0 when the technique has no telemetry mapping (vacuously covered).
   */
  techniqueCoverage(attackId: string): { configured: number; required: number; pct: number } {
    const configs = this.eventLog.getLoggingConfig(attackId);
    const required = configs.length;
    if (required === 0) return { configured: 0, required: 0, pct: 100 };
    const configured = configs.filter((c: LogConfig) => this.configured.has(telemetryKey(c.source, c.eventId))).length;
    return { configured, required, pct: Math.round((configured / required) * 100) };
  }

  // ─── Persistence ──────────────────────────────────────────────────────────

  private persist(): void {
    try {
      const shape: PersistedShape = { configured: [...this.configured] };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(shape));
    } catch {
      // localStorage may be unavailable (private mode, full quota); fail silent
    }
    this.statusSubject.next(new Set(this.configured));
  }

  private load(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw) as PersistedShape;
      if (parsed && Array.isArray(parsed.configured)) {
        this.configured = new Set(parsed.configured.filter(k => typeof k === 'string'));
        this.statusSubject.next(new Set(this.configured));
      }
    } catch {
      // Malformed storage — start clean
      this.configured = new Set();
    }
  }
}

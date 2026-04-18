// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export type ValidationStatus = 'passed' | 'failed' | 'partial' | 'no-telemetry' | 'untested';

/**
 * One detection-validation run for a single ATT&CK technique.
 * Captures the full purple-team loop: telemetry available → atomic test executed
 * → which detection sources fired → response actions taken → evidence artifacts.
 */
export interface ValidationRun {
  id: string;                  // uuid
  techniqueId: string;         // T1003.001
  techniqueName: string;       // "LSASS Memory"
  runDate: string;             // ISO timestamp
  operator: string;            // who ran it (free-text, optional)

  // 1. Telemetry — was the required logging actually present?
  telemetryRequired: string[];   // e.g. ["Sysmon Event 10", "Windows Security 4624"]
  telemetryAvailable: string[];  // subset of required that were observed in env

  // 2. Attack — what was actually executed
  atomicTestId: string;        // "AT-001" or empty
  atomicCommand: string;       // raw invoke command (for evidence)
  attackResult: 'executed' | 'failed-prereq' | 'blocked' | 'errored';

  // 3. Detection — which sources fired
  detectionsExpected: string[]; // e.g. ["sigma:lsass-dump", "splunk:cred-dump-spl"]
  detectionsFired: string[];    // subset that actually fired

  // 4. Response — what happened next
  responsePlaybook: string;    // free-text or "ir-playbook:T1003.001"
  responseActions: string[];   // ["isolated host", "rotated creds", "filed ticket #123"]

  // 5. Evidence
  evidenceLinks: string[];     // URLs to screenshots / S3 artifacts / wiki pages
  notes: string;               // free-text postmortem

  status: ValidationStatus;
}

const STORAGE_KEY = 'attacknavi.validation-runs.v1';

@Injectable({ providedIn: 'root' })
export class ValidationService {
  private runsSubject = new BehaviorSubject<ValidationRun[]>(this.load());
  readonly runs$: Observable<ValidationRun[]> = this.runsSubject.asObservable();

  private load(): ValidationRun[] {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    } catch {
      return [];
    }
  }

  private save(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.runsSubject.value));
    } catch {
      // localStorage full or disabled — skip
    }
  }

  private newId(): string {
    return typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `vr-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }

  /** All runs in storage. */
  get all(): ValidationRun[] {
    return this.runsSubject.value;
  }

  /** Runs for a specific technique. */
  forTechnique(techniqueId: string): ValidationRun[] {
    return this.runsSubject.value.filter(r => r.techniqueId === techniqueId);
  }

  /** Most recent run for a technique, or null. */
  latestFor(techniqueId: string): ValidationRun | null {
    const runs = this.forTechnique(techniqueId);
    if (runs.length === 0) return null;
    return runs.reduce((latest, r) => (r.runDate > latest.runDate ? r : latest));
  }

  /** Compute status from telemetry/detection/response inputs. */
  computeStatus(input: {
    telemetryRequired: string[];
    telemetryAvailable: string[];
    detectionsExpected: string[];
    detectionsFired: string[];
  }): ValidationStatus {
    if (
      input.telemetryRequired.length > 0 &&
      input.telemetryAvailable.length === 0
    ) {
      return 'no-telemetry';
    }
    if (input.detectionsExpected.length === 0) {
      return 'untested';
    }
    const fired = input.detectionsFired.length;
    const expected = input.detectionsExpected.length;
    if (fired === 0) return 'failed';
    if (fired === expected) return 'passed';
    return 'partial';
  }

  /** Add a new run. Returns the saved run with an id assigned. */
  record(partial: Omit<ValidationRun, 'id' | 'runDate' | 'status'> & { runDate?: string }): ValidationRun {
    const run: ValidationRun = {
      id: this.newId(),
      runDate: partial.runDate ?? new Date().toISOString(),
      status: this.computeStatus(partial),
      ...partial,
    };
    this.runsSubject.next([...this.runsSubject.value, run]);
    this.save();
    return run;
  }

  /** Update an existing run by id. */
  update(id: string, patch: Partial<ValidationRun>): void {
    const list = this.runsSubject.value.map(r => {
      if (r.id !== id) return r;
      const merged = { ...r, ...patch };
      // Recompute status if any of the inputs changed
      if (
        patch.telemetryRequired !== undefined ||
        patch.telemetryAvailable !== undefined ||
        patch.detectionsExpected !== undefined ||
        patch.detectionsFired !== undefined
      ) {
        merged.status = this.computeStatus({
          telemetryRequired: merged.telemetryRequired,
          telemetryAvailable: merged.telemetryAvailable,
          detectionsExpected: merged.detectionsExpected,
          detectionsFired: merged.detectionsFired,
        });
      }
      return merged;
    });
    this.runsSubject.next(list);
    this.save();
  }

  /** Delete a run by id. */
  delete(id: string): void {
    this.runsSubject.next(this.runsSubject.value.filter(r => r.id !== id));
    this.save();
  }

  /** Aggregate counts grouped by status across all runs. */
  statusCounts(): Record<ValidationStatus, number> {
    const counts: Record<ValidationStatus, number> = {
      passed: 0, failed: 0, partial: 0, 'no-telemetry': 0, untested: 0,
    };
    for (const r of this.runsSubject.value) counts[r.status]++;
    return counts;
  }

  /** Count of distinct techniques with at least one validation. */
  uniqueTechniqueCount(): number {
    return new Set(this.runsSubject.value.map(r => r.techniqueId)).size;
  }

  /** Export all runs as a portable JSON document. */
  exportJson(): string {
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      schemaVersion: '1.0',
      runs: this.runsSubject.value,
    }, null, 2);
  }

  /** Import runs from a previously-exported JSON document. Replaces existing. */
  importJson(jsonText: string): { ok: boolean; imported: number; error?: string } {
    try {
      const parsed = JSON.parse(jsonText);
      if (!Array.isArray(parsed.runs)) return { ok: false, imported: 0, error: 'Missing runs array' };
      this.runsSubject.next(parsed.runs);
      this.save();
      return { ok: true, imported: parsed.runs.length };
    } catch (err) {
      return { ok: false, imported: 0, error: String(err) };
    }
  }

  /** Build an ATT&CK Navigator layer JSON colored by validation status. */
  buildNavigatorLayer(domainId: string): object {
    const colorByStatus: Record<ValidationStatus, string> = {
      passed: '#10b981',         // green
      partial: '#f59e0b',        // amber
      failed: '#ef4444',         // red
      'no-telemetry': '#6b7280', // gray
      untested: '#9ca3af',       // light gray
    };
    // For each technique, pick latest run's status
    const latestById = new Map<string, ValidationRun>();
    for (const r of this.runsSubject.value) {
      const cur = latestById.get(r.techniqueId);
      if (!cur || r.runDate > cur.runDate) latestById.set(r.techniqueId, r);
    }
    return {
      name: `ATTACK-Navi Detection Validation — ${new Date().toISOString().split('T')[0]}`,
      versions: { attack: '17', navigator: '5', layer: '4.5' },
      domain: domainId,
      description: 'Auto-generated validation status by technique (latest run wins).',
      techniques: Array.from(latestById.values()).map(r => ({
        techniqueID: r.techniqueId,
        comment: `Status: ${r.status} — ${r.notes ?? ''}`.trim(),
        color: colorByStatus[r.status],
        showSubtechniques: true,
      })),
      gradient: { colors: [], minValue: 0, maxValue: 1 },
      legendItems: Object.entries(colorByStatus).map(([label, color]) => ({ label, color })),
    };
  }
}

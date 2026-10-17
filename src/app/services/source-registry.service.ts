// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { BehaviorSubject, Observable, distinctUntilChanged, map } from 'rxjs';
import { DATA_PRESENT_STATUSES, SourceDefinition, SourceRecord } from '../models/source-record';
import { SOURCE_DEFINITIONS } from './source-inventory';

/** A short, human-readable reason for a failed load. */
export function describeLoadError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 0) return `network error (no response)${err.url ? ` from ${err.url}` : ''}`;
    return `HTTP ${err.status}${err.statusText ? ` ${err.statusText}` : ''}${err.url ? ` from ${err.url}` : ''}`;
  }
  if (err instanceof Error) return err.message || err.name;
  if (typeof err === 'string' && err) return err;
  if (typeof ProgressEvent !== 'undefined' && err instanceof ProgressEvent) return 'network error';
  return 'unknown error';
}

function initialRecord(def: SourceDefinition): SourceRecord {
  return {
    ...def,
    status: def.initialStatus ?? 'pending',
    lastError: null,
    lastLoadedAt: null,
    rows: null,
  };
}

/**
 * The single place that says whether a data source loaded (product plan 6.3 / E1.3).
 *
 * Loaders call `begin` when a request starts, `succeed` with the row count when data
 * arrives, and `fail` with the error when it does not. A failure is never recorded as
 * loaded: `fail` sets status 'failed' and keeps the reason in `lastError`, and a
 * success with zero rows is 'empty', not 'loaded'. Data & Trust (E3.7) and the
 * data-health ribbon read the records from here.
 */
@Injectable({ providedIn: 'root' })
export class SourceRegistryService {
  private readonly recordsSubject: BehaviorSubject<ReadonlyMap<string, SourceRecord>>;

  /** Every record, in inventory order. Emits on every change. */
  readonly records$: Observable<SourceRecord[]>;

  constructor() {
    const records = new Map<string, SourceRecord>();
    for (const def of SOURCE_DEFINITIONS) {
      if (records.has(def.id)) throw new Error(`SourceRegistry: duplicate source id '${def.id}'`);
      records.set(def.id, initialRecord(def));
    }
    this.recordsSubject = new BehaviorSubject<ReadonlyMap<string, SourceRecord>>(records);
    this.records$ = this.recordsSubject.pipe(map(m => [...m.values()]));
  }

  /** All records, in inventory order. */
  all(): SourceRecord[] {
    return [...this.recordsSubject.value.values()];
  }

  /** One record; throws for an id that is not in the inventory (a programming error). */
  get(id: string): SourceRecord {
    const record = this.recordsSubject.value.get(id);
    if (!record) throw new Error(`SourceRegistry: unknown source id '${id}'`);
    return record;
  }

  has(id: string): boolean {
    return this.recordsSubject.value.has(id);
  }

  /** The record for `id`, re-emitted whenever it changes. */
  record$(id: string): Observable<SourceRecord> {
    this.get(id);
    return this.recordsSubject.pipe(
      map(m => m.get(id)!),
      distinctUntilChanged(),
    );
  }

  /** True when the source holds usable data (loaded, stale or archived-upstream with rows). */
  hasData(id: string): boolean {
    const r = this.get(id);
    if (!DATA_PRESENT_STATUSES.includes(r.status) || r.rows === 0) return false;
    // A withdrawn upstream with nothing loaded (CIS) holds no data.
    return r.status !== 'archived-upstream' || (r.rows ?? 0) > 0;
  }

  /** A request for `id` has started. Clears the previous error. */
  begin(id: string): void {
    this.patch(id, { status: 'loading', lastError: null });
  }

  /**
   * Data for `id` arrived. `rows` is what the loader indexed; 0 records 'empty'.
   * An archived upstream reports 'archived-upstream' and a source marked stale stays
   * 'stale', so a successful load never hides either fact.
   */
  succeed(id: string, rows: number | null = null, extra: { version?: string; note?: string } = {}): void {
    const def = this.get(id);
    if (rows === 0) {
      this.patch(id, { status: 'empty', lastError: null, rows: 0, lastLoadedAt: new Date().toISOString(), ...extra });
      return;
    }
    const status = def.archivedUpstream ? 'archived-upstream' : def.initialStatus === 'stale' ? 'stale' : 'loaded';
    this.patch(id, { status, lastError: null, rows, lastLoadedAt: new Date().toISOString(), ...extra });
  }

  /** Loading `id` failed. Records the reason; the source is never reported as loaded. */
  fail(id: string, error: unknown): void {
    this.patch(id, { status: 'failed', lastError: describeLoadError(error) });
  }

  private patch(id: string, change: Partial<SourceRecord>): void {
    const current = this.get(id);
    const next = new Map(this.recordsSubject.value);
    next.set(id, { ...current, ...change });
    this.recordsSubject.next(next);
  }
}

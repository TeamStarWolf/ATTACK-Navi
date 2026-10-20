// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The technique-marks store (Phase 2 design §3 P2-05, §2.3, §8): per-technique
// owner statements in `navi.v2.technique-marks`, keyed by TechniqueRefKey, on
// the v2 storage envelope. A mark says "this technique is implemented (or
// planned) here", optionally naming the mitigation it was confirmed through
// (`via: 'M1038'`), and which source wrote it: 'manual' (Confirm, bulk set)
// or 'layer:<name>' (a Navigator layer import).
//
// P2-05 ships the store and its read API only. No UI writes to it until P2-16
// (the drawer Confirm, bulk set and the Navigator import move here then).
// PostureService reads `marks$`; OwnerDataService counts implemented marks (D4).
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import type { ImplStatus } from './implementation.service';
import {
  type V2Envelope,
  type V2Store,
  readV2,
  replaceSource,
  writeV2,
} from '../models/storage-envelope';
import { type TechniqueRefKey, parseTechniqueRef } from '../models/technique-ref';

export const TECHNIQUE_MARKS_KEY = 'navi.v2.technique-marks';

/** One per-technique confirmation. */
export interface TechniqueMark {
  readonly ref: TechniqueRefKey;
  /** The mitigation the technique was confirmed through, e.g. 'M1038'. */
  readonly via?: string;
  readonly status: ImplStatus;
}

/** A stored mark: the confirmation plus the v2 envelope (its `source` names the writer). */
export type TechniqueMarkRecord = TechniqueMark & V2Envelope;

/** The sources a mark may carry: 'manual' and 'layer:<name>'. 'wizard' ratings stay in the v1 map (read-only). */
export type MarkSource = 'manual' | `layer:${string}`;

const STATUSES: readonly ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];

export function isMarkSource(x: unknown): x is MarkSource {
  if (x === 'manual') return true;
  return typeof x === 'string' && /^layer:\S/.test(x);
}

type Obj = Record<string, unknown>;

/**
 * Per-field allowlist copy of one stored mark; null when it is not one. The
 * key is bundled (WorkspaceBundleService), so a record can arrive from an
 * imported file: unknown fields are dropped and the envelope is re-derived
 * from the ref, so a record cannot claim a domain its ref does not name.
 */
export function sanitizeMark(x: unknown): TechniqueMarkRecord | null {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return null;
  const o = x as Obj;
  const ref = typeof o['ref'] === 'string' ? parseTechniqueRef(o['ref']) : null;
  if (ref === null) return null;
  if (typeof o['status'] !== 'string' || !(STATUSES as readonly string[]).includes(o['status'])) return null;
  if (!isMarkSource(o['source'])) return null;
  if (typeof o['createdAt'] !== 'string' || typeof o['updatedAt'] !== 'string') return null;
  const via = typeof o['via'] === 'string' && o['via'].trim() !== '' ? o['via'] : undefined;
  return {
    ref: o['ref'] as TechniqueRefKey,
    status: o['status'] as ImplStatus,
    ...(via !== undefined ? { via } : {}),
    source: o['source'],
    domain: ref.domain,
    attackVersion: ref.version,
    createdAt: o['createdAt'],
    updatedAt: o['updatedAt'],
  };
}

function isStoredMark(x: unknown): x is TechniqueMarkRecord {
  return sanitizeMark(x) !== null;
}

@Injectable({ providedIn: 'root' })
export class TechniqueMarksService {
  private store: V2Store<TechniqueMark> = this.load();
  private readonly marksSubject = new BehaviorSubject<readonly TechniqueMarkRecord[]>(this.store.records);
  /** Every stored mark. The first emission is synchronous, so D4 is right at boot (OwnerDataService). */
  readonly marks$: Observable<readonly TechniqueMarkRecord[]> = this.marksSubject.asObservable();

  get all(): readonly TechniqueMarkRecord[] {
    return this.marksSubject.value;
  }

  /**
   * Record one technique's confirmation from `source` (default 'manual',
   * status 'implemented'). One mark per technique per source: a repeat
   * replaces that source's mark for the ref and keeps its createdAt. False when
   * the ref or the source is not valid (nothing is written).
   */
  confirm(ref: TechniqueRefKey, opts: { via?: string; status?: ImplStatus; source?: MarkSource } = {}): boolean {
    const parsed = parseTechniqueRef(ref);
    const source = opts.source ?? 'manual';
    const status = opts.status ?? 'implemented';
    if (parsed === null || !isMarkSource(source) || !STATUSES.includes(status)) return false;
    const now = new Date().toISOString();
    const existing = this.store.records.find(r => r.ref === ref && r.source === source);
    const via = opts.via?.trim() ? opts.via.trim() : undefined;
    const mark: TechniqueMarkRecord = {
      ref, status, ...(via !== undefined ? { via } : {}),
      source, domain: parsed.domain, attackVersion: parsed.version,
      createdAt: existing?.createdAt ?? now, updatedAt: now,
    };
    const records = existing
      ? this.store.records.map(r => (r === existing ? mark : r))
      : [...this.store.records, mark];
    this.commit(records);
    return true;
  }

  /** Remove the mark `source` holds for `ref` (default 'manual'). Other sources' marks stay. */
  clear(ref: TechniqueRefKey, source: MarkSource = 'manual'): void {
    const records = this.store.records.filter(r => !(r.ref === ref && r.source === source));
    if (records.length !== this.store.records.length) this.commit(records);
  }

  /**
   * Replace every mark of one import source (a `layer:` source) with `marks`;
   * marks of every other source stay (merge by source, §2.3). 'manual' is never
   * replaced by an import. Marks whose ref does not parse are skipped. Returns
   * the number of marks stored for the source, or -1 when the source is refused.
   */
  replaceSource(source: `layer:${string}`, marks: readonly TechniqueMark[]): number {
    if (!isMarkSource(source) || (source as string) === 'manual') return -1;
    const now = new Date().toISOString();
    const incoming: TechniqueMarkRecord[] = [];
    for (const m of marks) {
      const r = sanitizeMark({ ...m, source, createdAt: now, updatedAt: now });
      if (r !== null) incoming.push(r);
    }
    this.commit(replaceSource(this.store.records, incoming, source));
    return incoming.length;
  }

  private load(): V2Store<TechniqueMark> {
    const store = readV2<TechniqueMark>(TECHNIQUE_MARKS_KEY, isStoredMark);
    return { ...store, records: store.records.map(r => sanitizeMark(r) as TechniqueMarkRecord) };
  }

  private commit(records: readonly TechniqueMarkRecord[]): void {
    this.store = { ...this.store, records };
    writeV2(TECHNIQUE_MARKS_KEY, this.store);
    this.marksSubject.next(records);
  }
}

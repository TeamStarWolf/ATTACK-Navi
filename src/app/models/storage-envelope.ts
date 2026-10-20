// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The v2 storage envelope (Phase 2 design §2.3, plan:590,781). Every record a
// v2 store holds says which domain and bundle version it was written under,
// which source wrote it, and when. These are pure helpers over localStorage
// with try/catch; no key is read or written until a store calls them
// (navi.v2.validation-runs in P2-02, navi.v2.threat-profile in P2-03,
// navi.v2.technique-marks in P2-05).
import type { RefDomain } from './technique-ref';

export type SourceId =
  | 'manual'                    // authored in this browser (panel, drawer); never replaced by an import
  | 'wizard'                    // legacy technique ratings found in mitre-nav-impl-v1 (read-only)
  | `lylat-range:${string}`     // Lylat contract import, one source per mission_id (R7; P2-20)
  | `layer:${string}`;          // Navigator layer import, by layer name (technique marks, P2-16)
// R19: no 'json:' source (no writer exists) and no 'csv:' source (the impl CSV writes the v1 map, §5.6).

export interface V2Envelope {
  readonly domain: RefDomain | null;   // null for records upgraded from v1 (§5, R6)
  readonly attackVersion: string;      // 'unknown' for records upgraded from v1
  readonly source: SourceId;
  readonly createdAt: string;          // ISO
  readonly updatedAt: string;          // ISO
}

export interface V2Store<T> {
  readonly schema: 2;
  readonly migratedFromV1Fingerprint?: string;   // fingerprint(v1 raw): fnv1a32 hex + ':' + v1 raw length (S11)
  readonly tombstones: readonly string[];        // ids deleted from v2; v1 never resurrects them (R20)
  readonly records: readonly (T & V2Envelope)[];
}

/** Replace every record whose source === `source` with `incoming`; keep the rest. Order: kept first, then incoming. */
export function replaceSource<T extends V2Envelope>(existing: readonly T[], incoming: readonly T[], source: SourceId): T[] {
  return [...existing.filter(r => r.source !== source), ...incoming];
}

/**
 * Upsert by `id` (manual runs): never deletes. An incoming record replaces the
 * existing one with its id in place; a new id is appended. When `incoming`
 * repeats an id, the last one wins.
 */
export function upsertById<T extends V2Envelope & { id: string }>(existing: readonly T[], incoming: readonly T[]): T[] {
  const out = [...existing];
  const at = new Map<string, number>();
  out.forEach((r, i) => at.set(r.id, i));
  for (const r of incoming) {
    const i = at.get(r.id);
    if (i === undefined) {
      at.set(r.id, out.length);
      out.push(r);
    } else {
      out[i] = r;
    }
  }
  return out;
}

/** Synchronous fingerprint (S11): FNV-1a 32-bit over the UTF-16 code units, hex, plus ':' + length. */
export function fingerprint(raw: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `${(h >>> 0).toString(16).padStart(8, '0')}:${raw.length}`;
}

/**
 * Read a v2 store. Empty on any failure: no key, storage that throws, corrupt
 * JSON, or a value that is not a schema-2 store. Records that fail `isRecord`
 * are skipped, and tombstones that are not strings are dropped.
 */
export function readV2<T>(key: string, isRecord: (x: unknown) => x is T & V2Envelope): V2Store<T> {
  const empty: V2Store<T> = { schema: 2, tombstones: [], records: [] };
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return empty;
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return empty;
    const o = parsed as { schema?: unknown; migratedFromV1Fingerprint?: unknown; tombstones?: unknown; records?: unknown };
    if (o.schema !== 2 || !Array.isArray(o.records) || !Array.isArray(o.tombstones)) return empty;
    const store: V2Store<T> = {
      schema: 2,
      tombstones: o.tombstones.filter((x): x is string => typeof x === 'string'),
      records: o.records.filter(isRecord),
    };
    return typeof o.migratedFromV1Fingerprint === 'string'
      ? { ...store, migratedFromV1Fingerprint: o.migratedFromV1Fingerprint }
      : store;
  } catch {
    return empty;
  }
}

/** Write a v2 store. False when storage throws (quota, disabled storage). */
export function writeV2<T>(key: string, store: V2Store<T>): boolean {
  try {
    localStorage.setItem(key, JSON.stringify(store));
    return true;
  } catch {
    return false;
  }
}

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
 * Replace a source's records only WITHIN the domains `incoming` carries: drop
 * records of `source` whose domain is among the incoming records' domains, keep
 * that source's records in every other domain, then append `incoming`. The Lylat
 * range import keys each file to the one domain loaded at import (R6 §3), so
 * loading each domain and re-importing the same mission ACCUMULATES it across
 * domains instead of the later import deleting the earlier domain's rows (P2-20).
 * Empty `incoming` drops nothing. Only the range path uses this; `manual` and
 * `layer:` keep their own merge rules.
 */
export function replaceSourceInDomains<T extends V2Envelope>(existing: readonly T[], incoming: readonly T[], source: SourceId): T[] {
  const domains = new Set<RefDomain | null>(incoming.map(r => r.domain));
  return [...existing.filter(r => !(r.source === source && domains.has(r.domain))), ...incoming];
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

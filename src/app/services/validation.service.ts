// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { DataService, type AttackDomain } from './data.service';
import type { ProofScope } from '../models/posture/posture.types';
import { runMatches } from '../models/posture/run-match';
import {
  type SourceId,
  type V2Envelope,
  type V2Store,
  fingerprint,
  readV2,
  replaceSource,
  upsertById,
  writeV2,
} from '../models/storage-envelope';
import {
  type RefDomain,
  type TechniqueRefKey,
  parseTechniqueRef,
  refForTechnique,
  techniqueRefKey,
} from '../models/technique-ref';
import { validateLylatExport, lylatRowsToRuns } from '../contracts/lylat-validated-detections';

export type ValidationStatus = 'passed' | 'failed' | 'partial' | 'no-telemetry' | 'untested' | 'not-reproducible';

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

/** One observed outcome of a run (Phase 2 design §3 P2-02). */
export interface ValidationOutcome {
  readonly detectionRef: string | null;
  readonly outcome: 'alerted' | 'blocked' | 'logged' | 'none';
  readonly coverageState?: 'validated' | 'telemetry-observed' | 'detection-authored' | 'deployed';
  readonly negativeControl?: 'blocked-on-hardened' | 'detection-only' | 'not-reproducible';
  readonly evidenceRef?: string;        // opaque; never a URL (evidenceLinks stays URLs)
  readonly sourceAttackVersion?: string; // the ATT&CK version the source named for this row; provenance only, never the run key (R6 §3)
}

/** A run in the v2 store: the v1 fields plus the storage envelope (§2.3) and the proof fields. */
export interface ValidationRunV2 extends ValidationRun, V2Envelope {
  /** null for runs migrated from v1 and for runs whose domain is unknown: resolved lazily per loaded domain (R6). */
  readonly techniqueRef: TechniqueRefKey | null;
  readonly proofScope: ProofScope;      // 'own-run' for panel records, 'range' for Lylat
  readonly outcomes: readonly ValidationOutcome[];
  readonly statusFromSource: boolean;   // true ⇒ update() never recomputes status
  readonly missionId?: string;
}

/** What an import did, per source (§5.8), and the rows it refused (§5.9). */
export interface ImportResult {
  ok: boolean;
  bySource: Record<string, { added: number; replaced: number }>;
  dropped: { row: number; reason: string }[];
  error?: string;
}

/** The v1 store: read once per construction for the copy-forward, never written or deleted again (§5.2). */
export const VALIDATION_RUNS_V1_KEY = 'attacknavi.validation-runs.v1';
/** The v2 store (§5.1). */
export const VALIDATION_RUNS_V2_KEY = 'navi.v2.validation-runs';
/** The Lylat contract schema; its files are imported by "Import range results" (P2-20), not here. */
export const LYLAT_CONTRACT_SCHEMA = 'lylat-validated-detections/1';

const STATUSES: readonly ValidationStatus[] = ['passed', 'failed', 'partial', 'no-telemetry', 'untested', 'not-reproducible'];
const ATTACK_RESULTS: readonly ValidationRun['attackResult'][] = ['executed', 'failed-prereq', 'blocked', 'errored'];
const REF_DOMAINS: readonly RefDomain[] = ['enterprise', 'ics', 'mobile', 'f3', 'atlas'];
const OUTCOMES: readonly ValidationOutcome['outcome'][] = ['alerted', 'blocked', 'logged', 'none'];
const COVERAGE_STATES: readonly NonNullable<ValidationOutcome['coverageState']>[] =
  ['validated', 'telemetry-observed', 'detection-authored', 'deployed'];
const NEGATIVE_CONTROLS: readonly NonNullable<ValidationOutcome['negativeControl']>[] =
  ['blocked-on-hardened', 'detection-only', 'not-reproducible'];

type Obj = Record<string, unknown>;

function isObj(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function oneOf<T extends string>(values: readonly T[], x: unknown): x is T {
  return typeof x === 'string' && (values as readonly string[]).includes(x);
}

function str(x: unknown): string {
  return typeof x === 'string' ? x : '';
}

function strList(x: unknown): string[] {
  return Array.isArray(x) ? x.filter((v): v is string => typeof v === 'string') : [];
}

/** A source a stored run may carry. 'wizard' names legacy technique ratings, never runs. */
export function isRunSource(x: unknown): x is Exclude<SourceId, 'wizard'> {
  if (typeof x !== 'string') return false;
  if (x === 'manual') return true;
  const m = /^(lylat-range|layer):(.+)$/.exec(x);
  return m !== null && m[2].trim() !== '';
}

/**
 * The proof scope a run of `source` carries (P2-02 interface): 'range' for a
 * Lylat mission, 'own-run' for everything else. Never read from the row, so an
 * import cannot raise a run's scope ('production' has no writer until E6.2).
 */
export function scopeForSource(source: Exclude<SourceId, 'wizard'>): ProofScope {
  return source.startsWith('lylat-range:') ? 'range' : 'own-run';
}

/** Compute status from telemetry/detection inputs (the panel's rule, also used to fill a v1 row's missing status). */
export function statusFromInputs(input: {
  telemetryRequired: readonly string[];
  telemetryAvailable: readonly string[];
  detectionsExpected: readonly string[];
  detectionsFired: readonly string[];
}): ValidationStatus {
  if (input.telemetryRequired.length > 0 && input.telemetryAvailable.length === 0) return 'no-telemetry';
  if (input.detectionsExpected.length === 0) return 'untested';
  const fired = input.detectionsFired.length;
  if (fired === 0) return 'failed';
  if (fired === input.detectionsExpected.length) return 'passed';
  return 'partial';
}

/** The fields update() may patch: every v1 field but id. A Record, so a new field cannot be left out. */
const PATCHABLE_FIELDS: Record<Exclude<keyof ValidationRun, 'id'>, true> = {
  techniqueId: true, techniqueName: true, runDate: true, operator: true,
  telemetryRequired: true, telemetryAvailable: true, atomicTestId: true, atomicCommand: true,
  attackResult: true, detectionsExpected: true, detectionsFired: true,
  responsePlaybook: true, responseActions: true, evidenceLinks: true, notes: true, status: true,
};
const PATCHABLE = Object.keys(PATCHABLE_FIELDS) as (keyof typeof PATCHABLE_FIELDS)[];

/** §5.2: 'alerted' per fired detection, and one 'blocked' outcome without a detection when the attack was blocked. */
export function outcomesFromV1(run: Pick<ValidationRun, 'detectionsFired' | 'attackResult'>): ValidationOutcome[] {
  const out: ValidationOutcome[] = run.detectionsFired.map(ref => ({ detectionRef: ref, outcome: 'alerted' as const }));
  if (run.attackResult === 'blocked') out.push({ detectionRef: null, outcome: 'blocked' });
  return out;
}

/** Per-field allowlist copy of one outcome; null when it is not an outcome. */
function sanitizeOutcome(x: unknown): ValidationOutcome | null {
  if (!isObj(x) || !oneOf(OUTCOMES, x['outcome'])) return null;
  const ref = x['detectionRef'];
  if (ref !== null && typeof ref !== 'string') return null;
  const o: { -readonly [K in keyof ValidationOutcome]: ValidationOutcome[K] } = { detectionRef: ref, outcome: x['outcome'] };
  if (oneOf(COVERAGE_STATES, x['coverageState'])) o.coverageState = x['coverageState'];
  if (oneOf(NEGATIVE_CONTROLS, x['negativeControl'])) o.negativeControl = x['negativeControl'];
  if (typeof x['evidenceRef'] === 'string') o.evidenceRef = x['evidenceRef'];
  if (typeof x['sourceAttackVersion'] === 'string') o.sourceAttackVersion = x['sourceAttackVersion'];
  return o;
}

/**
 * Per-field allowlist copy of one run (§5.9). Unknown fields are not copied.
 * A v1 row (no envelope) upgrades as §5.2 says: domain null, techniqueRef null,
 * attackVersion 'unknown', outcomes from detectionsFired and attackResult,
 * createdAt = updatedAt = runDate. Returns the reason when a required field is
 * missing or malformed.
 *
 * @param source the source the run is stored under; a row's own `source` is
 *   used when `source` is undefined and the row names a valid one, else 'manual'.
 */
export function sanitizeRun(
  x: unknown,
  source?: Exclude<SourceId, 'wizard'>,
): { run: ValidationRunV2 } | { reason: string } {
  if (!isObj(x)) return { reason: 'not an object' };
  for (const field of ['id', 'techniqueId', 'runDate'] as const) {
    if (typeof x[field] !== 'string' || (x[field] as string).trim() === '') return { reason: `missing ${field}` };
  }
  if (!oneOf(STATUSES, x['status'])) return { reason: 'missing or unknown status' };
  if (!oneOf(ATTACK_RESULTS, x['attackResult'])) return { reason: 'missing or unknown attackResult' };
  let src: Exclude<SourceId, 'wizard'>;
  if (source !== undefined) {
    src = source;
  } else if (x['source'] === undefined) {
    src = 'manual';                                   // v1 rows have no source (§5.8)
  } else if (isRunSource(x['source'])) {
    src = x['source'];
  } else {
    return { reason: 'unknown source' };
  }
  const runDate = x['runDate'] as string;
  const base: ValidationRun = {
    id: x['id'] as string,
    techniqueId: x['techniqueId'] as string,
    techniqueName: str(x['techniqueName']),
    runDate,
    operator: str(x['operator']),
    telemetryRequired: strList(x['telemetryRequired']),
    telemetryAvailable: strList(x['telemetryAvailable']),
    atomicTestId: str(x['atomicTestId']),
    atomicCommand: str(x['atomicCommand']),
    attackResult: x['attackResult'],
    detectionsExpected: strList(x['detectionsExpected']),
    detectionsFired: strList(x['detectionsFired']),
    responsePlaybook: str(x['responsePlaybook']),
    responseActions: strList(x['responseActions']),
    evidenceLinks: strList(x['evidenceLinks']),
    notes: str(x['notes']),
    status: x['status'],
  };
  const ref = typeof x['techniqueRef'] === 'string' && parseTechniqueRef(x['techniqueRef']) !== null
    ? (x['techniqueRef'] as TechniqueRefKey)
    : null;
  const outcomes = Array.isArray(x['outcomes'])
    ? x['outcomes'].map(sanitizeOutcome).filter((o): o is ValidationOutcome => o !== null)
    : outcomesFromV1(base);
  const run: ValidationRunV2 = {
    ...base,
    domain: oneOf(REF_DOMAINS, x['domain']) ? x['domain'] : null,
    attackVersion: typeof x['attackVersion'] === 'string' && x['attackVersion'] !== '' ? x['attackVersion'] : 'unknown',
    source: src,
    createdAt: typeof x['createdAt'] === 'string' ? x['createdAt'] : runDate,
    updatedAt: typeof x['updatedAt'] === 'string' ? x['updatedAt'] : runDate,
    techniqueRef: ref,
    // Both follow the source, never the row: a 'manual' row is an own run whose
    // status update() recomputes; a 'lylat-range:' row is a range run whose status
    // came from its source. A row's own proofScope / statusFromSource is ignored.
    proofScope: scopeForSource(src),
    outcomes,
    statusFromSource: src !== 'manual',
    ...(typeof x['missionId'] === 'string' ? { missionId: x['missionId'] } : {}),
  };
  return { run };
}

/** A stored v2 record: it sanitizes, and it names its own source. */
function isStoredRun(x: unknown): x is ValidationRunV2 {
  return isObj(x) && isRunSource(x['source']) && 'run' in sanitizeRun(x);
}

/** Read the v2 store; every record is re-copied through the allowlist. */
function readStore(): V2Store<ValidationRunV2> {
  const store = readV2<ValidationRunV2>(VALIDATION_RUNS_V2_KEY, isStoredRun);
  return { ...store, records: store.records.map(r => (sanitizeRun(r) as { run: ValidationRunV2 }).run) };
}

function readRaw(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function nonBlank(x: unknown): x is string {
  return typeof x === 'string' && x.trim() !== '';
}

/**
 * The v1 runs, upgraded (§5.2), and the rows that could not be (§5.11).
 *
 * The pre-P2-02 importJson stored rows unvalidated, so a v1 row may lack fields
 * the v2 allowlist requires. The v1 app still listed such a row, so the upgrade
 * fills what it can rather than lose it:
 * - a missing or unknown status is computed from the row's lists (the panel's rule);
 * - a missing or unknown attackResult becomes 'executed' (the panel's form default);
 * - a missing id becomes `v1-<fnv1a>-<length>` of the row, and a repeated id gets
 *   `~2`, `~3`…, both deterministic, so a re-run of the copy-forward finds them taken.
 * A row that is not an object, or has no techniqueId or runDate, is reported in
 * `dropped` (row = its index in the v1 array); it stays in the v1 key.
 */
function upgradeV1(raw: string): { runs: ValidationRunV2[]; dropped: ImportResult['dropped'] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { runs: [], dropped: [] };                 // the v1 app read this as no runs either
  }
  if (!Array.isArray(parsed)) return { runs: [], dropped: [] };
  const runs: ValidationRunV2[] = [];
  const dropped: ImportResult['dropped'] = [];
  const ids = new Set<string>();
  parsed.forEach((row: unknown, i: number) => {
    if (!isObj(row)) {
      dropped.push({ row: i, reason: 'not an object' });
      return;
    }
    const base = nonBlank(row['id']) ? row['id'] : `v1-${fingerprint(JSON.stringify(row)).replace(':', '-')}`;
    let id = base;
    for (let n = 2; ids.has(id); n++) id = `${base}~${n}`;
    const lists = {
      telemetryRequired: strList(row['telemetryRequired']),
      telemetryAvailable: strList(row['telemetryAvailable']),
      detectionsExpected: strList(row['detectionsExpected']),
      detectionsFired: strList(row['detectionsFired']),
    };
    // v1 rows are always 'manual' own runs, whatever extra fields they carry.
    const r = sanitizeRun({
      ...row,
      id,
      status: oneOf(STATUSES, row['status']) ? row['status'] : statusFromInputs(lists),
      attackResult: oneOf(ATTACK_RESULTS, row['attackResult']) ? row['attackResult'] : 'executed',
      source: undefined, domain: null, techniqueRef: null,
      attackVersion: undefined, outcomes: undefined, createdAt: undefined, updatedAt: undefined, missionId: undefined,
    }, 'manual');
    if ('reason' in r) {
      dropped.push({ row: i, reason: r.reason });
      return;
    }
    ids.add(id);
    runs.push(r.run);
  });
  return { runs, dropped };
}

/** "manual: 1 added, 0 replaced; lylat-range:m1: 2 added, 3 replaced. 1 row dropped (row 2: missing id)." */
export function describeImportResult(result: ImportResult): string {
  if (!result.ok) return `Import failed: ${result.error ?? 'unknown error'}`;
  const parts = Object.entries(result.bySource).map(([s, c]) => `${s}: ${c.added} added, ${c.replaced} replaced`);
  let msg = parts.length ? `Imported ${parts.join('; ')}.` : 'Nothing imported.';
  if (result.dropped.length) {
    const first = result.dropped.slice(0, 3).map(d => `row ${d.row}: ${d.reason}`).join('; ');
    msg += ` ${result.dropped.length} row${result.dropped.length === 1 ? '' : 's'} dropped (${first}${result.dropped.length > 3 ? '; …' : ''}).`;
  }
  return msg;
}

@Injectable({ providedIn: 'root' })
export class ValidationService {
  private readonly data = inject(DataService);
  private readonly resolver = inject(AttackIdResolverService);

  private readonly boot = this.loadAndCopyForward();
  /**
   * v1 rows the copy-forward could not carry (§5.11), recomputed on every
   * construction while the v1 key exists; they stay in that key. The panel
   * names them, so a run that cannot be carried is never silently gone.
   */
  readonly migrationDropped: readonly { row: number; reason: string }[] = this.boot.dropped;
  /** The in-memory v2 store; every writer goes through commit(). */
  private store: V2Store<ValidationRunV2> = this.boot.store;
  private runsSubject = new BehaviorSubject<ValidationRunV2[]>([...this.store.records]);
  /** The first emission already holds the runs copied forward from v1 (S11). */
  readonly runs$: Observable<ValidationRunV2[]> = this.runsSubject.asObservable();

  /**
   * §5.5: a workspace bundle that carried the v2 store is authoritative. Called
   * by WorkspaceBundleService.importBundle with the keys it wrote: when they
   * include the v2 key, the restored store's migratedFromV1Fingerprint becomes
   * the fingerprint of the v1 raw now in storage, so no copy-forward runs on
   * the next construction. A v1-only bundle changes nothing here: the next
   * construction copies forward under §5.2 (absent, non-tombstoned ids only).
   */
  static applyBundleRestore(writtenKeys: readonly string[]): void {
    if (!writtenKeys.includes(VALIDATION_RUNS_V2_KEY)) return;
    const v1 = readRaw(VALIDATION_RUNS_V1_KEY);
    const raw = readRaw(VALIDATION_RUNS_V2_KEY);
    if (v1 === null || raw === null) return;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!isObj(parsed) || parsed['schema'] !== 2 || !Array.isArray(parsed['records']) || !Array.isArray(parsed['tombstones'])) return;
      localStorage.setItem(VALIDATION_RUNS_V2_KEY, JSON.stringify({ ...parsed, migratedFromV1Fingerprint: fingerprint(v1) }));
    } catch {
      // Corrupt store or storage that throws: the next construction treats it as absent.
    }
  }

  /**
   * §5.2, synchronous, before runs$ exists. Copies forward when the v2 key is
   * absent, or when the v1 fingerprint differs from migratedFromV1Fingerprint
   * (a bundle import that wrote v2 has already set it, §5.5). Inserts only ids
   * absent from v2 and from its tombstones; never overwrites or deletes a v2
   * run; never writes or deletes the v1 key.
   */
  private loadAndCopyForward(): { store: V2Store<ValidationRunV2>; dropped: ImportResult['dropped'] } {
    const stored = readStore();
    const v1Raw = readRaw(VALIDATION_RUNS_V1_KEY);
    if (v1Raw === null) return { store: stored, dropped: [] };
    const fp = fingerprint(v1Raw);
    const upgraded = upgradeV1(v1Raw);
    const v2Present = readRaw(VALIDATION_RUNS_V2_KEY) !== null;
    if (v2Present && stored.migratedFromV1Fingerprint === fp) return { store: stored, dropped: upgraded.dropped };
    const taken = new Set([...stored.records.map(r => r.id), ...stored.tombstones]);
    const copied: ValidationRunV2[] = [];
    for (const run of upgraded.runs) {
      if (taken.has(run.id)) continue;
      taken.add(run.id);
      copied.push(run);
    }
    const next: V2Store<ValidationRunV2> = { ...stored, migratedFromV1Fingerprint: fp, records: [...stored.records, ...copied] };
    writeV2(VALIDATION_RUNS_V2_KEY, next);
    return { store: next, dropped: upgraded.dropped };
  }

  /** The one write path (two writers in one tick both land here). */
  private commit(records: readonly ValidationRunV2[], tombstones: readonly string[] = this.store.tombstones): void {
    this.store = { ...this.store, tombstones, records };
    writeV2(VALIDATION_RUNS_V2_KEY, this.store);
    this.runsSubject.next([...records]);
  }

  /** The loaded domain and its bundle version, or null while none is loaded (§1.11). */
  private loaded(): { id: AttackDomain; version: string } | null {
    const domain = this.data.getCurrentDomain();
    return domain ? { id: this.data.getCurrentAttackDomain(), version: domain.attackVersion ?? '' } : null;
  }

  /**
   * The technique key of a run of `techniqueId` recorded now: its ref in the
   * loaded domain, or null while none is loaded (§1.11). A ref is only written
   * when it parses (a loaded bundle without a dotted version cannot be keyed).
   */
  private keyFor(techniqueId: string): Pick<ValidationRunV2, 'domain' | 'attackVersion' | 'techniqueRef'> {
    const domain = this.loaded();
    const ref = domain ? refForTechnique({ attackId: techniqueId }, domain.id, domain.version) : null;
    const refKey = ref ? techniqueRefKey(ref) : null;
    return {
      domain: domain ? domain.id : null,
      attackVersion: domain && domain.version ? domain.version : 'unknown',
      techniqueRef: refKey !== null && parseTechniqueRef(refKey) !== null ? refKey : null,
    };
  }

  private newId(): string {
    return typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `vr-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }

  /** All runs in storage. */
  get all(): ValidationRunV2[] {
    return this.runsSubject.value;
  }

  /**
   * Runs of a technique of the loaded domain, through runMatches (§8): the same
   * matcher PostureService uses. Before a domain loads, the current domain id
   * stands in and the resolver is the identity.
   */
  forTechnique(techniqueId: string): ValidationRunV2[] {
    const domainId = this.loaded()?.id ?? this.data.getCurrentAttackDomain();
    const resolve = (id: string) => this.resolver.resolve(id);
    const t = { attackId: techniqueId };
    return this.runsSubject.value.filter(r => runMatches(r, t, domainId, resolve));
  }

  /** Most recent run for a technique, or null. */
  latestFor(techniqueId: string): ValidationRunV2 | null {
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
    return statusFromInputs(input);
  }

  /**
   * Add a new run (§5.7: always the v2 envelope). Source 'manual', proofScope
   * 'own-run', techniqueRef from the loaded domain (null while none is loaded).
   */
  record(partial: Omit<ValidationRun, 'id' | 'runDate' | 'status'> & { runDate?: string }): ValidationRunV2 {
    const now = new Date().toISOString();
    const runDate = partial.runDate ?? now;
    const base: ValidationRun = {
      techniqueId: partial.techniqueId,
      techniqueName: partial.techniqueName,
      operator: partial.operator,
      telemetryRequired: partial.telemetryRequired,
      telemetryAvailable: partial.telemetryAvailable,
      atomicTestId: partial.atomicTestId,
      atomicCommand: partial.atomicCommand,
      attackResult: partial.attackResult,
      detectionsExpected: partial.detectionsExpected,
      detectionsFired: partial.detectionsFired,
      responsePlaybook: partial.responsePlaybook,
      responseActions: partial.responseActions,
      evidenceLinks: partial.evidenceLinks,
      notes: partial.notes,
      id: this.newId(),
      runDate,
      status: this.computeStatus(partial),
    };
    const run: ValidationRunV2 = {
      ...base,
      ...this.keyFor(partial.techniqueId),
      source: 'manual',
      createdAt: now,
      updatedAt: now,
      proofScope: 'own-run',
      outcomes: outcomesFromV1(base),
      statusFromSource: false,
    };
    this.commit([...this.store.records, run]);
    return run;
  }

  /**
   * Update an existing run by id. Only the v1 fields are patched (never id,
   * source, proofScope, outcomes or the envelope). For runs whose status did not
   * come from their source (§5.10), status is recomputed when an input changes
   * and outcomes are re-derived (§5.2) when detectionsFired or attackResult
   * changes. A new techniqueId is re-keyed to the loaded domain, as record() keys it.
   */
  update(id: string, patch: Partial<ValidationRun>): void {
    const fields = Object.fromEntries(
      PATCHABLE.filter(k => patch[k] !== undefined).map(k => [k, patch[k]]),
    ) as Partial<ValidationRun>;
    const list = this.store.records.map(r => {
      if (r.id !== id) return r;
      let merged: ValidationRunV2 = { ...r, ...fields, updatedAt: new Date().toISOString() };
      if (fields.techniqueId !== undefined && fields.techniqueId !== r.techniqueId) {
        merged = { ...merged, ...this.keyFor(fields.techniqueId) };
      }
      if (!r.statusFromSource) {
        if (
          fields.telemetryRequired !== undefined ||
          fields.telemetryAvailable !== undefined ||
          fields.detectionsExpected !== undefined ||
          fields.detectionsFired !== undefined
        ) {
          merged.status = statusFromInputs(merged);
        }
        if (fields.detectionsFired !== undefined || fields.attackResult !== undefined) {
          merged = { ...merged, outcomes: outcomesFromV1(merged) };
        }
      }
      return merged;
    });
    this.commit(list);
  }

  /** Delete a run by id and tombstone it, so a later v1 copy-forward cannot resurrect it (§5.4). */
  delete(id: string): void {
    const tombstones = this.store.tombstones.includes(id) ? this.store.tombstones : [...this.store.tombstones, id];
    this.commit(this.store.records.filter(r => r.id !== id), tombstones);
  }

  /** Aggregate counts grouped by status across all runs. */
  statusCounts(): Record<ValidationStatus, number> {
    const counts: Record<ValidationStatus, number> = {
      passed: 0, failed: 0, partial: 0, 'no-telemetry': 0, untested: 0, 'not-reproducible': 0,
    };
    for (const r of this.runsSubject.value) counts[r.status]++;
    return counts;
  }

  /** Count of distinct techniques with at least one validation. */
  uniqueTechniqueCount(): number {
    return new Set(this.runsSubject.value.map(r => r.techniqueId)).size;
  }

  /** Export all runs as a portable JSON document (v2 records, envelope included). */
  exportJson(): string {
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      schemaVersion: '2.0',
      runs: this.runsSubject.value,
    }, null, 2);
  }

  /**
   * Import runs from an exported JSON document, merging by source (§5.8):
   * rows are grouped by `source` (v1-format rows have none and count as
   * 'manual'); 'manual' rows upsert by id and never delete; every other source
   * present replaces all stored runs of that source. A Lylat contract file is
   * refused here and belongs to "Import range results" (P2-20).
   */
  importJson(jsonText: string): ImportResult {
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText);
    } catch (err) {
      return { ok: false, bySource: {}, dropped: [], error: String(err) };
    }
    if (isObj(parsed) && parsed['schema'] === LYLAT_CONTRACT_SCHEMA) {
      return {
        ok: false, bySource: {}, dropped: [],
        error: `This is a Lylat range results file (${LYLAT_CONTRACT_SCHEMA}). Use "Import range results" to load it.`,
      };
    }
    if (!isObj(parsed) || !Array.isArray(parsed['runs'])) {
      return { ok: false, bySource: {}, dropped: [], error: 'Missing runs array' };
    }
    const dropped: ImportResult['dropped'] = [];
    const groups = new Map<SourceId, { row: number; run: ValidationRunV2 }[]>();
    (parsed['runs'] as unknown[]).forEach((x, i) => {
      const r = sanitizeRun(x);
      if ('reason' in r) {
        dropped.push({ row: i, reason: r.reason });
        return;
      }
      const g = groups.get(r.run.source) ?? [];
      g.push({ row: i, run: r.run });
      groups.set(r.run.source, g);
    });
    return this.merge(groups, dropped);
  }

  /**
   * Replace every stored run of `source` with `rows` (the API "Import range
   * results" calls, P2-20). Rows go through the same allowlist and are stored
   * under `source`, with the scope and statusFromSource that source gives
   * ('range' and true for `lylat-range:`), whatever the rows carry.
   */
  importRows(rows: readonly ValidationRunV2[], source: Exclude<SourceId, 'manual' | 'wizard'>): ImportResult {
    if (!isRunSource(source) || (source as string) === 'manual') {
      return { ok: false, bySource: {}, dropped: [], error: `Not an import source: ${String(source)}` };
    }
    const dropped: ImportResult['dropped'] = [];
    const group: { row: number; run: ValidationRunV2 }[] = [];
    rows.forEach((x, i) => {
      const r = sanitizeRun(x, source);
      if ('reason' in r) dropped.push({ row: i, reason: r.reason });
      else group.push({ row: i, run: r.run });
    });
    if (rows.length > 0 && group.length === 0) {
      return { ok: false, bySource: {}, dropped, error: 'No valid rows; nothing was replaced.' };
    }
    return this.merge(new Map<SourceId, typeof group>([[source, group]]), dropped);
  }

  /**
   * Load a Lylat `lylat-validated-detections/1` file (P2-20). The text is parsed,
   * validated against the contract (structure, enums, patterns and the privacy
   * regex — a hit refuses the whole file, nothing reaches the store), then every
   * row is resolved and keyed at import to the LOADED domain (so an imported run
   * keys exactly like a manual run), grouped by its `lylat-range:<mission>`
   * source, and committed in a SINGLE atomic merge that replaces each mission's
   * source. One `runs$` emission results, so every reactive reader (the Proven
   * lens, PostureService) updates in-session without a reload.
   *
   * Atlas rows, rows whose technique does not resolve, and rows whose technique
   * is not in the loaded domain land in `dropped` — each against its EXPORT row
   * index, so the reader can find the row. The file never travels through a URL;
   * callers pass the text they read.
   */
  importRangeContract(text: string): ImportResult {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      return { ok: false, bySource: {}, dropped: [], error: String(err) };
    }
    if (!isObj(parsed) || parsed['schema'] !== LYLAT_CONTRACT_SCHEMA) {
      return { ok: false, bySource: {}, dropped: [], error: `Not a ${LYLAT_CONTRACT_SCHEMA} file.` };
    }
    const v = validateLylatExport(parsed);
    if (!v.ok) {
      const shown = v.errors.slice(0, 5).join('; ');
      const more = v.errors.length > 5 ? ` (+${v.errors.length - 5} more)` : '';
      return { ok: false, bySource: {}, dropped: [], error: `Invalid range results file: ${shown}${more}` };
    }
    const resolve = (id: string) => this.resolver.resolve(id);
    const loaded = this.loaded();
    const domainId = loaded ? loaded.id : this.data.getCurrentAttackDomain();
    const domainVersion = loaded?.version ?? '';
    // The loaded domain's technique ids (resolved), so a well-formed id that names
    // no technique of this domain is skipped. A bundle that lists no techniques
    // (never the real app) does not gate — keeps the pure validator the authority.
    const current = this.data.getCurrentDomain() as { techniques?: { attackId: string }[] } | null;
    const known = new Set((current?.techniques ?? []).map(t => resolve(t.attackId)));
    const isKnown = (id: string) => known.size === 0 || known.has(id);

    const { bySource, skipped } = lylatRowsToRuns(v.value, resolve, domainId, domainVersion, isKnown);
    const dropped: ImportResult['dropped'] = [...skipped];
    // Sanitise every mapped run (tracking its export row for any drop), then
    // commit all missions at once: one store write, one emission (atomic).
    const groups = new Map<SourceId, { row: number; run: ValidationRunV2 }[]>();
    for (const [source, tagged] of bySource) {
      const group: { row: number; run: ValidationRunV2 }[] = [];
      for (const { row, run } of tagged) {
        const r = sanitizeRun(run, source);
        if ('reason' in r) dropped.push({ row, reason: r.reason });
        else group.push({ row, run: r.run });
      }
      if (group.length > 0) groups.set(source, group);
    }
    return this.merge(groups, dropped);
  }

  /** Apply grouped rows: 'manual' upserts by id, every other source replaces itself. One commit. */
  private merge(
    groups: ReadonlyMap<SourceId, readonly { row: number; run: ValidationRunV2 }[]>,
    dropped: ImportResult['dropped'],
  ): ImportResult {
    let records: ValidationRunV2[] = [...this.store.records];
    const bySource: ImportResult['bySource'] = {};
    // Replacing sources first, so an id a replaced source gives up is free for the rows after it.
    const order = [...groups.keys()].sort((a, b) => Number(a === 'manual') - Number(b === 'manual'));
    for (const source of order) {
      const owner = new Map(records.filter(r => r.source !== source).map(r => [r.id, r.source]));
      const seen = new Set<string>();
      const incoming: ValidationRunV2[] = [];
      for (const { row, run } of groups.get(source) ?? []) {
        const other = owner.get(run.id);
        if (other !== undefined) {
          dropped.push({ row, reason: `id ${run.id} belongs to source ${other}` });
        } else if (source !== 'manual' && seen.has(run.id)) {
          dropped.push({ row, reason: `duplicate id ${run.id}` });
        } else {
          seen.add(run.id);
          incoming.push(run);
        }
      }
      if (source === 'manual') {
        const existing = new Set(records.filter(r => r.source === 'manual').map(r => r.id));
        const ids = new Set(incoming.map(r => r.id));
        const replaced = [...ids].filter(id => existing.has(id)).length;
        bySource[source] = { added: ids.size - replaced, replaced };
        records = upsertById(records, incoming);
      } else {
        bySource[source] = { added: incoming.length, replaced: records.filter(r => r.source === source).length };
        records = replaceSource(records, incoming, source);
      }
    }
    dropped.sort((a, b) => a.row - b.row);
    this.commit(records);
    return { ok: true, bySource, dropped };
  }

  /**
   * Build an ATT&CK Navigator layer JSON colored by validation status. The
   * ATT&CK version is the loaded domain's, else the newest run's known one;
   * it is left out when neither is known.
   */
  buildNavigatorLayer(domainId: string): object {
    const colorByStatus: Record<ValidationStatus, string> = {
      passed: '#10b981',         // green
      partial: '#f59e0b',        // amber
      failed: '#ef4444',         // red
      'no-telemetry': '#6b7280', // gray
      untested: '#9ca3af',       // light gray
      'not-reproducible': '#8b5cf6', // violet
    };
    // For each technique, pick latest run's status
    const latestById = new Map<string, ValidationRunV2>();
    for (const r of this.runsSubject.value) {
      const cur = latestById.get(r.techniqueId);
      if (!cur || r.runDate > cur.runDate) latestById.set(r.techniqueId, r);
    }
    const domainVersion = this.loaded()?.version ?? '';
    const runVersion = [...this.runsSubject.value]
      .filter(r => r.attackVersion !== 'unknown')
      .sort((a, b) => b.runDate.localeCompare(a.runDate))[0]?.attackVersion ?? '';
    const attack = domainVersion || runVersion;
    return {
      name: `ATTACK-Navi Detection Validation — ${new Date().toISOString().split('T')[0]}`,
      versions: { ...(attack ? { attack } : {}), navigator: '5', layer: '4.5' },
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

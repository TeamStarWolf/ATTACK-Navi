// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import tinycolor from 'tinycolor2';
import { AttackDomain } from './data.service';
import {
  AttackNaviLayer,
  AttackNaviLayerMeta,
  LayerConversionResult,
  UserLayerGradient,
  UserLayerLink,
  UserLayerMetadataEntry,
  UserLayerTechnique,
  toLayerMeta,
} from '../models/user-layer';

/** Own IndexedDB store for saved user layers (separate from the STIX cache DB). */
const IDB_DB = 'attack-navi-user-layers';
const IDB_STORE = 'layers';

/** Guard rails so a hostile/huge upload can't hang or blow out storage. */
const MAX_JSON_BYTES = 20 * 1024 * 1024; // 20 MB of raw JSON text
const MAX_TECHNIQUES = 20000;

/** Navigator's default red→yellow→green gradient (used when the layer omits one). */
const DEFAULT_GRADIENT: UserLayerGradient = {
  colors: ['#ff6666', '#ffe766', '#8ec843'],
  minValue: 0,
  maxValue: 100,
};

/**
 * Owns the "saved user layers" feature: converting an uploaded MITRE ATT&CK
 * Navigator layer into ATTACK-Navi's internal {@link AttackNaviLayer} model,
 * persisting it in IndexedDB, and exposing the active layer's per-technique data
 * so the matrix can color by it and the sidebar can surface it.
 *
 * The score accessors ({@link getScore}/{@link maxScore}) intentionally mirror
 * LibraryLayerService so the matrix's existing `library` heatmap mode can render
 * a user layer with no new heatmap plumbing; {@link getGradientColor} adds the
 * layer's own gradient/explicit-color fidelity on top.
 */
@Injectable({ providedIn: 'root' })
export class UserLayerService {
  /** Saved-layer metadata for the list UI (newest first). */
  private layersSubject = new BehaviorSubject<AttackNaviLayerMeta[]>([]);
  readonly layers$ = this.layersSubject.asObservable();

  /** The layer currently applied to the matrix/sidebar, or null. */
  private activeLayerSubject = new BehaviorSubject<AttackNaviLayer | null>(null);
  readonly activeLayer$ = this.activeLayerSubject.asObservable();

  /** Emits whenever the active layer changes, so the matrix can re-render. */
  private changedSubject = new BehaviorSubject<boolean>(false);
  readonly changed$ = this.changedSubject.asObservable();

  /** attackId → technique entry, for O(1) matrix/sidebar lookups on the active layer. */
  private activeIndex = new Map<string, UserLayerTechnique>();
  private activeMaxScore = 1;

  constructor() {
    void this.refreshList();
  }

  get layers(): AttackNaviLayerMeta[] {
    return this.layersSubject.value;
  }

  get activeLayer(): AttackNaviLayer | null {
    return this.activeLayerSubject.value;
  }

  // ── Conversion ─────────────────────────────────────────────────────────────

  /**
   * Parses and converts a raw MITRE Navigator layer JSON string into the
   * internal model. Supports the current format (v4.5) and tolerates v4.x/v3
   * variants (single `version` string, `mitre-*` domains, missing gradient/
   * links). Throws with a friendly message on malformed or oversized input.
   */
  convert(json: string): LayerConversionResult {
    if (typeof json !== 'string' || !json.trim()) {
      throw new Error('Empty layer file.');
    }
    if (json.length > MAX_JSON_BYTES) {
      throw new Error('Layer file is too large (over 20 MB).');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('Failed to parse Navigator layer JSON.');
    }
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid Navigator layer: not a JSON object.');
    }

    const raw = parsed as Record<string, unknown>;
    if (!Array.isArray(raw['techniques'])) {
      throw new Error('Invalid Navigator layer: missing techniques array.');
    }
    if ((raw['techniques'] as unknown[]).length > MAX_TECHNIQUES) {
      throw new Error('Layer file has too many technique entries.');
    }

    const warnings: string[] = [];
    const { domain, navigatorDomain, known } = this.normalizeDomain(raw['domain']);
    if (!known) {
      warnings.push(
        `Unrecognized layer domain "${String(raw['domain'] ?? '')}" — treating it as Enterprise ATT&CK.`,
      );
    }

    const { attackVersion, navigatorVersion, layerVersion, sourceFormat } = this.readVersions(raw);
    const techniques = this.convertTechniques(raw['techniques'] as unknown[]);

    const layer: AttackNaviLayer = {
      id: this.newId(),
      name: this.str(raw['name']) || 'Imported Layer',
      description: this.str(raw['description']),
      domain,
      navigatorDomain,
      attackVersion,
      navigatorVersion,
      layerVersion,
      filters: { platforms: this.strArray(this.pick(raw['filters'], 'platforms')) },
      gradient: this.convertGradient(raw['gradient']),
      legendItems: this.convertLegend(raw['legendItems']),
      metadata: this.convertMetadata(raw['metadata']),
      links: this.convertLinks(raw['links']),
      techniques,
      importedAt: new Date().toISOString(),
      sourceFormat,
    };
    return { layer, warnings };
  }

  private convertTechniques(rows: unknown[]): UserLayerTechnique[] {
    const out: UserLayerTechnique[] = [];
    for (const row of rows) {
      if (!row || typeof row !== 'object') continue;
      const r = row as Record<string, unknown>;
      const techniqueID = this.str(r['techniqueID']);
      if (!techniqueID) continue;
      out.push({
        techniqueID,
        tactic: this.str(r['tactic']),
        score: typeof r['score'] === 'number' && Number.isFinite(r['score']) ? (r['score'] as number) : null,
        color: this.str(r['color']),
        comment: this.str(r['comment']),
        enabled: typeof r['enabled'] === 'boolean' ? (r['enabled'] as boolean) : true,
        metadata: this.convertMetadata(r['metadata']),
        links: this.convertLinks(r['links']),
        showSubtechniques: r['showSubtechniques'] === true,
      });
    }
    return out;
  }

  private convertGradient(value: unknown): UserLayerGradient {
    if (!value || typeof value !== 'object') return { ...DEFAULT_GRADIENT };
    const g = value as Record<string, unknown>;
    const colors = this.strArray(g['colors']).filter(c => !!tinycolor(c).isValid());
    if (colors.length < 2) return { ...DEFAULT_GRADIENT };
    const minValue = this.num(g['minValue'], 0);
    const maxValue = this.num(g['maxValue'], 100);
    return { colors, minValue, maxValue: maxValue === minValue ? minValue + 1 : maxValue };
  }

  private convertLegend(value: unknown): { label: string; color: string }[] {
    if (!Array.isArray(value)) return [];
    return value
      .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object')
      .map(e => ({ label: this.str(e['label']), color: this.str(e['color']) }))
      .filter(e => e.label || e.color);
  }

  private convertMetadata(value: unknown): UserLayerMetadataEntry[] {
    if (!Array.isArray(value)) return [];
    return value
      .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object' && e['divider'] !== true)
      .map(e => ({ name: this.str(e['name']), value: this.str(e['value']) }))
      .filter(e => e.name || e.value);
  }

  private convertLinks(value: unknown): UserLayerLink[] {
    if (!Array.isArray(value)) return [];
    return value
      .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object' && e['divider'] !== true)
      .map(e => ({ label: this.str(e['label']), url: this.str(e['url']) }))
      .filter(e => e.label || e.url);
  }

  /**
   * Maps a Navigator `domain` string to an internal {@link AttackDomain}.
   * Handles current (`enterprise-attack`), legacy (`mitre-enterprise`) and bare
   * (`enterprise`) spellings.
   */
  private normalizeDomain(value: unknown): { domain: AttackDomain; navigatorDomain: string; known: boolean } {
    const raw = this.str(value);
    const key = raw.toLowerCase();
    if (/(^|-)ics/.test(key)) return { domain: 'ics', navigatorDomain: raw || 'ics-attack', known: true };
    if (key.includes('mobile')) return { domain: 'mobile', navigatorDomain: raw || 'mobile-attack', known: true };
    if (key.includes('enterprise')) return { domain: 'enterprise', navigatorDomain: raw || 'enterprise-attack', known: true };
    if (key === 'f3' || key.includes('fraud')) return { domain: 'f3', navigatorDomain: raw || 'f3', known: true };
    return { domain: 'enterprise', navigatorDomain: raw, known: false };
  }

  private readVersions(raw: Record<string, unknown>): {
    attackVersion: string; navigatorVersion: string; layerVersion: string; sourceFormat: string;
  } {
    const versions = raw['versions'];
    if (versions && typeof versions === 'object') {
      const v = versions as Record<string, unknown>;
      const layerVersion = this.str(v['layer']);
      return {
        attackVersion: this.str(v['attack']),
        navigatorVersion: this.str(v['navigator']),
        layerVersion,
        sourceFormat: layerVersion ? `navigator-${layerVersion}` : 'navigator-4.x',
      };
    }
    // v3 carried a single top-level `version` string.
    const legacy = this.str(raw['version']);
    return {
      attackVersion: '',
      navigatorVersion: '',
      layerVersion: legacy,
      sourceFormat: legacy ? `navigator-${legacy}` : 'navigator-3.x',
    };
  }

  // ── Active-layer accessors (matrix + sidebar read these) ─────────────────────

  /** The active layer's technique entry for a given ATT&CK id, or null. */
  getEntry(attackId: string): UserLayerTechnique | null {
    return this.activeIndex.get(attackId) ?? null;
  }

  /** Per-technique score for the `library` heatmap mode (0 when absent/unscored). */
  getScore(attackId: string): number {
    return this.activeIndex.get(attackId)?.score ?? 0;
  }

  /** Largest score in the active layer (for relative coloring). */
  maxScore(): number {
    return this.activeMaxScore;
  }

  /**
   * The cell color for a technique under the active layer, honoring the layer's
   * own data: an explicit per-technique `color` wins; otherwise the score is
   * interpolated across the layer's gradient. Returns null when the technique is
   * absent, disabled, or unscored with no explicit color.
   */
  getGradientColor(attackId: string): string | null {
    const entry = this.activeIndex.get(attackId);
    const layer = this.activeLayer;
    if (!entry || !layer || !entry.enabled) return null;
    if (entry.color && tinycolor(entry.color).isValid()) {
      return tinycolor(entry.color).toHexString();
    }
    if (entry.score === null) return null;
    return this.interpolateGradient(entry.score, layer.gradient);
  }

  /** Linear interpolation of a score across the gradient's color stops. */
  private interpolateGradient(score: number, gradient: UserLayerGradient): string {
    const { colors, minValue, maxValue } = gradient;
    if (colors.length === 1) return tinycolor(colors[0]).toHexString();
    const span = maxValue - minValue || 1;
    const ratio = Math.max(0, Math.min(1, (score - minValue) / span));
    const scaled = ratio * (colors.length - 1);
    const lower = Math.floor(scaled);
    const upper = Math.min(lower + 1, colors.length - 1);
    const localRatio = scaled - lower;
    return tinycolor.mix(colors[lower], colors[upper], localRatio * 100).toHexString();
  }

  // ── Activation ───────────────────────────────────────────────────────────────

  /** Loads a saved layer by id and makes it the active layer. */
  async setActive(id: string): Promise<AttackNaviLayer | null> {
    const layer = await this.getLayer(id);
    if (layer) this.applyActive(layer);
    return layer;
  }

  /** Applies an in-memory layer object as active (no persistence read). */
  applyActive(layer: AttackNaviLayer): void {
    this.activeIndex = new Map(layer.techniques.map(t => [t.techniqueID, t]));
    const scores = layer.techniques.map(t => t.score ?? 0);
    this.activeMaxScore = scores.length ? Math.max(1, ...scores) : 1;
    this.activeLayerSubject.next(layer);
    this.changedSubject.next(true);
  }

  /** Clears the active layer (matrix/sidebar stop showing user-layer data). */
  clearActive(): void {
    this.activeIndex = new Map();
    this.activeMaxScore = 1;
    this.activeLayerSubject.next(null);
    this.changedSubject.next(true);
  }

  // ── Persistence (IndexedDB CRUD) ─────────────────────────────────────────────

  /** Convert + persist + activate in one step. Returns the conversion result. */
  async importAndSave(json: string): Promise<LayerConversionResult> {
    const result = this.convert(json);
    await this.saveLayer(result.layer);
    this.applyActive(result.layer);
    return result;
  }

  async saveLayer(layer: AttackNaviLayer): Promise<void> {
    const db = await this.openIDB();
    await new Promise<void>((res, rej) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const req = tx.objectStore(IDB_STORE).put(layer);
      req.onsuccess = () => res();
      req.onerror = () => rej(req.error);
    });
    await this.refreshList();
  }

  async getLayer(id: string): Promise<AttackNaviLayer | null> {
    try {
      const db = await this.openIDB();
      return await new Promise((res, rej) => {
        const tx = db.transaction(IDB_STORE, 'readonly');
        const req = tx.objectStore(IDB_STORE).get(id);
        req.onsuccess = () => res((req.result as AttackNaviLayer) ?? null);
        req.onerror = () => rej(req.error);
      });
    } catch {
      return null;
    }
  }

  async deleteLayer(id: string): Promise<void> {
    const db = await this.openIDB();
    await new Promise<void>((res, rej) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const req = tx.objectStore(IDB_STORE).delete(id);
      req.onsuccess = () => res();
      req.onerror = () => rej(req.error);
    });
    if (this.activeLayer?.id === id) this.clearActive();
    await this.refreshList();
  }

  /** Reloads the saved-layer metadata list from IndexedDB. */
  async refreshList(): Promise<void> {
    const metas = await this.listMetas();
    metas.sort((a, b) => b.importedAt.localeCompare(a.importedAt));
    this.layersSubject.next(metas);
  }

  private async listMetas(): Promise<AttackNaviLayerMeta[]> {
    try {
      const db = await this.openIDB();
      const layers: AttackNaviLayer[] = await new Promise((res, rej) => {
        const tx = db.transaction(IDB_STORE, 'readonly');
        const req = tx.objectStore(IDB_STORE).getAll();
        req.onsuccess = () => res((req.result as AttackNaviLayer[]) ?? []);
        req.onerror = () => rej(req.error);
      });
      return layers.map(toLayerMeta);
    } catch {
      return [];
    }
  }

  private openIDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_DB, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE, { keyPath: 'id' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  // ── Small helpers ────────────────────────────────────────────────────────────

  private newId(): string {
    return `layer-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }

  private str(value: unknown): string {
    return typeof value === 'string' ? value : '';
  }

  private num(value: unknown, fallback: number): number {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      const n = Number(value);
      if (Number.isFinite(n)) return n;
    }
    return fallback;
  }

  private strArray(value: unknown): string[] {
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
  }

  private pick(value: unknown, key: string): unknown {
    return value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined;
  }
}

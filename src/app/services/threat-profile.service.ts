// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subscription } from 'rxjs';
import { DataService } from './data.service';
import { LibraryLayerService } from './library-layer.service';
import { Domain } from '../models/domain';
import { readV2, writeV2, V2Envelope } from '../models/storage-envelope';
import { ThreatProfile, ThreatProfileSource, LibraryLayerInput, resolveProfile } from '../models/threat-profile';

const STORAGE_KEY = 'navi.v2.threat-profile';
const DEFAULT_SOURCE: ThreatProfileSource = { kind: 'top-groups', n: 20 };

/**
 * A stored source is a ThreatProfileSource carrying the v2 envelope. Every kind's
 * own fields are validated: the key is in WorkspaceBundleService.BUNDLED_KEYS, so a
 * record can arrive from an imported bundle. A malformed one (for example
 * `{kind:'groups', ids:{}}`, which would throw in `new Set(ids)`) must fail here so
 * readV2 drops it and the service falls back to the default, rather than crashing on
 * every load (a persistent client-side DoS).
 */
function isStoredSource(x: unknown): x is ThreatProfileSource & V2Envelope {
  const r = x as Record<string, unknown>;
  if (!r || typeof r['source'] !== 'string' || typeof r['createdAt'] !== 'string') return false;
  switch (r['kind']) {
    case 'top-groups': return Number.isInteger(r['n']) && (r['n'] as number) >= 0 && (r['n'] as number) <= 1000;
    case 'groups':
    case 'campaigns': return Array.isArray(r['ids']) && (r['ids'] as unknown[]).every((i) => typeof i === 'string');
    case 'library-layer': return typeof r['file'] === 'string';
    case 'all': return true;
    default: return false;
  }
}

/** The label shown before a domain has loaded; resolveProfile recomputes it once a Domain is present. */
function labelFor(src: ThreatProfileSource): string {
  switch (src.kind) {
    case 'top-groups': return `Top ${Number.isFinite(src.n) ? Math.max(1, Math.trunc(src.n)) : 1} groups by prevalence`;
    case 'groups': return 'Groups';
    case 'campaigns': return 'Campaigns';
    case 'library-layer': return src.file;
    case 'all': return 'All techniques';
  }
}

/** Drop the envelope fields, returning the plain ThreatProfileSource. */
function sourceFromRecord(r: ThreatProfileSource & V2Envelope): ThreatProfileSource {
  switch (r.kind) {
    case 'top-groups': return { kind: 'top-groups', n: r.n };
    case 'groups': return { kind: 'groups', ids: r.ids };
    case 'campaigns': return { kind: 'campaigns', ids: r.ids };
    case 'library-layer': return { kind: 'library-layer', file: r.file };
    case 'all': return { kind: 'all' };
  }
}

@Injectable({ providedIn: 'root' })
export class ThreatProfileService implements OnDestroy {
  private source: ThreatProfileSource;
  /** The resolved layer input for a `library-layer` source; null until it loads. */
  private layerInput: LibraryLayerInput | null = null;
  private layerSub?: Subscription;
  private profileSubject: BehaviorSubject<ThreatProfile>;
  readonly profile$: Observable<ThreatProfile>;
  private readonly sub: Subscription;

  constructor(private dataService: DataService, private libraryLayers: LibraryLayerService) {
    this.source = this.loadSource();
    this.profileSubject = new BehaviorSubject<ThreatProfile>(this.build(this.dataService.getCurrentDomain()));
    this.profile$ = this.profileSubject.asObservable();
    // Re-resolve on every domain emission, INCLUDING null: a domain switch emits null
    // first (data.service), and leaving the old profile up would show a cross-domain
    // denominator while getCurrentAttackDomain() already names the new domain.
    this.sub = this.dataService.domain$.subscribe((domain) => this.profileSubject.next(this.build(domain)));
    this.loadLayerIfNeeded();
  }

  get current(): ThreatProfile {
    return this.profileSubject.value;
  }

  setSource(src: ThreatProfileSource): void {
    this.source = src;
    this.persist(src);
    this.loadLayerIfNeeded();   // clears or (re)loads the layer input, then re-emits
    this.profileSubject.next(this.build(this.dataService.getCurrentDomain()));
  }

  weight(techniqueStixId: string): number {
    return this.current.weight(techniqueStixId);
  }

  /** Resolve against a loaded domain, or an empty profile (label only) before one is present. */
  private build(domain: Domain | null): ThreatProfile {
    if (domain) {
      // Defensive: a resolve failure must not throw inside the domain$ subscription.
      try { return resolveProfile(this.source, domain, this.layerInput ?? undefined); } catch { /* fall through */ }
    }
    const src = this.source;
    return {
      source: src,
      domain: this.dataService.getCurrentAttackDomain(),
      label: labelFor(src),
      groupIds: [],
      techniqueIds: new Set(),
      parentTechniqueIds: new Set(),
      weight: () => 0,
      usedBy: () => [],
    };
  }

  /** A library-layer source needs its technique ids loaded (async); other kinds clear the input. */
  private loadLayerIfNeeded(): void {
    this.layerSub?.unsubscribe();
    this.layerInput = null;
    const src = this.source;
    if (src.kind !== 'library-layer') return;
    const file = src.file;
    this.layerSub = this.libraryLayers.layerTechniqueIds(file).subscribe((ids) => {
      const meta = this.libraryLayers.manifest.find((m) => m.file === file) ?? { file, name: file, description: '' };
      this.layerInput = { meta, techniques: ids.map((techniqueID) => ({ techniqueID })) };
      this.profileSubject.next(this.build(this.dataService.getCurrentDomain()));
    });
  }

  private loadSource(): ThreatProfileSource {
    try {
      const record = readV2<ThreatProfileSource>(STORAGE_KEY, isStoredSource).records[0];
      return record ? sourceFromRecord(record) : DEFAULT_SOURCE;
    } catch {
      return DEFAULT_SOURCE;
    }
  }

  private persist(src: ThreatProfileSource): void {
    const now = new Date().toISOString();
    const record: ThreatProfileSource & V2Envelope = {
      ...src,
      domain: this.dataService.getCurrentAttackDomain(),
      attackVersion: this.dataService.getCurrentDomain()?.attackVersion ?? 'unknown',
      source: 'manual',
      createdAt: now,
      updatedAt: now,
    };
    writeV2<ThreatProfileSource>(STORAGE_KEY, { schema: 2, tombstones: [], records: [record] });
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
    this.layerSub?.unsubscribe();
  }
}

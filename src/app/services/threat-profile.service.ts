// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subscription } from 'rxjs';
import { DataService } from './data.service';
import { Domain } from '../models/domain';
import { readV2, writeV2, V2Envelope } from '../models/storage-envelope';
import { ThreatProfile, ThreatProfileSource, resolveProfile } from '../models/threat-profile';

const STORAGE_KEY = 'navi.v2.threat-profile';
const DEFAULT_SOURCE: ThreatProfileSource = { kind: 'top-groups', n: 20 };

const KINDS: ReadonlySet<string> = new Set(['top-groups', 'groups', 'campaigns', 'library-layer', 'all']);
/** A stored source is a ThreatProfileSource carrying the v2 envelope. */
function isStoredSource(x: unknown): x is ThreatProfileSource & V2Envelope {
  const r = x as Record<string, unknown>;
  return !!r && typeof r['kind'] === 'string' && KINDS.has(r['kind'] as string)
    && typeof r['source'] === 'string' && typeof r['createdAt'] === 'string';
}

/** The label shown before a domain has loaded; resolveProfile recomputes it once a Domain is present. */
function labelFor(src: ThreatProfileSource): string {
  switch (src.kind) {
    case 'top-groups': return `Top ${src.n} groups by prevalence`;
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
  private profileSubject: BehaviorSubject<ThreatProfile>;
  readonly profile$: Observable<ThreatProfile>;
  private readonly sub: Subscription;

  constructor(private dataService: DataService) {
    this.source = this.loadSource();
    this.profileSubject = new BehaviorSubject<ThreatProfile>(this.build(this.dataService.getCurrentDomain()));
    this.profile$ = this.profileSubject.asObservable();
    // Re-resolve the stored source whenever a domain loads or the user switches domains.
    this.sub = this.dataService.domain$.subscribe((domain) => {
      if (domain) this.profileSubject.next(this.build(domain));
    });
  }

  get current(): ThreatProfile {
    return this.profileSubject.value;
  }

  setSource(src: ThreatProfileSource): void {
    this.source = src;
    this.persist(src);
    this.profileSubject.next(this.build(this.dataService.getCurrentDomain()));
  }

  weight(techniqueStixId: string): number {
    return this.current.weight(techniqueStixId);
  }

  /** Resolve against a loaded domain, or an empty profile (label only) before one is present. */
  private build(domain: Domain | null): ThreatProfile {
    if (domain) return resolveProfile(this.source, domain);
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

  private loadSource(): ThreatProfileSource {
    const record = readV2<ThreatProfileSource>(STORAGE_KEY, isStoredSource).records[0];
    return record ? sourceFromRecord(record) : DEFAULT_SOURCE;
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
  }
}

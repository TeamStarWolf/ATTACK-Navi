// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Inject, Injectable, InjectionToken, OnDestroy, Optional, Signal, computed, signal } from '@angular/core';
import { BehaviorSubject, Observable, Subscription } from 'rxjs';
import { DataService } from './data.service';
import { LibraryLayerService } from './library-layer.service';
import { Domain } from '../models/domain';
import { readV2, writeV2, V2Envelope } from '../models/storage-envelope';
import type { ThreatProfileEmptyReason, ThreatWeightProvider } from '../models/posture/posture.types';
import {
  ThreatProfile, ThreatProfileSource, LibraryLayerInput, ProfileDomainGroups, ProfileGroupRef,
  type GroupIndexEntry, type KnownGroup, STIX_GROUP_ID, attackDomainOf, currentIndexedGroups, groupNameHints, indexGroups,
  normaliseStoredGroupIds, profileDomainNotice, resolveProfile, resolveStoredGroup, splitStoredGroups,
  threatProfileEmptyReason,
} from '../models/threat-profile';
import GROUP_INDEX_DATA from '../../assets/data/group-index.json';

/**
 * The all-domain group index the profile resolves stored ids against (RP-F decision
 * 25): src/assets/data/group-index.json, built from the bundled Enterprise, ICS and
 * Mobile STIX files by scripts/build-group-index.mjs. Provided for specs; the app
 * reads the bundled file.
 */
export const GROUP_INDEX = new InjectionToken<readonly GroupIndexEntry[]>('GROUP_INDEX');

/** The bundled index's groups. */
export const BUNDLED_GROUP_INDEX: readonly GroupIndexEntry[] = (GROUP_INDEX_DATA as { groups: GroupIndexEntry[] }).groups;

const STORAGE_KEY = 'navi.v2.threat-profile';
const DEFAULT_SOURCE: ThreatProfileSource = { kind: 'top-groups', n: 20 };

/**
 * The stored record. `groupNames` is a display hint only (STIX id to group name, for
 * a groups source): the name of every stored id that resolves to a real group
 * (groupNameHints), written whenever it changes. It is never part of the source and
 * never a resolution (RP-F decision 25): the group index names an absent group.
 */
type StoredRecord = ThreatProfileSource & V2Envelope & { readonly groupNames?: Readonly<Record<string, string>> };

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

/**
 * The stored name hint as data: only string-to-string entries keyed by a STIX
 * intrusion-set id (it may come from an imported bundle); anything else is dropped.
 * It is compared, never resolved against (RP-F decision 25).
 */
function readHint(hint: unknown): Readonly<Record<string, string>> {
  const out: Record<string, string> = Object.create(null);
  if (!hint || typeof hint !== 'object' || Array.isArray(hint)) return out;
  for (const [id, name] of Object.entries(hint as Record<string, unknown>)) {
    if (STIX_GROUP_ID.test(id) && typeof name === 'string' && name.length > 0) out[id] = name;
  }
  return out;
}

/** Two name hints hold the same entries. */
function sameHint(a: Readonly<Record<string, string>>, b: Readonly<Record<string, string>>): boolean {
  const ka = Object.keys(a);
  return ka.length === Object.keys(b).length && ka.every((k) => b[k] === a[k]);
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
export class ThreatProfileService implements OnDestroy, ThreatWeightProvider {
  private source: ThreatProfileSource;
  /** The resolved layer input for a `library-layer` source; null until it loads. */
  private layerInput: LibraryLayerInput | null = null;
  private layerSub?: Subscription;
  private profileSubject: BehaviorSubject<ThreatProfile>;
  readonly profile$: Observable<ThreatProfile>;
  private readonly sub: Subscription;

  // THREAT_WEIGHT_PROVIDER revision (P2-10): a signal bumped on every profile$
  // emission (domain switch, setSource, layer load), so PostureService.states —
  // which reads weight() imperatively — tracks the profile and recomputes. The
  // bump happens in a subscription, never inside a computed; the service stays a
  // BehaviorSubject service (§10.4 item 9), this is only the seam's signal bridge.
  private readonly revisionSig = signal(0);
  readonly revision: Signal<number> = this.revisionSig.asReadonly();
  // The profile's parent technique ids, kept in sync with profile$ so the posture card
  // (and P2-17/P2-12) can read the threat-relevant denominator through the token signal.
  private readonly parentsSig = signal<ReadonlySet<string>>(new Set());
  readonly parents: Signal<ReadonlySet<string>> = this.parentsSig.asReadonly();
  // Why parents() is empty (RP-F item 6, round 1), so the Threat gaps legend can say
  // something true: an empty source, a profile still resolving, or one with no
  // technique in the loaded domain. Set before the revision bump it travels with.
  private readonly emptyReasonSig = signal<ThreatProfileEmptyReason | null>(null);
  readonly emptyReason: Signal<ThreatProfileEmptyReason | null> = this.emptyReasonSig.asReadonly();
  /** Whether the last profile was resolved against a loaded domain. */
  private domainLoaded = false;
  /** The domain the last profile was resolved against (null while one loads). */
  private lastDomain: Domain | null = null;
  /**
   * Every real group: the current groups of the all-domain group index (RP-F decision
   * 25) and of every domain loaded this session, keyed as splitStoredGroups reads it
   * (STIX id and ATT&CK id; GroupIdIndex), so an absent group is named by its name,
   * not its id, and named once when stored under both ids (RP-F decision 13), on a
   * fresh boot into a domain that lacks it as much as after a switch. A stored name
   * hint is never learned here: a hint is never a resolution.
   */
  private readonly knownGroups = new Map<string, KnownGroup>();
  /** The name hint as stored (or last written), so normaliseSource writes only on a change. */
  private storedHint: Readonly<Record<string, string>> = {};
  // The stored groups split against the loaded domain (a groups source only), kept in
  // sync with profile$. A domain switch changes the split, never the stored source.
  private readonly domainGroupsSig = signal<ProfileDomainGroups | null>(null);
  readonly domainGroups: Signal<ProfileDomainGroups | null> = this.domainGroupsSig.asReadonly();
  /** The one cross-domain sentence (profileDomainNotice), or null when no stored group is absent. */
  readonly domainNotice: Signal<string | null> = computed(() => profileDomainNotice(this.domainGroupsSig()));

  constructor(
    private dataService: DataService,
    private libraryLayers: LibraryLayerService,
    @Optional() @Inject(GROUP_INDEX) groupIndex: readonly GroupIndexEntry[] | null = null,
  ) {
    indexGroups(this.knownGroups, currentIndexedGroups(groupIndex ?? BUNDLED_GROUP_INDEX));
    this.source = this.loadSource();
    const initial = this.dataService.getCurrentDomain();
    this.domainLoaded = !!initial;
    this.lastDomain = initial;
    this.learnNames(initial);
    this.normaliseSource();
    this.profileSubject = new BehaviorSubject<ThreatProfile>(this.build(initial));
    this.profile$ = this.profileSubject.asObservable();
    // Re-resolve on every domain emission, INCLUDING null: a domain switch emits null
    // first (data.service), and leaving the old profile up would show a cross-domain
    // denominator while getCurrentAttackDomain() already names the new domain.
    this.sub = this.dataService.domain$.subscribe((domain) => this.emit(domain));
    this.sub.add(this.profile$.subscribe((p) => {
      this.emptyReasonSig.set(threatProfileEmptyReason(
        this.source, p.parentTechniqueIds.size, this.domainLoaded,
        this.source.kind !== 'library-layer' || this.layerInput !== null));
      this.domainGroupsSig.set(this.splitFor(this.lastDomain));
      this.revisionSig.update((n) => n + 1);
      this.parentsSig.set(p.parentTechniqueIds);
    }));
    this.loadLayerIfNeeded();
  }

  get current(): ThreatProfile {
    return this.profileSubject.value;
  }

  setSource(src: ThreatProfileSource): void {
    this.source = src;
    this.persist(src);
    this.loadLayerIfNeeded();   // clears or (re)loads the layer input, then re-emits
    this.emit(this.dataService.getCurrentDomain());
  }

  /**
   * The stored groups `domain` carries (a groups source only; [] for every other kind,
   * the 'all' profile included, and while no domain is loaded). Same membership rule
   * as resolveProfile (splitStoredGroups).
   */
  presentGroups(domain: Domain | null): ProfileGroupRef[] {
    return [...(this.splitFor(domain)?.present ?? [])];
  }

  /**
   * The stored groups `domain` lacks, named (a groups source only; [] otherwise). They
   * stay in the stored source: a domain switch never narrows the profile.
   */
  absentGroups(domain: Domain | null): ProfileGroupRef[] {
    return [...(this.splitFor(domain)?.absent ?? [])];
  }

  /**
   * The stored ids that resolve to no group seen this session (a groups source only; []
   * otherwise): aliases, revoked or unknown ATT&CK ids, malformed STIX ids (RP-F decision
   * 18). Named as stored and marked `unresolved`; they stay in the stored source.
   */
  unresolvedGroups(domain: Domain | null): ProfileGroupRef[] {
    return (this.splitFor(domain)?.unresolved ?? []).map((id) => ({ id, name: id, unresolved: true }));
  }

  /** The split behind presentGroups/absentGroups/unresolvedGroups, or null when it does not apply. */
  private splitFor(domain: Domain | null): ProfileDomainGroups | null {
    const src = this.source;
    if (!domain || src.kind !== 'groups') return null;
    const { present, absentIds, unresolvedIds } = splitStoredGroups(src.ids, domain, this.knownGroups);
    return {
      domain: attackDomainOf(domain),
      present: present.map((g) => ({ id: g.id, name: g.name })),
      absent: absentIds.map((id) => ({ id, name: resolveStoredGroup(this.knownGroups, id)?.name ?? id })),
      unresolved: unresolvedIds,
    };
  }

  /** Remember every group of a loaded domain (ids and names only; nothing is stored). */
  private learnNames(domain: Domain | null): void {
    indexGroups(this.knownGroups, domain?.groups ?? []);
  }

  /**
   * One shape in storage (RP-F decisions 18 and 25): a groups source's ids are
   * trimmed, empty ids dropped, and ATT&CK ids (G0016, any case) become the STIX ids
   * of the real groups they name (the group index or a loaded domain); the record is
   * written back with the name hint of every resolved id. Ids that resolve to no real
   * group are kept as they are: an unresolved id is announced, never dropped. Runs at
   * construction and on every domain load; writes only when the ids or the hint change
   * (a hint-less store gains its hint on the first load, so it reads the same after F5).
   */
  private normaliseSource(): void {
    const src = this.source;
    if (src.kind !== 'groups') return;
    const ids = normaliseStoredGroupIds(src.ids, this.knownGroups);
    const sameIds = ids.length === src.ids.length && ids.every((id, i) => id === src.ids[i]);
    if (sameIds && sameHint(groupNameHints(ids, this.knownGroups), this.storedHint)) return;
    this.source = { kind: 'groups', ids };
    this.persist(this.source);
  }

  /**
   * A navi.v2.threat-profile value arriving in a workspace bundle, in the stored shape
   * (RP-F decision 18): its groups ids normalised against the groups seen this session,
   * with the name hint of each that resolves. Anything that does not parse as a v2
   * store is returned unchanged (loadSource validates it as it always has).
   */
  normaliseImportedValue(value: string): string {
    try {
      const store = JSON.parse(value) as { records?: unknown };
      if (!store || typeof store !== 'object' || !Array.isArray(store.records)) return value;
      const records = store.records.map((r: unknown) => {
        const rec = r as Record<string, unknown> | null;
        if (!rec || rec['kind'] !== 'groups' || !Array.isArray(rec['ids']) || !rec['ids'].every((i) => typeof i === 'string')) return r;
        // RP-F decision 25: the hint is rebuilt from the ids that resolve; an imported hint
        // is never a resolution, so one naming an unresolved id is not carried over.
        const ids = normaliseStoredGroupIds(rec['ids'] as string[], this.knownGroups);
        return { ...rec, ids, groupNames: groupNameHints(ids, this.knownGroups) };
      });
      return JSON.stringify({ ...store, records });
    } catch {
      return value;
    }
  }

  /** Resolve against `domain` (null while one loads) and emit. */
  private emit(domain: Domain | null): void {
    this.domainLoaded = !!domain;
    this.lastDomain = domain;
    this.learnNames(domain);
    this.normaliseSource();
    this.profileSubject.next(this.build(domain));
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
      usedByDirect: () => [],
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
      this.emit(this.dataService.getCurrentDomain());
    });
  }

  private loadSource(): ThreatProfileSource {
    try {
      const record = readV2<ThreatProfileSource>(STORAGE_KEY, isStoredSource).records[0] as StoredRecord | undefined;
      if (!record) return DEFAULT_SOURCE;
      this.storedHint = readHint(record.groupNames);
      return sourceFromRecord(record);
    } catch {
      return DEFAULT_SOURCE;
    }
  }

  private persist(src: ThreatProfileSource): void {
    const now = new Date().toISOString();
    const names = src.kind === 'groups' ? groupNameHints(src.ids, this.knownGroups) : {};
    if (src.kind === 'groups') this.storedHint = names;
    const record: StoredRecord = {
      ...src,
      ...(src.kind === 'groups' ? { groupNames: names } : {}),
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

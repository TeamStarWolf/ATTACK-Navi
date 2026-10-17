// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, Subscription, defer, from, of, throwError } from 'rxjs';
import { catchError, distinctUntilChanged, map, switchMap, tap } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { SourceRegistryService } from './source-registry.service';
import { SOURCE_DEFINITIONS } from './source-inventory';
import { SettingsService } from './settings.service';
import { Domain, TacticColumn, DetectionNote } from '../models/domain';
import { Tactic } from '../models/tactic';
import { Technique } from '../models/technique';
import { Mitigation, MitigationRelationship } from '../models/mitigation';
import { ThreatGroup } from '../models/group';
import { AttackSoftware } from '../models/software';
import { ProcedureExample } from '../models/procedure';
import { MitreDataSource, MitreDataComponent } from '../models/datasource';
import { Campaign } from '../models/campaign';

/**
 * How ATT&CK reaches the matrix (decision D2: the bundled version is pinned).
 * - 'bundled' (the default for a fresh profile): only the pinned bundle shipped with the
 *   build is loaded; MITRE is contacted only when the user asks "Check for ATT&CK update".
 * - 'live': the pinned bundle is still what loads, and each load also checks MITRE for a
 *   newer release and offers it. Neither mode ever swaps the version on screen by itself:
 *   a newer release is applied only by an explicit click, and only for this session.
 * Persisted as the user setting AppSettings.attackDataMode.
 */
export type DataSourceMode = 'live' | 'bundled';

/** Where an ATT&CK update check stands, for the domain on screen. */
export type AttackUpdateStatus = 'idle' | 'checking' | 'up-to-date' | 'available' | 'failed' | 'applied';

export interface AttackUpdateState {
  status: AttackUpdateStatus;
  domain?: AttackDomain;
  /** The pinned (bundled) release, read from the bundle's own collection object via the SourceRegistry. */
  pinnedVersion?: string;
  /** The release MITRE publishes now (set once a check has fetched it). */
  liveVersion?: string;
  /** Why the check failed ('failed' only). */
  error?: string;
}

/**
 * Compare two dotted ATT&CK release numbers ('19.2' vs '20.0'). Returns a negative
 * number when a < b, 0 when equal, positive when a > b; null when either is not a
 * release number, so an unreadable version is never mistaken for a newer one.
 */
export function compareAttackVersions(a: string, b: string): number | null {
  const parse = (v: string) => (/^\d+(\.\d+)*$/.test(v.trim()) ? v.trim().split('.').map(Number) : null);
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export type AttackDomain = 'enterprise' | 'ics' | 'mobile' | 'f3';

type DomainConfig = {
  liveUrl: string;
  bundledUrl: string | null;
  idbKey: string;
  name: string;
  /** SourceRegistry ids of the bundled snapshot and the live copy. */
  sourceId: string;
  liveSourceId: string;
};

const DOMAIN_CONFIG: Record<AttackDomain, DomainConfig> = {
  enterprise: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    bundledUrl: 'assets/data/enterprise-attack.json',
    idbKey: 'enterprise-attack-v2',
    name: 'Enterprise ATT&CK',
    sourceId: 'attack-enterprise',
    liveSourceId: 'attack-live-enterprise',
  },
  ics: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
    bundledUrl: 'assets/data/ics-attack.json',
    idbKey: 'ics-attack-v1',
    name: 'ICS ATT&CK',
    sourceId: 'attack-ics',
    liveSourceId: 'attack-live-ics',
  },
  mobile: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
    bundledUrl: 'assets/data/mobile-attack.json',
    idbKey: 'mobile-attack-v1',
    name: 'Mobile ATT&CK',
    sourceId: 'attack-mobile',
    liveSourceId: 'attack-live-mobile',
  },
  // CTID's F3 Fraud Framework (ctid.mitre.org/fraud) — ATT&CK-convention STIX
  // (123 techniques incl. 49 subtechniques, 8 tactics, source_name mitre-f3).
  // It ships no mitigations/groups, so coverage features are honestly empty.
  f3: {
    liveUrl: 'https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json',
    bundledUrl: 'assets/data/f3-attack.json',
    idbKey: 'f3-attack-v1',
    name: 'F3 Fraud Framework',
    sourceId: 'attack-f3',
    liveSourceId: 'attack-live-f3',
  },
};

const IDB_DB = 'mitre-navigator-cache';
const IDB_STORE = 'stix-bundles';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
/** SourceRecord note for a live ATT&CK source served from the IndexedDB cache this session. */
export const CACHED_LIVE_NOTE = 'Served this session from the IndexedDB cache of an earlier live fetch (at most 24 hours old); not re-fetched.';

export const ATTACK_NAVIGATOR_DOMAIN_CONFIG: Record<AttackDomain, { navigatorDomain: string; defaultPlatforms: string[] }> = {
  enterprise: {
    navigatorDomain: 'enterprise-attack',
    defaultPlatforms: ['Windows', 'Linux', 'macOS', 'Azure AD', 'Office 365', 'Google Workspace', 'SaaS', 'IaaS', 'Network', 'Containers', 'PRE'],
  },
  ics: {
    navigatorDomain: 'ics-attack',
    defaultPlatforms: ['Control Server', 'Data Historian', 'Device Configuration/Parameters', 'Engineering Workstation', 'Field Controller/RTU/PLC/IED', 'Human-Machine Interface', 'Input/Output Server', 'Safety Instrumented System/Protection Relay'],
  },
  mobile: {
    navigatorDomain: 'mobile-attack',
    defaultPlatforms: ['Android', 'iOS'],
  },
  f3: {
    navigatorDomain: 'f3',
    defaultPlatforms: [],
  },
};

@Injectable({ providedIn: 'root' })
export class DataService {
  private domainSubject = new BehaviorSubject<Domain | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(false);
  private errorSubject = new BehaviorSubject<string | null>(null);
  // D2: the pinned bundle is the default. The persisted user setting (AppSettings.attackDataMode)
  // replaces this in the constructor; a fresh profile has no setting and stays 'bundled'.
  private mode: DataSourceMode = 'bundled';
  private attackDomain: AttackDomain = 'enterprise';

  currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');

  /** ISO timestamp of the last successful domain data load */
  lastFetched$ = new BehaviorSubject<string | null>(null);

  /**
   * Where the currently displayed domain data came from:
   * 'bundled' = the pinned bundle (decision D2, epic E1.4);
   * 'live' = a newer release the user chose with applyUpdate() for this
   * session only;
   * 'cached' = no longer emitted since E1.4 (kept in the type for the legend).
   */
  freshness$ = new BehaviorSubject<'bundled' | 'cached' | 'live' | null>(null);
  private loadRequestId = 0;
  private domainSub?: Subscription;

  /** The state of "Check for ATT&CK update" for the domain on screen. */
  readonly update$ = new BehaviorSubject<AttackUpdateState>({ status: 'idle' });
  private checkSub?: Subscription;
  private checkRequestId = 0;
  /** A newer release fetched by a check and offered, not yet applied. */
  private pendingUpdate: { domain: AttackDomain; data: Domain } | null = null;
  /**
   * Releases the user chose to use for this session only (in memory, never persisted):
   * a reload or a new tab starts on the pinned bundle again.
   */
  private sessionUpdates = new Map<AttackDomain, Domain>();

  domain$: Observable<Domain | null> = this.domainSubject.asObservable();
  loading$: Observable<boolean> = this.loadingSubject.asObservable();
  error$: Observable<string | null> = this.errorSubject.asObservable();

  constructor(
    private http: HttpClient,
    // DI always supplies the root resolver; the default only serves callers
    // that construct the parser directly (e.g. the lens test harness).
    private attackIdResolver: AttackIdResolverService = new AttackIdResolverService(),
    private sources: SourceRegistryService = new SourceRegistryService(),
    settings: SettingsService = new SettingsService(),
  ) {
    // Keep the shared resolver in step with whichever domain is on screen, so
    // lookup tables keyed by retired ids translate against the same release.
    this.domainSubject.subscribe((domain) => this.attackIdResolver.setSupersededBy(domain?.supersededBy));
    // The data mode is a persisted user setting; 'bundled' when nothing was saved.
    settings.settings$.pipe(
      map((s) => (s.attackDataMode === 'live' ? 'live' : 'bundled') as DataSourceMode),
      distinctUntilChanged(),
    ).subscribe((mode) => { this.mode = mode; });
  }

  /**
   * The live technique id for `attackId` in the loaded domain: the id that
   * replaced it when ATT&CK retired it (following the full `revoked-by` chain,
   * see Domain.supersededBy), otherwise `attackId` unchanged.
   */
  resolveAttackId(attackId: string): string {
    return this.attackIdResolver.resolve(attackId);
  }

  /**
   * Set the data mode for this service instance. The persisted choice is the user
   * setting AppSettings.attackDataMode (Settings > Data), which this follows.
   */
  setDataSourceMode(mode: DataSourceMode): void {
    this.mode = mode;
  }

  getDataSourceMode(): DataSourceMode {
    return this.mode;
  }

  setAttackDomain(domain: AttackDomain): void {
    this.attackDomain = domain;
    this.currentDomain$.next(domain);
  }

  getCurrentAttackDomain(): AttackDomain {
    return this.attackDomain;
  }

  getCurrentDomain(): Domain | null {
    return this.domainSubject.value;
  }

  switchDomain(domain: AttackDomain): void {
    if (domain === this.currentDomain$.value) return;
    this.attackDomain = domain;
    this.currentDomain$.next(domain);
    this.domainSubject.next(null);
    this.loadDomain();
  }

  /**
   * Drop the cached live copy and this session's applied update for the domain on
   * screen, then reload the pinned bundle. Never fetches a newer release.
   */
  async forceRefresh(): Promise<void> {
    try {
      const config = DOMAIN_CONFIG[this.attackDomain];
      const db = await this.openIDB();
      await new Promise<void>((res, rej) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        const req = tx.objectStore(IDB_STORE).delete(config.idbKey);
        req.onsuccess = () => res();
        req.onerror = () => rej(req.error);
      });
    } catch { /* ignore */ }
    this.sessionUpdates.delete(this.attackDomain);
    this.loadDomain();
  }

  /**
   * Load the domain on screen: the pinned bundle, or the release the user chose for
   * this session. The version never changes here on its own (decision D2); in 'live'
   * mode the load is followed by an update check that only offers a newer release.
   */
  loadDomain(): void {
    this.domainSub?.unsubscribe();
    this.resetUpdateCheck();
    const requestId = ++this.loadRequestId;
    this.loadingSubject.next(true);
    this.errorSubject.next(null);

    const domainKey = this.attackDomain;
    const config = DOMAIN_CONFIG[domainKey];
    const chosen = this.sessionUpdates.get(domainKey);
    const load$ = chosen
      ? of(chosen).pipe(tap(() => this.freshness$.next('live')))
      : this.loadBundled(config).pipe(tap(() => this.freshness$.next('bundled')));
    const afterLoad = () => {
      if (chosen) this.update$.next(this.updateState('applied', domainKey, chosen.attackVersion));
      else if (this.mode === 'live') this.runUpdateCheck(true);
    };
    this.domainSub = load$.subscribe({
      next: (domain) => {
        if (requestId !== this.loadRequestId) return;
        this.domainSubject.next(domain);
        this.loadingSubject.next(false);
        this.lastFetched$.next(new Date().toISOString());
        afterLoad();
      },
      error: (err) => {
        if (requestId !== this.loadRequestId) return;
        this.errorSubject.next(err?.message ?? 'Failed to load ATT&CK data');
        this.loadingSubject.next(false);
        afterLoad();
      },
    });
  }

  /**
   * The pinned ATT&CK release of `domain`: the version the bundled file's own
   * x-mitre-collection object declares, as the SourceRegistry recorded it when the
   * bundle loaded, falling back to the inventory's bundled version before that.
   */
  pinnedVersion(domain: AttackDomain = this.attackDomain): string {
    const id = DOMAIN_CONFIG[domain].sourceId;
    return this.sources.get(id).version || SOURCE_DEFINITIONS.find((d) => d.id === id)?.version || '';
  }

  /**
   * "Check for ATT&CK update": fetch the release MITRE publishes now for the domain on
   * screen and compare it with the pinned one. A newer release is only offered
   * (update$ 'available'); nothing on screen changes until applyUpdate().
   */
  checkForUpdate(): void {
    this.runUpdateCheck(false);
  }

  /** Use the offered release for the domain on screen, for this session only. */
  applyUpdate(): void {
    const pending = this.pendingUpdate;
    if (!pending || pending.domain !== this.attackDomain) return;
    this.pendingUpdate = null;
    this.sessionUpdates.set(pending.domain, pending.data);
    // A load still in flight must not overwrite the release the user just chose.
    this.domainSub?.unsubscribe();
    this.loadRequestId++;
    this.domainSubject.next(pending.data);
    this.loadingSubject.next(false);
    this.freshness$.next('live');
    this.lastFetched$.next(new Date().toISOString());
    this.update$.next(this.updateState('applied', pending.domain, pending.data.attackVersion));
  }

  /** Decline the offer (or close the check's message); the pinned release stays. */
  dismissUpdate(): void {
    this.cancelCheck();
    this.pendingUpdate = null;
    this.update$.next({ status: 'idle' });
  }

  /** Leave this session's applied release and go back to the pinned bundle. */
  revertToPinned(): void {
    this.sessionUpdates.delete(this.attackDomain);
    this.loadDomain();
  }

  private updateState(status: AttackUpdateStatus, domain: AttackDomain, liveVersion?: string, error?: string): AttackUpdateState {
    return { status, domain, pinnedVersion: this.pinnedVersion(domain), liveVersion: liveVersion || undefined, error };
  }

  private cancelCheck(): void {
    this.checkSub?.unsubscribe();
    this.checkSub = undefined;
    this.checkRequestId++;
  }

  private resetUpdateCheck(): void {
    this.cancelCheck();
    this.pendingUpdate = null;
    if (this.update$.value.status !== 'idle') this.update$.next({ status: 'idle' });
  }

  /**
   * Fetch the live release for the domain on screen and compare it with the pinned one.
   * `allowCache`: the automatic check of 'live' mode may answer from a live copy cached in
   * IndexedDB in the last 24 hours; the explicit button always asks MITRE.
   */
  private runUpdateCheck(allowCache: boolean): void {
    this.cancelCheck();
    this.pendingUpdate = null;
    const checkId = this.checkRequestId;
    const domainKey = this.attackDomain;
    const config = DOMAIN_CONFIG[domainKey];
    this.update$.next(this.updateState('checking', domainKey));
    const live$ = allowCache
      ? from(this.loadFromIDB(config.idbKey)).pipe(
          switchMap((cached) => cached
            ? of(cached).pipe(tap(() => this.sources.succeed(config.liveSourceId, cached.techniques.length, {
                version: cached.attackVersion || undefined,
                note: CACHED_LIVE_NOTE,
              })))
            : this.fetchLive(config)),
        )
      : this.fetchLive(config);
    this.checkSub = live$.subscribe({
      next: (live) => {
        if (checkId !== this.checkRequestId || this.attackDomain !== domainKey) return;
        const pinned = this.pinnedVersion(domainKey);
        const order = compareAttackVersions(live.attackVersion ?? '', pinned);
        if (order === null) {
          this.update$.next(this.updateState('failed', domainKey, live.attackVersion,
            `the live release '${live.attackVersion || 'none'}' cannot be compared with the pinned '${pinned || 'none'}'`));
        } else if (order > 0) {
          this.pendingUpdate = { domain: domainKey, data: live };
          this.update$.next(this.updateState('available', domainKey, live.attackVersion));
        } else {
          this.update$.next(this.updateState('up-to-date', domainKey, live.attackVersion));
        }
      },
      error: (err) => {
        if (checkId !== this.checkRequestId || this.attackDomain !== domainKey) return;
        this.update$.next(this.updateState('failed', domainKey, undefined, err?.message ?? String(err)));
      },
    });
  }

  getMitigationsForTechnique(techniqueId: string): MitigationRelationship[] {
    return this.domainSubject.value?.mitigationsByTechnique.get(techniqueId) ?? [];
  }

  getTechniquesForMitigation(mitigationId: string): Technique[] {
    return this.domainSubject.value?.techniquesByMitigation.get(mitigationId) ?? [];
  }

  getGroupsForTechnique(techniqueId: string): ThreatGroup[] {
    return this.domainSubject.value?.groupsByTechnique.get(techniqueId) ?? [];
  }

  getTechniquesForGroup(groupId: string): Technique[] {
    return this.domainSubject.value?.techniquesByGroup.get(groupId) ?? [];
  }

  /**
   * Software a group actually uses per the ATT&CK STIX `uses` relationships.
   * (Previously this was inferred from shared techniques, which over-attributed:
   * any software touching a technique got credited to every group using it.)
   */
  getSoftwareForGroup(groupId: string): AttackSoftware[] {
    return this.domainSubject.value?.softwareByGroup.get(groupId) ?? [];
  }

  getGroupsForSoftware(softwareId: string): ThreatGroup[] {
    return this.domainSubject.value?.groupsBySoftware.get(softwareId) ?? [];
  }

  getSoftwareForCampaign(campaignId: string): AttackSoftware[] {
    return this.domainSubject.value?.softwareByCampaign.get(campaignId) ?? [];
  }

  getCampaignsForGroup(groupId: string): Campaign[] {
    return this.domainSubject.value?.campaignsByGroup.get(groupId) ?? [];
  }

  getDetectionNotesForTechnique(techniqueId: string): import('../models/domain').DetectionNote[] {
    return this.domainSubject.value?.detectionNotesByTechnique.get(techniqueId) ?? [];
  }

  getSoftwareForTechnique(techniqueId: string): AttackSoftware[] {
    return this.domainSubject.value?.softwareByTechnique.get(techniqueId) ?? [];
  }

  getTechniquesForSoftware(softwareId: string): Technique[] {
    return this.domainSubject.value?.techniquesBySoftware.get(softwareId) ?? [];
  }

  getCampaignsForTechnique(techniqueId: string): import('../models/campaign').Campaign[] {
    return this.domainSubject.value?.campaignsByTechnique.get(techniqueId) ?? [];
  }

  getTechniquesForCampaign(campaignId: string): Technique[] {
    return this.domainSubject.value?.techniquesByCampaign.get(campaignId) ?? [];
  }

  getProceduresForTechnique(techniqueId: string): import('../models/procedure').ProcedureExample[] {
    return this.domainSubject.value?.proceduresByTechnique.get(techniqueId) ?? [];
  }

  getTechniquesForDataComponent(dataComponentId: string): Technique[] {
    return this.domainSubject.value?.techniquesByDataComponent.get(dataComponentId) ?? [];
  }

  getDataComponentsForTechnique(techniqueId: string): import('../models/datasource').MitreDataComponent[] {
    return this.domainSubject.value?.dataComponentsByTechnique.get(techniqueId) ?? [];
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  /**
   * Fetch and parse the live STIX for `config` (MITRE's master branch, unpinned). Used only
   * by the update check: the result is compared and offered, never put on screen directly.
   * The live source records its own outcome in the SourceRegistry.
   */
  private fetchLive(config: typeof DOMAIN_CONFIG[AttackDomain]): Observable<Domain> {
    return defer(() => {
      this.sources.begin(config.liveSourceId);
      return this.http.get<any>(config.liveUrl);
    }).pipe(
      retryWithBackoff(),
      switchMap((bundle) => from(this.saveToIDB(bundle, config.idbKey).then(() => this.parseBundle(bundle, config.name)))),
      tap((domain) => this.sources.succeed(config.liveSourceId, domain.techniques.length, { version: domain.attackVersion || undefined })),
      catchError((err) => {
        this.sources.fail(config.liveSourceId, err);
        return throwError(() => err);
      }),
    );
  }

  private loadBundled(config: typeof DOMAIN_CONFIG[AttackDomain]): Observable<Domain> {
    if (!config.bundledUrl) {
      return throwError(() => new Error('No bundled fallback available'));
    }
    return defer(() => {
      this.sources.begin(config.sourceId);
      return this.http.get<any>(config.bundledUrl!);
    }).pipe(
      switchMap((bundle) => of(this.parseBundle(bundle, config.name))),
      tap({
        // The version comes from the bundle itself, so the record cannot drift from the file.
        next: (domain) => this.sources.succeed(config.sourceId, domain.techniques.length, { version: domain.attackVersion || undefined }),
        error: (err) => this.sources.fail(config.sourceId, err),
      }),
    );
  }

  // ── IndexedDB helpers ────────────────────────────────────────────────────────

  private openIDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async loadFromIDB(key: string): Promise<Domain | null> {
    try {
      const db = await this.openIDB();
      const entry: { bundle: any; ts: number } | undefined = await new Promise((res, rej) => {
        const tx = db.transaction(IDB_STORE, 'readonly');
        const req = tx.objectStore(IDB_STORE).get(key);
        req.onsuccess = () => res(req.result);
        req.onerror = () => rej(req.error);
      });
      if (!entry) return null;
      if (Date.now() - entry.ts > CACHE_TTL_MS) return null;
      const config = DOMAIN_CONFIG[this.attackDomain];
      return this.parseBundle(entry.bundle, config.name);
    } catch {
      return null;
    }
  }

  private async saveToIDB(bundle: any, key: string): Promise<void> {
    try {
      const db = await this.openIDB();
      await new Promise<void>((res, rej) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        const req = tx.objectStore(IDB_STORE).put({ bundle, ts: Date.now() }, key);
        req.onsuccess = () => res();
        req.onerror = () => rej(req.error);
      });
    } catch {
      // quota exceeded or unavailable — silently ignore
    }
  }

  // ── STIX parsing ─────────────────────────────────────────────────────────────

  private parseBundle(bundle: any, domainName: string = 'Enterprise ATT&CK'): Domain {
    const tacticsMap = new Map<string, Tactic>();        // STIX id → Tactic
    const techniquesMap = new Map<string, Technique>();  // STIX id → Technique
    const mitigationsMap = new Map<string, Mitigation>(); // STIX id → Mitigation
    const softwareMap = new Map<string, AttackSoftware>(); // STIX id → Software
    const dataSourcesMap = new Map<string, MitreDataSource>(); // STIX id → DataSource
    const dataComponentsMap = new Map<string, MitreDataComponent>(); // STIX id → DataComponent
    const campaignsMap = new Map<string, Campaign>(); // STIX id → Campaign
    // v18 detection model
    const analyticsMap = new Map<string, string[]>(); // analyticId → dataComponentRefs[]
    const detStrategyAnalyticRefs = new Map<string, string[]>(); // detStratId → analyticIds[]
    let matrixObj: any = null;
    let attackVersion = '';
    let attackModified = '';
    const mitigatesRels: Array<{ sourceRef: string; targetRef: string; description: string }> = [];
    const groupsMap = new Map<string, ThreatGroup>();
    const usesRels: Array<{ groupRef: string; techniqueRef: string; description: string }> = [];
    const softwareUsesRels: Array<{ softwareRef: string; techniqueRef: string; description: string }> = [];
    const campaignUsesRels: Array<{ campaignRef: string; techniqueRef: string; description: string }> = [];
    // group/campaign → software toolkit relationships ("uses" with a tool/malware target)
    const groupSoftwareRels: Array<{ groupRef: string; softwareRef: string }> = [];
    const campaignSoftwareRels: Array<{ campaignRef: string; softwareRef: string }> = [];
    // detects: detection-strategy → technique (v18) or data-component → technique (legacy)
    const detectsRels: Array<{ sourceRef: string; techniqueRef: string; description: string }> = [];
    // revoked-by: retired technique → its replacement (ATT&CK restructures)
    const revokedByRels: Array<{ sourceRef: string; targetRef: string }> = [];
    const retiredStixToAttackId = new Map<string, string>();
    const retiredNames = new Map<string, string>();

    for (const obj of bundle.objects ?? []) {
      // x-mitre-collection is never revoked — parse it before the revoked check
      if (obj.type === 'x-mitre-collection') {
        attackVersion = obj.x_mitre_version ?? '';
        attackModified = obj.modified ?? '';
        continue;
      }

      // Revoked techniques are excluded from the matrix, but their ids still appear in
      // mapping data built against an earlier ATT&CK release. Keep just enough to
      // translate those ids forward before dropping the object.
      if (obj.revoked && obj.type === 'attack-pattern') {
        const retiredId = this.extractAttackId(obj);
        if (retiredId) {
          retiredStixToAttackId.set(obj.id, retiredId);
          retiredNames.set(retiredId, obj.name ?? '');
        }
      }

      if (obj.revoked || obj.x_mitre_deprecated) {
        // `revoked-by` edges are not themselves revoked, so they survive this filter;
        // only the revoked technique objects above need rescuing here.
        continue;
      }

      switch (obj.type) {
        case 'x-mitre-matrix':
          matrixObj = obj;
          break;

        case 'intrusion-set': {
          const attackId = this.extractAttackId(obj);
          if (!attackId) break;
          groupsMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
            aliases: obj.aliases ?? [],
          });
          break;
        }

        case 'x-mitre-tactic': {
          const attackId = this.extractAttackId(obj);
          if (!attackId) break;
          tacticsMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            shortname: obj.x_mitre_shortname ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
            order: 0,
          });
          break;
        }

        case 'attack-pattern': {
          const attackId = this.extractAttackId(obj);
          if (!attackId) break;
          techniquesMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
            tacticShortnames: (obj.kill_chain_phases ?? []).map((p: any) => p.phase_name),
            isSubtechnique: obj.x_mitre_is_subtechnique ?? false,
            parentId: null,
            subtechniques: [],
            mitigationCount: 0,
            platforms: obj.x_mitre_platforms ?? [],
            dataSources: obj.x_mitre_data_sources ?? [],
            detectionText: obj.x_mitre_detection ?? '',
            defenseBypassed: obj.x_mitre_defense_bypassed ?? [],
            permissionsRequired: obj.x_mitre_permissions_required ?? [],
            effectivePermissions: obj.x_mitre_effective_permissions ?? [],
            systemRequirements: obj.x_mitre_system_requirements ?? [],
            impactType: obj.x_mitre_impact_type ?? [],
            remoteSupport: obj.x_mitre_remote_support ?? false,
            capecIds: (obj.external_references ?? [])
              .filter((r: any) => r.source_name === 'capec')
              .map((r: any) => r.external_id as string),
          });
          break;
        }

        case 'x-mitre-data-source': {
          dataSourcesMap.set(obj.id, {
            id: obj.id,
            name: obj.name ?? '',
            description: obj.description ?? '',
            collectionLayers: obj.x_mitre_collection_layers ?? [],
          });
          break;
        }

        case 'x-mitre-data-component': {
          // v18+: data source name comes from x_mitre_log_sources[0].name
          // older: x_mitre_data_source_ref (now deprecated/empty)
          const logSources: Array<{ name: string; channel?: string }> = obj.x_mitre_log_sources ?? [];
          const dataSourceName = logSources.length > 0 ? logSources[0].name : '';
          dataComponentsMap.set(obj.id, {
            id: obj.id,
            name: obj.name ?? '',
            dataSourceRef: obj.x_mitre_data_source_ref ?? '',
            dataSourceName,
          });
          break;
        }

        case 'campaign': {
          const attackId = this.extractAttackId(obj);
          if (!attackId) break;
          campaignsMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
            aliases: obj.aliases ?? [],
            firstSeen: obj.first_seen ?? '',
            lastSeen: obj.last_seen ?? '',
            attributedGroupIds: [],
          });
          break;
        }

        case 'x-mitre-analytic': {
          const dcRefs = (obj.x_mitre_log_source_references ?? [])
            .map((lsr: any) => lsr.x_mitre_data_component_ref)
            .filter(Boolean);
          analyticsMap.set(obj.id, dcRefs);
          break;
        }

        case 'x-mitre-detection-strategy': {
          detStrategyAnalyticRefs.set(obj.id, obj.x_mitre_analytic_refs ?? []);
          break;
        }

        case 'tool':
        case 'malware': {
          const attackId = this.extractAttackId(obj);
          if (!attackId) break;
          softwareMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
            type: obj.type === 'malware' ? 'malware' : 'tool',
            platforms: obj.x_mitre_platforms ?? [],
            aliases: obj.x_mitre_aliases ?? obj.aliases ?? [],
          });
          break;
        }

        case 'course-of-action': {
          const attackId = this.extractAttackId(obj);
          if (!attackId?.startsWith('M')) break;
          mitigationsMap.set(obj.id, {
            id: obj.id,
            attackId,
            name: obj.name ?? '',
            description: obj.description ?? '',
            url: this.extractUrl(obj),
          });
          break;
        }

        case 'relationship':
          if (obj.relationship_type === 'revoked-by') {
            revokedByRels.push({ sourceRef: obj.source_ref, targetRef: obj.target_ref });
          } else if (obj.relationship_type === 'mitigates') {
            mitigatesRels.push({
              sourceRef: obj.source_ref,
              targetRef: obj.target_ref,
              description: obj.description ?? '',
            });
          } else if (obj.relationship_type === 'uses' && obj.target_ref?.startsWith('attack-pattern--')) {
            if (obj.source_ref?.startsWith('intrusion-set--')) {
              usesRels.push({ groupRef: obj.source_ref, techniqueRef: obj.target_ref, description: obj.description ?? '' });
            } else if (
              obj.source_ref?.startsWith('tool--') ||
              obj.source_ref?.startsWith('malware--')
            ) {
              softwareUsesRels.push({ softwareRef: obj.source_ref, techniqueRef: obj.target_ref, description: obj.description ?? '' });
            } else if (obj.source_ref?.startsWith('campaign--')) {
              campaignUsesRels.push({ campaignRef: obj.source_ref, techniqueRef: obj.target_ref, description: obj.description ?? '' });
            }
          } else if (
            obj.relationship_type === 'uses' &&
            (obj.target_ref?.startsWith('tool--') || obj.target_ref?.startsWith('malware--'))
          ) {
            // Toolkit relationships: which software a group/campaign employs
            if (obj.source_ref?.startsWith('intrusion-set--')) {
              groupSoftwareRels.push({ groupRef: obj.source_ref, softwareRef: obj.target_ref });
            } else if (obj.source_ref?.startsWith('campaign--')) {
              campaignSoftwareRels.push({ campaignRef: obj.source_ref, softwareRef: obj.target_ref });
            }
          } else if (
            obj.relationship_type === 'detects' &&
            (obj.source_ref?.startsWith('x-mitre-detection-strategy--') ||
             obj.source_ref?.startsWith('x-mitre-data-component--')) &&
            obj.target_ref?.startsWith('attack-pattern--')
          ) {
            detectsRels.push({ sourceRef: obj.source_ref, techniqueRef: obj.target_ref, description: obj.description ?? '' });
          } else if (
            obj.relationship_type === 'attributed-to' &&
            obj.source_ref?.startsWith('campaign--') &&
            obj.target_ref?.startsWith('intrusion-set--')
          ) {
            const campaign = campaignsMap.get(obj.source_ref);
            if (campaign) campaign.attributedGroupIds.push(obj.target_ref);
          }
          break;
      }
    }

    // ── Assign tactic ordering from matrix ───────────────────────────────────
    const tacticRefs: string[] = matrixObj?.tactic_refs ?? [];
    tacticRefs.forEach((ref, i) => {
      const tactic = tacticsMap.get(ref);
      if (tactic) tactic.order = i;
    });
    const tactics = [...tacticsMap.values()].sort((a, b) => a.order - b.order);

    // ── Link subtechniques to parents ────────────────────────────────────────
    for (const tech of techniquesMap.values()) {
      if (tech.isSubtechnique) {
        // T1055.011 → parent attackId is T1055
        const parentAttackId = tech.attackId.split('.')[0];
        const parent = [...techniquesMap.values()].find((t) => t.attackId === parentAttackId);
        if (parent) {
          tech.parentId = parent.id;
          parent.subtechniques.push(tech);
        }
      }
    }
    // Sort subtechniques by attackId
    for (const tech of techniquesMap.values()) {
      tech.subtechniques.sort((a, b) => a.attackId.localeCompare(b.attackId));
    }

    // ── Build mitigation indexes ─────────────────────────────────────────────
    const mitigationsByTechnique = new Map<string, MitigationRelationship[]>();
    const techniquesByMitigation = new Map<string, Technique[]>();

    for (const rel of mitigatesRels) {
      const mitigation = mitigationsMap.get(rel.sourceRef);
      const technique = techniquesMap.get(rel.targetRef);
      if (!mitigation || !technique) continue;

      // mitigationsByTechnique
      if (!mitigationsByTechnique.has(technique.id)) {
        mitigationsByTechnique.set(technique.id, []);
      }
      mitigationsByTechnique.get(technique.id)!.push({ mitigation, description: rel.description });

      // techniquesByMitigation
      if (!techniquesByMitigation.has(mitigation.id)) {
        techniquesByMitigation.set(mitigation.id, []);
      }
      techniquesByMitigation.get(mitigation.id)!.push(technique);
    }

    // ── Compute mitigationCount per technique ────────────────────────────────
    let maxMitigationCount = 0;
    for (const tech of techniquesMap.values()) {
      tech.mitigationCount = mitigationsByTechnique.get(tech.id)?.length ?? 0;
      if (tech.mitigationCount > maxMitigationCount) maxMitigationCount = tech.mitigationCount;
    }

    // ── Build tactic columns (parent techniques only) ────────────────────────
    const shortnameLookup = new Map<string, Tactic>();
    for (const t of tactics) shortnameLookup.set(t.shortname, t);

    const tacticColumns: TacticColumn[] = tactics.map((tactic) => ({
      tactic,
      techniques: [...techniquesMap.values()]
        .filter((t) => !t.isSubtechnique && t.tacticShortnames.includes(tactic.shortname))
        .sort((a, b) => a.attackId.localeCompare(b.attackId)),
    }));

    // ── Build threat group indexes ────────────────────────────────────────────
    const groupsByTechnique = new Map<string, ThreatGroup[]>();
    const techniquesByGroup = new Map<string, Technique[]>();

    for (const rel of usesRels) {
      const group = groupsMap.get(rel.groupRef);
      const technique = techniquesMap.get(rel.techniqueRef);
      if (!group || !technique) continue;

      if (!groupsByTechnique.has(technique.id)) groupsByTechnique.set(technique.id, []);
      groupsByTechnique.get(technique.id)!.push(group);

      if (!techniquesByGroup.has(group.id)) techniquesByGroup.set(group.id, []);
      techniquesByGroup.get(group.id)!.push(technique);
    }

    // ── Build software indexes + procedure examples ───────────────────────────
    const softwareByTechnique = new Map<string, AttackSoftware[]>();
    const techniquesBySoftware = new Map<string, Technique[]>();
    const proceduresByTechnique = new Map<string, ProcedureExample[]>();

    for (const rel of usesRels) {
      const group = groupsMap.get(rel.groupRef);
      const technique = techniquesMap.get(rel.techniqueRef);
      if (!group || !technique || !rel.description) continue;
      if (!proceduresByTechnique.has(technique.id)) proceduresByTechnique.set(technique.id, []);
      proceduresByTechnique.get(technique.id)!.push({
        sourceId: group.id,
        sourceName: group.name,
        attackId: group.attackId,
        sourceType: 'group',
        description: rel.description,
      });
    }

    for (const rel of softwareUsesRels) {
      const sw = softwareMap.get(rel.softwareRef);
      const technique = techniquesMap.get(rel.techniqueRef);
      if (!sw || !technique) continue;

      if (!softwareByTechnique.has(technique.id)) softwareByTechnique.set(technique.id, []);
      softwareByTechnique.get(technique.id)!.push(sw);

      if (!techniquesBySoftware.has(sw.id)) techniquesBySoftware.set(sw.id, []);
      techniquesBySoftware.get(sw.id)!.push(technique);

      if (rel.description) {
        if (!proceduresByTechnique.has(technique.id)) proceduresByTechnique.set(technique.id, []);
        proceduresByTechnique.get(technique.id)!.push({
          sourceId: sw.id,
          sourceName: sw.name,
          attackId: sw.attackId,
          sourceType: sw.type,
          description: rel.description,
        });
      }
    }

    // ── Resolve data component source names (legacy fallback) ────────────────
    for (const dc of dataComponentsMap.values()) {
      const ds = dataSourcesMap.get(dc.dataSourceRef);
      if (ds) dc.dataSourceName = ds.name;
    }

    const techniquesByDataComponent = new Map<string, Technique[]>();
    const dataComponentsByTechnique = new Map<string, MitreDataComponent[]>();

    const detectionNotesByTechnique = new Map<string, DetectionNote[]>();

    for (const rel of detectsRels) {
      const technique = techniquesMap.get(rel.techniqueRef);
      if (!technique) continue;

      // Resolve which data component(s) this detection relationship maps to
      let dcIds: string[] = [];
      if (rel.sourceRef.startsWith('x-mitre-data-component--')) {
        // Legacy (v17 and earlier): direct data-component → technique
        dcIds = [rel.sourceRef];
      } else if (rel.sourceRef.startsWith('x-mitre-detection-strategy--')) {
        // v18+: detection-strategy → analytics → data-component refs
        const analyticIds = detStrategyAnalyticRefs.get(rel.sourceRef) ?? [];
        for (const analyticId of analyticIds) {
          dcIds.push(...(analyticsMap.get(analyticId) ?? []));
        }
      }

      const dcNames: string[] = [];
      for (const dcId of dcIds) {
        const dc = dataComponentsMap.get(dcId);
        if (!dc) continue;
        dcNames.push(dc.name);

        if (!techniquesByDataComponent.has(dc.id)) techniquesByDataComponent.set(dc.id, []);
        techniquesByDataComponent.get(dc.id)!.push(technique);

        if (!dataComponentsByTechnique.has(technique.id)) dataComponentsByTechnique.set(technique.id, []);
        dataComponentsByTechnique.get(technique.id)!.push(dc);
      }

      // Preserve the relationship's detection guidance (dropped previously)
      if (rel.description) {
        if (!detectionNotesByTechnique.has(technique.id)) detectionNotesByTechnique.set(technique.id, []);
        detectionNotesByTechnique.get(technique.id)!.push({
          dataComponentName: dcNames.join(', ') || 'Detection strategy',
          description: rel.description,
        });
      }
    }

    // ── Build campaign indexes ─────────────────────────────────────────────────
    const campaignsByTechnique = new Map<string, Campaign[]>();
    const techniquesByCampaign = new Map<string, Technique[]>();

    for (const rel of campaignUsesRels) {
      const campaign = campaignsMap.get(rel.campaignRef);
      const technique = techniquesMap.get(rel.techniqueRef);
      if (!campaign || !technique) continue;

      if (!campaignsByTechnique.has(technique.id)) campaignsByTechnique.set(technique.id, []);
      campaignsByTechnique.get(technique.id)!.push(campaign);

      if (!techniquesByCampaign.has(campaign.id)) techniquesByCampaign.set(campaign.id, []);
      techniquesByCampaign.get(campaign.id)!.push(technique);

      // Campaign procedure examples (descriptions were dropped previously)
      if (rel.description) {
        if (!proceduresByTechnique.has(technique.id)) proceduresByTechnique.set(technique.id, []);
        proceduresByTechnique.get(technique.id)!.push({
          sourceId: campaign.id,
          sourceName: campaign.name,
          attackId: campaign.attackId,
          sourceType: 'campaign',
          description: rel.description,
        });
      }
    }

    // ── Build toolkit indexes (group/campaign → software) ────────────────────
    const softwareByGroup = new Map<string, AttackSoftware[]>();
    const groupsBySoftware = new Map<string, ThreatGroup[]>();
    const softwareByCampaign = new Map<string, AttackSoftware[]>();

    for (const rel of groupSoftwareRels) {
      const group = groupsMap.get(rel.groupRef);
      const sw = softwareMap.get(rel.softwareRef);
      if (!group || !sw) continue;

      if (!softwareByGroup.has(group.id)) softwareByGroup.set(group.id, []);
      softwareByGroup.get(group.id)!.push(sw);

      if (!groupsBySoftware.has(sw.id)) groupsBySoftware.set(sw.id, []);
      groupsBySoftware.get(sw.id)!.push(group);
    }

    for (const rel of campaignSoftwareRels) {
      const campaign = campaignsMap.get(rel.campaignRef);
      const sw = softwareMap.get(rel.softwareRef);
      if (!campaign || !sw) continue;

      if (!softwareByCampaign.has(campaign.id)) softwareByCampaign.set(campaign.id, []);
      softwareByCampaign.get(campaign.id)!.push(sw);
    }

    // ── Campaign attribution reverse index (group → campaigns) ───────────────
    const campaignsByGroup = new Map<string, Campaign[]>();
    for (const campaign of campaignsMap.values()) {
      for (const groupId of campaign.attributedGroupIds) {
        if (!groupsMap.has(groupId)) continue;
        if (!campaignsByGroup.has(groupId)) campaignsByGroup.set(groupId, []);
        campaignsByGroup.get(groupId)!.push(campaign);
      }
    }

    // ── Dedupe + deterministic ordering for every relationship index ─────────
    // STIX bundles can carry multiple `uses` relationships for the same pair
    // (one per reference); insertion order is otherwise bundle-dependent.
    const dedupeSortById = <T extends { id: string; attackId: string }>(map: Map<string, T[]>): void => {
      for (const [key, items] of map) {
        const unique = [...new Map(items.map((item) => [item.id, item])).values()];
        unique.sort((a, b) => a.attackId.localeCompare(b.attackId));
        map.set(key, unique);
      }
    };
    dedupeSortById(groupsByTechnique);
    dedupeSortById(techniquesByGroup);
    dedupeSortById(softwareByTechnique);
    dedupeSortById(techniquesBySoftware);
    dedupeSortById(campaignsByTechnique);
    dedupeSortById(techniquesByCampaign);
    dedupeSortById(techniquesByMitigation);
    dedupeSortById(techniquesByDataComponent);
    dedupeSortById(softwareByGroup);
    dedupeSortById(groupsBySoftware);
    dedupeSortById(softwareByCampaign);
    dedupeSortById(campaignsByGroup);
    // Data components have no attackId — dedupe by id, order by name
    for (const [key, items] of dataComponentsByTechnique) {
      const unique = [...new Map(items.map((dc) => [dc.id, dc])).values()];
      unique.sort((a, b) => a.name.localeCompare(b.name));
      dataComponentsByTechnique.set(key, unique);
    }

    // ── Resolve retired technique ids to their replacements ──────────────────
    // A revocation can chain across releases (A revoked by B, B later revoked by C),
    // so each id is followed to the end of the chain rather than one hop.
    const directSuccessor = new Map<string, string>();
    for (const rel of revokedByRels) {
      const from = retiredStixToAttackId.get(rel.sourceRef);
      if (!from) continue;
      const toLive = techniquesMap.get(rel.targetRef)?.attackId;
      const to = toLive ?? retiredStixToAttackId.get(rel.targetRef);
      if (to && to !== from) directSuccessor.set(from, to);
    }

    const liveAttackIds = new Set([...techniquesMap.values()].map((t) => t.attackId));
    const supersededBy = new Map<string, string>();
    for (const from of directSuccessor.keys()) {
      const seen = new Set<string>([from]);
      let cursor = from;
      let next = directSuccessor.get(cursor);
      while (next && !seen.has(next) && !liveAttackIds.has(next)) {
        seen.add(next);
        cursor = next;
        next = directSuccessor.get(cursor);
      }
      // Only record a replacement that actually exists in this release.
      if (next && liveAttackIds.has(next)) supersededBy.set(from, next);
    }

    const techniques = [...techniquesMap.values()];
    const mitigations = [...mitigationsMap.values()].sort((a, b) =>
      a.attackId.localeCompare(b.attackId),
    );
    const groups = [...groupsMap.values()].sort((a, b) => a.attackId.localeCompare(b.attackId));
    const software = [...softwareMap.values()].sort((a, b) => a.attackId.localeCompare(b.attackId));
    const dataSources = [...dataSourcesMap.values()].sort((a, b) => a.name.localeCompare(b.name));
    const dataComponents = [...dataComponentsMap.values()].sort((a, b) => a.name.localeCompare(b.name));
    const campaigns = [...campaignsMap.values()].sort((a, b) => a.attackId.localeCompare(b.attackId));

    return {
      name: domainName,
      attackVersion,
      attackModified,
      tactics,
      techniques,
      mitigations,
      tacticColumns,
      mitigationsByTechnique,
      techniquesByMitigation,
      maxMitigationCount,
      groups,
      groupsByTechnique,
      techniquesByGroup,
      software,
      softwareByTechnique,
      techniquesBySoftware,
      proceduresByTechnique,
      dataSources,
      dataComponents,
      techniquesByDataComponent,
      dataComponentsByTechnique,
      campaigns,
      campaignsByTechnique,
      techniquesByCampaign,
      softwareByGroup,
      groupsBySoftware,
      softwareByCampaign,
      campaignsByGroup,
      detectionNotesByTechnique,
      supersededBy,
      retiredNames,
    };
  }

  private extractAttackId(obj: any): string | null {
    for (const ref of obj.external_references ?? []) {
      // 'mitre-' family: mitre-attack (Enterprise/ICS/Mobile) and mitre-f3
      // (CTID Fraud Framework) both follow the ATT&CK STIX ref convention.
      if (ref.source_name?.startsWith('mitre-') && ref.external_id) {
        return ref.external_id;
      }
    }
    return null;
  }

  /**
   * The object's own ATT&CK / F3 page URL from its `mitre-*` external
   * reference, accepted only when it is an http(s) URL. Anything else (a
   * `javascript:` or `data:` scheme in a tampered bundle, a relative path,
   * a missing url) falls back to the canonical page built from the ATT&CK id,
   * so the URL that reaches `[href]` bindings and the generated HTML report
   * is never an executable scheme.
   */
  private extractUrl(obj: any): string {
    let fallback = '';
    for (const ref of obj.external_references ?? []) {
      if (!ref.source_name?.startsWith('mitre-')) continue;
      if (typeof ref.url === 'string' && DataService.isHttpUrl(ref.url)) {
        return ref.url;
      }
      if (!fallback) fallback = DataService.canonicalUrl(ref.source_name, obj.type, ref.external_id);
    }
    return fallback;
  }

  private static isHttpUrl(url: string): boolean {
    try {
      const protocol = new URL(url).protocol;
      return protocol === 'https:' || protocol === 'http:';
    } catch {
      return false;
    }
  }

  /**
   * Canonical public page for a STIX object, keyed on its source and type:
   * attack.mitre.org for `mitre-attack` (and the legacy `mitre-ics-attack` /
   * `mitre-mobile-attack` names still carried by some deprecated objects),
   * ctid.mitre.org/fraud for `mitre-f3`. Same URL shapes as the bundled data.
   * Returns '' when the id is missing or the type has no public page.
   */
  private static canonicalUrl(sourceName: string, stixType: string, attackId: unknown): string {
    if (typeof attackId !== 'string' || !/^[A-Z]+\d+(\.\d+)?$/.test(attackId)) return '';
    if (sourceName === 'mitre-f3') {
      if (stixType === 'attack-pattern') return `https://ctid.mitre.org/fraud/techniques/${attackId}`;
      if (stixType === 'x-mitre-tactic') return `https://ctid.mitre.org/fraud/tactics/${attackId}`;
      return '';
    }
    if (sourceName !== 'mitre-attack' && sourceName !== 'mitre-ics-attack' && sourceName !== 'mitre-mobile-attack') return '';
    switch (stixType) {
      case 'attack-pattern': return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}`;
      case 'x-mitre-tactic': return `https://attack.mitre.org/tactics/${attackId}`;
      case 'course-of-action': return `https://attack.mitre.org/mitigations/${attackId}`;
      case 'intrusion-set': return `https://attack.mitre.org/groups/${attackId}`;
      case 'tool':
      case 'malware': return `https://attack.mitre.org/software/${attackId}`;
      case 'campaign': return `https://attack.mitre.org/campaigns/${attackId}`;
      default: return '';
    }
  }
}

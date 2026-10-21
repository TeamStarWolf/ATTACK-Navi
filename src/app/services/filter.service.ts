// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject, combineLatest, map, debounceTime, filter, take } from 'rxjs';
import { Technique } from '../models/technique';
import { Mitigation } from '../models/mitigation';
import { Domain } from '../models/domain';
import { AttackDomain, DataService } from './data.service';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { sameDataSource } from '../utils/data-source-names';

export type SortMode = 'alpha' | 'coverage';
export type HeatmapMode = 'coverage' | 'exposure' | 'status' | 'controls' | 'software' | 'campaign' | 'risk' | 'kev' | 'd3fend' | 'atomic' | 'engage' | 'car' | 'cve' | 'detection' | 'frequency' | 'cri' | 'unified' | 'library' | 'sigma' | 'nist' | 'veris' | 'epss' | 'elastic' | 'splunk' | 'intelligence' | 'm365' | 'my-exposure' | 'wazuh' | 'csa-ccm' | 'm365-controls' | 'kill-chain' | 'poc-exploits' | 'f3-origin' | 'posture' | 'proven' | 'covered';

/**
 * The lens a fresh profile opens on (plan E1.5, decision D4): Prevalence, the
 * Threat lens 'frequency' (how many ATT&CK groups use each technique). It is
 * true for every visitor and claims nothing about their environment, unlike
 * 'unified' (Reference depth), which painted a profile with no owner data as
 * strong. Shown with a one-line banner until owner data exists (OwnerDataService).
 * A link without heat= opens this lens.
 */
export const DEFAULT_HEATMAP_MODE: HeatmapMode = 'frequency';
export type SearchScope = 'name' | 'full';
export const SEARCH_SCOPES: readonly SearchScope[] = ['name', 'full'];
/** Mitigation implementation statuses the `impl` filter (and URL param) may take. */
export const IMPL_STATUSES = ['implemented', 'in-progress', 'planned', 'not-started'] as const;
export type ImplStatus = (typeof IMPL_STATUSES)[number];

export function isHeatmapMode(value: string | null | undefined): value is HeatmapMode {
  return !!value && HEATMAP_MODES.some(m => m.value === value);
}
export function isSearchScope(value: string | null | undefined): value is SearchScope {
  return !!value && (SEARCH_SCOPES as readonly string[]).includes(value);
}
export function isImplStatus(value: string | null | undefined): value is ImplStatus {
  return !!value && (IMPL_STATUSES as readonly string[]).includes(value);
}

/**
 * The name DataService gives each loaded Domain (Domain.name), per ATT&CK domain.
 * applyUrlState waits for the domain with this name, and the not-in-domain toast
 * names the domain with it.
 */
const ATTACK_DOMAIN_NAMES: Record<AttackDomain, string> = {
  enterprise: 'Enterprise ATT&CK',
  ics: 'ICS ATT&CK',
  mobile: 'Mobile ATT&CK',
  f3: 'F3 Fraud Framework',
};

/** Validates the `dom` URL param (#118's pattern: an unknown value is ignored). */
export function isAttackDomain(value: string | null | undefined): value is AttackDomain {
  return !!value && Object.prototype.hasOwnProperty.call(ATTACK_DOMAIN_NAMES, value);
}

/**
 * The ids a `tech` URL param may carry (#118's pattern: anything else is ignored):
 * ATT&CK Enterprise/ICS/Mobile techniques and sub-techniques (T1059, T1059.001,
 * T0807), F3 ids (F1001) and ATLAS ids (AML.T0051, AML.T0051.000). Case-insensitive;
 * applyUrlState trims first and rejects anything longer than URL_TECH_ID_MAX_LENGTH.
 */
export const URL_TECH_ID_PATTERN = /^(?:T\d{4}|F\d{4}|AML\.T\d{4})(?:\.\d{3})?$/i;
export const URL_TECH_ID_MAX_LENGTH = 16;

/**
 * Validates and normalises the raw `tech` URL param: the trimmed, upper-cased id
 * when it matches URL_TECH_ID_PATTERN, else null. A null is ignored silently, so a
 * crafted link can never put its own text in front of the user.
 */
export function normalizeUrlTechId(value: string | null | undefined): string | null {
  if (!value) return null;
  const id = value.trim();
  if (!id || id.length > URL_TECH_ID_MAX_LENGTH || !URL_TECH_ID_PATTERN.test(id)) return null;
  return id.toUpperCase();
}

/**
 * The domain a technique id belongs to when its id convention says so without
 * loading another bundle: ICS ids are T08xx, F3's own ids are Fxxxx. Any other id
 * is ambiguous (Enterprise, Mobile and v19 ICS share the T1xxx range), so null.
 */
export function domainHintForAttackId(attackId: string): AttackDomain | null {
  if (/^T08\d\d(\.\d{3})?$/.test(attackId)) return 'ics';
  if (/^F\d{4}(\.\d{3})?$/.test(attackId)) return 'f3';
  return null;
}

/** The toast a `tech` link raises when its id is not in the loaded domain. Takes the normalised id (normalizeUrlTechId), never the raw param. */
export function techNotInDomainMessage(attackId: string, domain: AttackDomain): string {
  const where = `${attackId} is not in ${ATTACK_DOMAIN_NAMES[domain]}.`;
  const hint = domainHintForAttackId(attackId);
  return hint && hint !== domain
    ? `${where} Add dom=${hint} to the link or switch domain.`
    : `${where} Check the id or switch domain.`;
}

export interface FilterStateSnapshot {
  heatmapMode: HeatmapMode;
  activeThreatGroupIds: string[];
  activeSoftwareIds: string[];
  activeCampaignIds: string[];
  activeMitigationFilterIds: string[];
  whatIfMitigationIds: string[];
  platformFilter: string | null;
  sortMode: SortMode;
  dimUncovered: boolean;
  searchFilterMode: boolean;
  hiddenTacticIds: string[];
}

@Injectable({ providedIn: 'root' })
export class FilterService {
  private selectedTechniqueSubject = new BehaviorSubject<Technique | null>(null);
  private activeMitigationFiltersSubject = new BehaviorSubject<Mitigation[]>([]);
  private techniqueQuerySubject = new BehaviorSubject<string>('');
  private sortModeSubject = new BehaviorSubject<SortMode>('alpha');
  private dimUncoveredSubject = new BehaviorSubject<boolean>(false);
  private platformFilterSubject = new BehaviorSubject<string | null>(null);
  private hiddenTacticIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  private searchScopeSubject = new BehaviorSubject<SearchScope>('name');
  private activeThreatGroupIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  private whatIfMitigationIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  private activeSoftwareIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  private activeCampaignIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  private activeDataSourceSubject = new BehaviorSubject<string | null>(null);
  private heatmapModeSubject = new BehaviorSubject<HeatmapMode>(DEFAULT_HEATMAP_MODE);
  private implStatusFilterSubject = new BehaviorSubject<string | null>(null);
  private searchFilterModeSubject = new BehaviorSubject<boolean>(false);
  searchFilterMode$: Observable<boolean> = this.searchFilterModeSubject.asObservable();
  private cveTechniqueIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  cveTechniqueIds$: Observable<Set<string>> = this.cveTechniqueIdsSubject.asObservable();
  private techniqueSearchSubject = new BehaviorSubject<string>('');
  techniqueSearch$: Observable<string> = this.techniqueSearchSubject.asObservable();
  /**
   * Whether the technique drawer stays open across workspaces (E2.3). Not in the
   * URL. Closing the drawer (selectTechnique(null), Escape, clearAll) unpins it.
   */
  private drawerPinnedSubject = new BehaviorSubject<boolean>(false);
  readonly drawerPinned$: Observable<boolean> = this.drawerPinnedSubject.asObservable();
  /** One-off messages about a shared link (a `tech` id not in the loaded domain); AppComponent toasts them. */
  private urlNoticeSubject = new Subject<string>();
  readonly urlNotice$: Observable<string> = this.urlNoticeSubject.asObservable();
  /**
   * A `tech` id read from the URL that waits for its domain to load. It is
   * serialized meanwhile, so the first writer pass keeps it in the address bar.
   */
  private pendingUrlTechId: string | null = null;

  selectedTechnique$: Observable<Technique | null> = this.selectedTechniqueSubject.asObservable();
  activeMitigationFilters$: Observable<Mitigation[]> = this.activeMitigationFiltersSubject.asObservable();
  techniqueQuery$: Observable<string> = this.techniqueQuerySubject.asObservable();
  sortMode$: Observable<SortMode> = this.sortModeSubject.asObservable();
  dimUncovered$: Observable<boolean> = this.dimUncoveredSubject.asObservable();
  platformFilter$: Observable<string | null> = this.platformFilterSubject.asObservable();
  hiddenTacticIds$: Observable<Set<string>> = this.hiddenTacticIdsSubject.asObservable();
  searchScope$: Observable<SearchScope> = this.searchScopeSubject.asObservable();
  activeThreatGroupIds$: Observable<Set<string>> = this.activeThreatGroupIdsSubject.asObservable();
  whatIfMitigationIds$: Observable<Set<string>> = this.whatIfMitigationIdsSubject.asObservable();
  activeSoftwareIds$: Observable<Set<string>> = this.activeSoftwareIdsSubject.asObservable();
  activeCampaignIds$: Observable<Set<string>> = this.activeCampaignIdsSubject.asObservable();
  activeDataSource$: Observable<string | null> = this.activeDataSourceSubject.asObservable();
  heatmapMode$: Observable<HeatmapMode> = this.heatmapModeSubject.asObservable();
  implStatusFilter$: Observable<string | null> = this.implStatusFilterSubject.asObservable();

  highlightedTechniqueIds$: Observable<Set<string>>;
  matchedTechniqueIds$: Observable<Set<string>>;
  platformFilteredIds$: Observable<Set<string> | null>;
  threatGroupTechniqueIds$: Observable<Set<string>>;
  softwareTechniqueIds$: Observable<Set<string>>;
  campaignTechniqueIds$: Observable<Set<string>>;
  dataSourceFilteredIds$: Observable<Set<string> | null>;

  private platformMultiSubject = new BehaviorSubject<Set<string>>(new Set());
  platformMulti$: Observable<Set<string>> = this.platformMultiSubject.asObservable();

  /** Debounced signal that URL-relevant state changed (consumed by UrlStateService). */
  urlRelevantState$!: Observable<void>;
  private domainSnapshot: Domain | null = null;

  constructor(
    private dataService: DataService,
    // DI supplies the root resolver (DataService keeps it on the loaded domain);
    // the default only serves callers that construct the service directly.
    private attackIdResolver: AttackIdResolverService = new AttackIdResolverService(),
  ) {
    this.highlightedTechniqueIds$ = combineLatest([
      this.activeMitigationFiltersSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([mitigations, domain]) => {
        if (!mitigations.length || !domain) return new Set<string>();
        const ids = new Set<string>();
        for (const m of mitigations) {
          const techniques = domain.techniquesByMitigation.get(m.id) ?? [];
          for (const t of techniques) ids.add(t.id);
        }
        return ids;
      }),
    );

    this.matchedTechniqueIds$ = combineLatest([
      this.techniqueQuerySubject,
      this.searchScopeSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([query, scope, domain]) => {
        const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
        if (!terms.length || !domain) return new Set<string>();
        return new Set(
          domain.techniques
            .filter((t) => {
              const haystack = scope === 'full'
                ? `${t.attackId} ${t.name} ${(t as any).description ?? ''}`.toLowerCase()
                : `${t.attackId} ${t.name}`.toLowerCase();
              return terms.every((term) => haystack.includes(term));
            })
            .map((t) => t.id),
        );
      }),
    );

    this.platformFilteredIds$ = combineLatest([
      this.platformFilterSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([platform, domain]) => {
        if (!platform || !domain) return null;
        return new Set(
          domain.techniques
            .filter((t) => t.platforms.some((p) => p.toLowerCase() === platform.toLowerCase()))
            .map((t) => t.id),
        );
      }),
    );

    this.threatGroupTechniqueIds$ = combineLatest([
      this.activeThreatGroupIdsSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([groupIds, domain]) => {
        if (!groupIds.size || !domain) return new Set<string>();
        const ids = new Set<string>();
        for (const gid of groupIds) {
          const techniques = domain.techniquesByGroup.get(gid) ?? [];
          for (const t of techniques) ids.add(t.id);
        }
        return ids;
      }),
    );

    this.softwareTechniqueIds$ = combineLatest([
      this.activeSoftwareIdsSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([swIds, domain]) => {
        if (!swIds.size || !domain) return new Set<string>();
        const ids = new Set<string>();
        for (const swId of swIds) {
          const techniques = domain.techniquesBySoftware.get(swId) ?? [];
          for (const t of techniques) ids.add(t.id);
        }
        return ids;
      }),
    );

    this.campaignTechniqueIds$ = combineLatest([
      this.activeCampaignIdsSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([campIds, domain]) => {
        if (!campIds.size || !domain) return new Set<string>();
        const ids = new Set<string>();
        for (const campId of campIds) {
          const techniques = domain.techniquesByCampaign.get(campId) ?? [];
          for (const t of techniques) ids.add(t.id);
        }
        return ids;
      }),
    );

    this.dataSourceFilteredIds$ = combineLatest([
      this.activeDataSourceSubject,
      this.dataService.domain$,
    ]).pipe(
      map(([dsName, domain]) => {
        if (!dsName || !domain) return null;
        // Find all data components whose dataSourceName matches, then collect their techniques
        const ids = new Set<string>();
        for (const dc of domain.dataComponents) {
          if (sameDataSource(dc.dataSourceName, dsName)) {
            const techs = domain.techniquesByDataComponent.get(dc.id) ?? [];
            for (const t of techs) ids.add(t.id);
          }
        }
        return ids;
      }),
    );

    this.dataService.domain$.subscribe((d) => (this.domainSnapshot = d));

    // Emits (debounced) whenever any URL-relevant filter state changes.
    // UrlStateService subscribes to this and serializes into router query
    // params — FilterService itself has no Router dependency.
    this.urlRelevantState$ = combineLatest([
      this.activeMitigationFiltersSubject,
      this.techniqueQuerySubject,
      this.platformFilterSubject,
      this.dimUncoveredSubject,
      this.activeDataSourceSubject,
      this.activeThreatGroupIdsSubject,
      this.activeSoftwareIdsSubject,
      this.activeCampaignIdsSubject,
      this.heatmapModeSubject,
      this.implStatusFilterSubject,
      this.searchScopeSubject,
      this.searchFilterModeSubject,
      this.techniqueSearchSubject,
      this.dataService.domain$,
      this.platformMultiSubject,
      this.selectedTechniqueSubject,
    ]).pipe(debounceTime(300), map(() => void 0));
  }

  /** The ATT&CK domain on screen. A DataService stub without currentDomain$ reads as Enterprise. */
  private currentAttackDomain(): AttackDomain {
    return this.dataService.currentDomain$?.value ?? 'enterprise';
  }

  /**
   * Apply shareable state from URL query params (formerly the raw location
   * hash — see UrlStateService and the legacy-hash shim in main.ts).
   */
  applyUrlState(params: URLSearchParams): void {
    try {
      // `dom` first: a link to an ICS technique must load ICS before `tech` is
      // looked up. The switch starts now, before the wait below. There is no
      // clearAll (a fresh boot has nothing to clear), so the rest of the link survives.
      const dom = params.get('dom');
      const current = this.currentAttackDomain();
      const target: AttackDomain = isAttackDomain(dom) ? dom : current;
      if (target !== current) this.dataService.switchDomain(target);

      const tq = params.get('tq') ?? '';
      if (tq) this.techniqueQuerySubject.next(tq);
      const pf = params.get('pf');
      if (pf) this.platformFilterSubject.next(pf);
      const plat = params.get('plat');
      if (plat) this.platformMultiSubject.next(new Set(plat.split(',').filter(Boolean)));
      if (params.get('dim') === '1') this.dimUncoveredSubject.next(true);
      if (params.get('sfm') === '1') this.searchFilterModeSubject.next(true);
      const ds = params.get('ds');
      if (ds) this.activeDataSourceSubject.next(ds);
      // A share link can carry a mistyped or retired value. An unknown mode would
      // paint every cell the default colour under the wrong legend and never fire the
      // mode's loaders, so each enumerated param is validated and otherwise ignored;
      // the next URL write then serializes only the valid state.
      const heat = params.get('heat');
      if (isHeatmapMode(heat)) this.heatmapModeSubject.next(heat);
      const impl = params.get('impl');
      if (isImplStatus(impl)) this.implStatusFilterSubject.next(impl);
      const scope = params.get('scope');
      if (isSearchScope(scope)) this.searchScopeSubject.next(scope);
      const tsearch = params.get('tsearch') ?? '';
      if (tsearch) this.techniqueSearchSubject.next(tsearch);

      const mitIds = (params.get('mit') ?? '').split(',').filter(Boolean);
      const grpIds = (params.get('grp') ?? '').split(',').filter(Boolean);
      const swAttackIds = (params.get('sw') ?? '').split(',').filter(Boolean);
      const campAttackIds = (params.get('camp') ?? '').split(',').filter(Boolean);

      // Validated before any use: an id outside URL_TECH_ID_PATTERN is ignored
      // silently (no selection, no toast), and only the normalised id is ever
      // echoed, so a crafted link cannot put arbitrary text in the notice.
      const techId = normalizeUrlTechId(params.get('tech')) ?? '';
      this.pendingUrlTechId = techId || null;

      if (mitIds.length || grpIds.length || swAttackIds.length || campAttackIds.length || techId) {
        // Wait for the TARGET domain, not the first emission: domain$ replays
        // whatever is loaded (Enterprise, on a boot that is switching to ICS).
        const targetName = ATTACK_DOMAIN_NAMES[target];
        this.dataService.domain$.pipe(
          filter((d): d is Domain => !!d && d.name === targetName),
          take(1),
        ).subscribe((domain) => {
          if (mitIds.length) {
            const mits = mitIds.map((id) => domain.mitigations.find((m) => m.attackId === id)).filter((m): m is Mitigation => m !== undefined);
            if (mits.length) this.activeMitigationFiltersSubject.next(mits);
          }
          if (grpIds.length) {
            const ids = new Set(grpIds.map((id) => domain.groups.find((g) => g.attackId === id)?.id).filter((id): id is string => !!id));
            if (ids.size) this.activeThreatGroupIdsSubject.next(ids);
          }
          if (swAttackIds.length) {
            const ids = new Set(swAttackIds.map((id) => domain.software.find((s) => s.attackId === id)?.id).filter((id): id is string => !!id));
            if (ids.size) this.activeSoftwareIdsSubject.next(ids);
          }
          if (campAttackIds.length) {
            const ids = new Set(campAttackIds.map((id) => domain.campaigns.find((c) => c.attackId === id)?.id).filter((id): id is string => !!id));
            if (ids.size) this.activeCampaignIdsSubject.next(ids);
          }
          // Select the technique from the URL (tech=T1059.001). A retired id opens
          // the technique that replaced it; an id the domain lacks selects nothing
          // and says which domain to add. Skipped if the user selected meanwhile.
          if (techId && this.pendingUrlTechId === techId) {
            this.pendingUrlTechId = null;
            // The resolver is the identity until a domain loads; DataService
            // subscribed first, so it already holds THIS domain's map here.
            const liveId = this.attackIdResolver.resolve(techId);
            const technique = domain.techniques.find((t: Technique) => t.attackId === liveId);
            if (technique) {
              this.selectTechnique(technique);
            } else {
              this.urlNoticeSubject.next(techNotInDomainMessage(techId, target));
            }
          }
        });
      }
    } catch { /* ignore parse errors */ }
  }

  /**
   * Serialize the current shareable filter state to URL query params.
   * Same keys as the pre-router hash format (mit, tq, pf, plat, dim, sfm,
   * ds, heat, impl, scope, tsearch, grp, sw, camp) so old links stay valid
   * through the legacy-hash shim, plus (E2.3) `tech`, the open technique, and
   * `dom`, the ATT&CK domain when it is not Enterprise. With `tech`, `heat`
   * and `dom` are always written, so a pasted link carries its lens and domain
   * even at the defaults.
   */
  serializeUrlState(): Record<string, string> {
    const domain = this.domainSnapshot;
    const params: Record<string, string> = {};
    const mits = this.activeMitigationFiltersSubject.value;
    if (mits.length) params['mit'] = mits.map((m) => m.attackId).join(',');
    const tq = this.techniqueQuerySubject.value;
    if (tq.trim()) params['tq'] = tq.trim();
    const pf = this.platformFilterSubject.value;
    if (pf) params['pf'] = pf;
    const platMulti = this.platformMultiSubject.value;
    if (platMulti.size) params['plat'] = [...platMulti].join(',');
    if (this.dimUncoveredSubject.value) params['dim'] = '1';
    if (this.searchFilterModeSubject.value) params['sfm'] = '1';
    const ds = this.activeDataSourceSubject.value;
    if (ds) params['ds'] = ds;
    const tech = this.selectedTechniqueSubject.value?.attackId ?? this.pendingUrlTechId;
    const heat = this.heatmapModeSubject.value;
    if (heat !== DEFAULT_HEATMAP_MODE || tech) params['heat'] = heat;
    const impl = this.implStatusFilterSubject.value;
    if (impl) params['impl'] = impl;
    const scope = this.searchScopeSubject.value;
    if (scope !== 'name') params['scope'] = scope;
    const tsearch = this.techniqueSearchSubject.value;
    if (tsearch.trim()) params['tsearch'] = tsearch.trim();
    if (domain) {
      const groupIds = this.activeThreatGroupIdsSubject.value;
      if (groupIds.size) {
        const ids = [...groupIds].map((id) => domain.groups.find((g) => g.id === id)?.attackId).filter(Boolean);
        if (ids.length) params['grp'] = ids.join(',');
      }
      const swIds = this.activeSoftwareIdsSubject.value;
      if (swIds.size) {
        const ids = [...swIds].map((id) => domain.software.find((s) => s.id === id)?.attackId).filter(Boolean);
        if (ids.length) params['sw'] = ids.join(',');
      }
      const campIds = this.activeCampaignIdsSubject.value;
      if (campIds.size) {
        const ids = [...campIds].map((id) => domain.campaigns.find((c) => c.id === id)?.attackId).filter(Boolean);
        if (ids.length) params['camp'] = ids.join(',');
      }
    }
    const attackDomain = this.currentAttackDomain();
    if (attackDomain !== 'enterprise' || tech) params['dom'] = attackDomain;
    if (tech) params['tech'] = tech;
    return params;
  }

  selectTechnique(technique: Technique | null): void {
    // A selection made now supersedes a `tech` link still waiting for its domain.
    this.pendingUrlTechId = null;
    // Closing the drawer unpins it (the close button, Escape on the matrix or
    // through HotkeysService, clearAll), so a later selection starts unpinned.
    if (technique === null) this.drawerPinnedSubject.next(false);
    this.selectedTechniqueSubject.next(technique);
  }

  setDrawerPinned(p: boolean): void {
    this.drawerPinnedSubject.next(p);
  }

  /** Replace entire mitigation filter with a single mitigation, or clear. */
  filterByMitigation(mitigation: Mitigation | null): void {
    this.activeMitigationFiltersSubject.next(mitigation ? [mitigation] : []);
  }

  addMitigationFilter(mitigation: Mitigation): void {
    const current = this.activeMitigationFiltersSubject.value;
    if (!current.find((m) => m.id === mitigation.id)) {
      this.activeMitigationFiltersSubject.next([...current, mitigation]);
    }
  }

  removeMitigationFilter(mitigation: Mitigation): void {
    const current = this.activeMitigationFiltersSubject.value;
    this.activeMitigationFiltersSubject.next(current.filter((m) => m.id !== mitigation.id));
  }

  setTechniqueQuery(q: string): void {
    this.techniqueQuerySubject.next(q);
  }

  setSortMode(mode: SortMode): void {
    this.sortModeSubject.next(mode);
  }

  toggleDimUncovered(): void {
    this.dimUncoveredSubject.next(!this.dimUncoveredSubject.value);
  }

  setPlatformFilter(platform: string | null): void {
    this.platformFilterSubject.next(platform);
  }

  toggleTacticVisibility(tacticId: string): void {
    const current = new Set(this.hiddenTacticIdsSubject.value);
    if (current.has(tacticId)) current.delete(tacticId);
    else current.add(tacticId);
    this.hiddenTacticIdsSubject.next(current);
  }

  clearHiddenTactics(): void {
    this.hiddenTacticIdsSubject.next(new Set());
  }

  toggleThreatGroup(groupId: string): void {
    const current = new Set(this.activeThreatGroupIdsSubject.value);
    if (current.has(groupId)) current.delete(groupId);
    else current.add(groupId);
    this.activeThreatGroupIdsSubject.next(current);
  }

  clearThreatGroups(): void {
    this.activeThreatGroupIdsSubject.next(new Set());
  }

  toggleWhatIfMitigation(mitigationId: string): void {
    const current = new Set(this.whatIfMitigationIdsSubject.value);
    if (current.has(mitigationId)) current.delete(mitigationId);
    else current.add(mitigationId);
    this.whatIfMitigationIdsSubject.next(current);
  }

  clearWhatIf(): void {
    this.whatIfMitigationIdsSubject.next(new Set());
  }

  toggleSoftware(softwareId: string): void {
    const current = new Set(this.activeSoftwareIdsSubject.value);
    if (current.has(softwareId)) current.delete(softwareId);
    else current.add(softwareId);
    this.activeSoftwareIdsSubject.next(current);
  }

  clearSoftware(): void {
    this.activeSoftwareIdsSubject.next(new Set());
  }

  toggleCampaign(campaignId: string): void {
    const current = new Set(this.activeCampaignIdsSubject.value);
    if (current.has(campaignId)) current.delete(campaignId);
    else current.add(campaignId);
    this.activeCampaignIdsSubject.next(current);
  }

  clearCampaigns(): void {
    this.activeCampaignIdsSubject.next(new Set());
  }

  setDataSourceFilter(name: string | null): void {
    this.activeDataSourceSubject.next(name);
  }

  setHeatmapMode(mode: HeatmapMode): void {
    this.heatmapModeSubject.next(mode);
  }

  setImplStatusFilter(status: string | null): void {
    this.implStatusFilterSubject.next(status);
  }

  setSearchScope(scope: SearchScope): void {
    this.searchScopeSubject.next(scope);
  }

  toggleSearchScope(): void {
    this.searchScopeSubject.next(this.searchScopeSubject.value === 'name' ? 'full' : 'name');
  }

  toggleSearchFilterMode(): void {
    this.searchFilterModeSubject.next(!this.searchFilterModeSubject.value);
  }

  setSearchFilterMode(v: boolean): void {
    this.searchFilterModeSubject.next(v);
  }

  setCveFilter(techniqueIds: string[]): void {
    this.cveTechniqueIdsSubject.next(new Set(techniqueIds));
  }

  clearCveFilter(): void {
    this.cveTechniqueIdsSubject.next(new Set());
  }

  setTechniqueSearch(query: string): void {
    this.techniqueSearchSubject.next(query);
  }

  getTechniqueSearch(): string {
    return this.techniqueSearchSubject.value;
  }

  togglePlatform(platform: string): void {
    const current = new Set(this.platformMultiSubject.value);
    if (current.has(platform)) current.delete(platform);
    else current.add(platform);
    this.platformMultiSubject.next(current);
  }

  setPlatformMulti(platforms: Set<string>): void {
    this.platformMultiSubject.next(platforms);
  }

  clearPlatformFilter(): void {
    this.platformMultiSubject.next(new Set());
  }

  clearAll(): void {
    this.selectTechnique(null);
    this.activeMitigationFiltersSubject.next([]);
    this.techniqueQuerySubject.next('');
    this.sortModeSubject.next('alpha');
    this.platformFilterSubject.next(null);
    this.platformMultiSubject.next(new Set());
    this.dimUncoveredSubject.next(false);
    this.hiddenTacticIdsSubject.next(new Set());
    this.searchScopeSubject.next('name');
    this.activeThreatGroupIdsSubject.next(new Set());
    this.whatIfMitigationIdsSubject.next(new Set());
    this.activeSoftwareIdsSubject.next(new Set());
    this.activeCampaignIdsSubject.next(new Set());
    this.activeDataSourceSubject.next(null);
    this.heatmapModeSubject.next(DEFAULT_HEATMAP_MODE);
    this.implStatusFilterSubject.next(null);
    this.searchFilterModeSubject.next(false);
    this.cveTechniqueIdsSubject.next(new Set());
    this.techniqueSearchSubject.next('');
  }

  getStateSnapshot(): FilterStateSnapshot {
    return {
      heatmapMode: this.heatmapModeSubject.value,
      activeThreatGroupIds: [...this.activeThreatGroupIdsSubject.value],
      activeSoftwareIds: [...this.activeSoftwareIdsSubject.value],
      activeCampaignIds: [...this.activeCampaignIdsSubject.value],
      activeMitigationFilterIds: this.activeMitigationFiltersSubject.value.map(m => m.id),
      whatIfMitigationIds: [...this.whatIfMitigationIdsSubject.value],
      platformFilter: this.platformFilterSubject.value,
      sortMode: this.sortModeSubject.value,
      dimUncovered: this.dimUncoveredSubject.value,
      searchFilterMode: this.searchFilterModeSubject.value,
      hiddenTacticIds: [...this.hiddenTacticIdsSubject.value],
    };
  }

  restoreStateSnapshot(state: Partial<FilterStateSnapshot> | null | undefined): void {
    if (!state) return;
    if (state.heatmapMode) this.heatmapModeSubject.next(state.heatmapMode as HeatmapMode);
    if (state.platformFilter !== undefined) this.platformFilterSubject.next(state.platformFilter);
    if (state.sortMode) this.sortModeSubject.next(state.sortMode as SortMode);
    if (typeof state.dimUncovered === 'boolean') this.dimUncoveredSubject.next(state.dimUncovered);
    if (typeof state.searchFilterMode === 'boolean') this.searchFilterModeSubject.next(state.searchFilterMode);
    if (Array.isArray(state.hiddenTacticIds)) {
      this.hiddenTacticIdsSubject.next(new Set<string>(state.hiddenTacticIds));
    }
    if (Array.isArray(state.activeThreatGroupIds)) {
      this.activeThreatGroupIdsSubject.next(new Set<string>(state.activeThreatGroupIds));
    }
    if (Array.isArray(state.activeSoftwareIds)) {
      this.activeSoftwareIdsSubject.next(new Set<string>(state.activeSoftwareIds));
    }
    if (Array.isArray(state.activeCampaignIds)) {
      this.activeCampaignIdsSubject.next(new Set<string>(state.activeCampaignIds));
    }
    if (Array.isArray(state.whatIfMitigationIds)) {
      this.whatIfMitigationIdsSubject.next(new Set<string>(state.whatIfMitigationIds));
    }
    // Restore active mitigation filters from IDs via the domain
    if (Array.isArray(state.activeMitigationFilterIds) && state.activeMitigationFilterIds.length) {
      this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
        const mits = (state.activeMitigationFilterIds as string[])
          .map((id: string) => domain.mitigations.find(m => m.id === id))
          .filter((m): m is Mitigation => m !== undefined);
        this.activeMitigationFiltersSubject.next(mits);
      });
    } else {
      this.activeMitigationFiltersSubject.next([]);
    }
  }
}

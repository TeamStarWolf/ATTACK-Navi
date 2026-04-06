// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subscription, combineLatest, map, debounceTime, filter, take } from 'rxjs';
import { Technique } from '../models/technique';
import { Mitigation } from '../models/mitigation';
import { DataService } from './data.service';

export type SortMode = 'alpha' | 'coverage';
export type ActivePanel = 'dashboard' | 'threats' | 'priority' | 'whatif' | 'report' | 'controls' | 'software' | 'comparison' | 'layers' | 'cve' | 'analytics' | 'sigma' | 'purple' | 'actor' | 'search' | 'yara' | 'roadmap' | 'detection' | 'compliance' | 'actor-compare' | 'timeline' | 'settings' | 'custom-mit' | 'killchain' | 'risk-matrix' | 'scenario' | 'siem' | 'datasources' | 'watchlist' | 'changelog' | 'tags' | 'target' | 'campaign-timeline' | 'technique-graph' | 'coverage-diff' | 'intelligence' | 'collection' | 'assessment' | 'assets' | 'gap-analysis' | 'ir-playbook' | null;
export type HeatmapMode = 'coverage' | 'exposure' | 'status' | 'controls' | 'software' | 'campaign' | 'risk' | 'kev' | 'd3fend' | 'atomic' | 'engage' | 'car' | 'cve' | 'detection' | 'frequency' | 'cri' | 'unified' | 'sigma' | 'nist' | 'veris' | 'epss' | 'elastic' | 'splunk' | 'intelligence' | 'm365' | 'my-exposure';
export type SearchScope = 'name' | 'full';

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
  private activePanelSubject = new BehaviorSubject<ActivePanel>(null);
  private heatmapModeSubject = new BehaviorSubject<HeatmapMode>('coverage');
  private implStatusFilterSubject = new BehaviorSubject<string | null>(null);
  private searchFilterModeSubject = new BehaviorSubject<boolean>(false);
  searchFilterMode$: Observable<boolean> = this.searchFilterModeSubject.asObservable();
  private cveTechniqueIdsSubject = new BehaviorSubject<Set<string>>(new Set());
  cveTechniqueIds$: Observable<Set<string>> = this.cveTechniqueIdsSubject.asObservable();
  private techniqueSearchSubject = new BehaviorSubject<string>('');
  techniqueSearch$: Observable<string> = this.techniqueSearchSubject.asObservable();

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
  activePanel$: Observable<ActivePanel> = this.activePanelSubject.asObservable();
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

  private urlSub: Subscription | null = null;

  constructor(private dataService: DataService) {
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
          if (dc.dataSourceName === dsName) {
            const techs = domain.techniquesByDataComponent.get(dc.id) ?? [];
            for (const t of techs) ids.add(t.id);
          }
        }
        return ids;
      }),
    );

    this.readUrlState();

    this.urlSub = combineLatest([
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
    ]).pipe(debounceTime(300)).subscribe(([mits, tq, pf, dim, ds, groupIds, swIds, campIds, heat, impl, scope, sfm, tsearch, domain, platMulti]) => {
      this.writeUrlState(mits, tq, pf, dim, ds, groupIds, swIds, campIds, heat, impl, scope, sfm, tsearch, domain, platMulti);
    });
  }

  private readUrlState(): void {
    const hash = window.location.hash.slice(1);
    if (!hash) return;
    try {
      const params = new URLSearchParams(hash);
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
      const heat = params.get('heat') as HeatmapMode | null;
      if (heat) this.heatmapModeSubject.next(heat);
      const impl = params.get('impl');
      if (impl) this.implStatusFilterSubject.next(impl);
      const scope = params.get('scope') as SearchScope | null;
      if (scope) this.searchScopeSubject.next(scope);
      const tsearch = params.get('tsearch') ?? '';
      if (tsearch) this.techniqueSearchSubject.next(tsearch);

      const mitIds = (params.get('mit') ?? '').split(',').filter(Boolean);
      const grpIds = (params.get('grp') ?? '').split(',').filter(Boolean);
      const swAttackIds = (params.get('sw') ?? '').split(',').filter(Boolean);
      const campAttackIds = (params.get('camp') ?? '').split(',').filter(Boolean);

      const techId = params.get('tech') ?? '';

      if (mitIds.length || grpIds.length || swAttackIds.length || campAttackIds.length || techId) {
        this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe((domain) => {
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
          // Auto-select technique from URL (tech=T1059.001)
          if (techId) {
            const technique = domain.techniques.find((t: Technique) => t.attackId === techId);
            if (technique) {
              this.selectTechnique(technique);
            }
          }
        });
      }
    } catch { /* ignore parse errors */ }
  }

  private writeUrlState(
    mits: Mitigation[], tq: string, pf: string | null, dim: boolean,
    ds: string | null, groupIds: Set<string>, swIds: Set<string>, campIds: Set<string>,
    heat: HeatmapMode, impl: string | null, scope: SearchScope, sfm: boolean, tsearch: string, domain: any,
    platMulti: Set<string> = new Set(),
  ): void {
    const params = new URLSearchParams();
    if (mits.length) params.set('mit', mits.map((m) => m.attackId).join(','));
    if (tq.trim()) params.set('tq', tq.trim());
    if (pf) params.set('pf', pf);
    if (platMulti.size) params.set('plat', [...platMulti].join(','));
    if (dim) params.set('dim', '1');
    if (sfm) params.set('sfm', '1');
    if (ds) params.set('ds', ds);
    if (heat !== 'coverage') params.set('heat', heat);
    if (impl) params.set('impl', impl);
    if (scope !== 'name') params.set('scope', scope);
    if (tsearch.trim()) params.set('tsearch', tsearch.trim());
    if (domain && groupIds.size) {
      const ids = [...groupIds].map((id) => domain.groups.find((g: any) => g.id === id)?.attackId).filter(Boolean);
      if (ids.length) params.set('grp', ids.join(','));
    }
    if (domain && swIds.size) {
      const ids = [...swIds].map((id) => domain.software.find((s: any) => s.id === id)?.attackId).filter(Boolean);
      if (ids.length) params.set('sw', ids.join(','));
    }
    if (domain && campIds.size) {
      const ids = [...campIds].map((id) => domain.campaigns.find((c: any) => c.id === id)?.attackId).filter(Boolean);
      if (ids.length) params.set('camp', ids.join(','));
    }
    const hash = params.toString();
    history.replaceState(null, '', hash ? '#' + hash : window.location.pathname + window.location.search);
  }

  selectTechnique(technique: Technique | null): void {
    this.selectedTechniqueSubject.next(technique);
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

  getActivePanel(): ActivePanel {
    return this.activePanelSubject.value;
  }

  setActivePanel(panel: ActivePanel): void {
    this.activePanelSubject.next(panel);
  }

  togglePanel(panel: Exclude<ActivePanel, null>): void {
    const current = this.activePanelSubject.value;
    this.activePanelSubject.next(current === panel ? null : panel);
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
    this.selectedTechniqueSubject.next(null);
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
    this.heatmapModeSubject.next('coverage');
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

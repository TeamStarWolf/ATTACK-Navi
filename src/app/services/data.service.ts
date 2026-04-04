import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, from, of, throwError } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';
import { Domain, TacticColumn } from '../models/domain';
import { Tactic } from '../models/tactic';
import { Technique } from '../models/technique';
import { Mitigation, MitigationRelationship } from '../models/mitigation';
import { ThreatGroup } from '../models/group';
import { AttackSoftware } from '../models/software';
import { ProcedureExample } from '../models/procedure';
import { MitreDataSource, MitreDataComponent } from '../models/datasource';
import { Campaign } from '../models/campaign';

export type DataSourceMode = 'live' | 'bundled';

export type AttackDomain = 'enterprise' | 'ics' | 'mobile';

const DOMAIN_CONFIG: Record<AttackDomain, { liveUrl: string; bundledUrl: string | null; idbKey: string; name: string }> = {
  enterprise: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    bundledUrl: 'assets/enterprise-attack.json',
    idbKey: 'enterprise-attack-v2',
    name: 'Enterprise ATT&CK',
  },
  ics: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
    bundledUrl: null,
    idbKey: 'ics-attack-v1',
    name: 'ICS ATT&CK',
  },
  mobile: {
    liveUrl: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
    bundledUrl: null,
    idbKey: 'mobile-attack-v1',
    name: 'Mobile ATT&CK',
  },
};

const IDB_DB = 'mitre-navigator-cache';
const IDB_STORE = 'stix-bundles';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

@Injectable({ providedIn: 'root' })
export class DataService {
  private domainSubject = new BehaviorSubject<Domain | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(false);
  private errorSubject = new BehaviorSubject<string | null>(null);
  private mode: DataSourceMode = 'live';
  private attackDomain: AttackDomain = 'enterprise';

  currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');

  /** ISO timestamp of the last successful domain data load */
  lastFetched$ = new BehaviorSubject<string | null>(null);

  domain$: Observable<Domain | null> = this.domainSubject.asObservable();
  loading$: Observable<boolean> = this.loadingSubject.asObservable();
  error$: Observable<string | null> = this.errorSubject.asObservable();

  constructor(private http: HttpClient) {}

  setDataSourceMode(mode: DataSourceMode): void {
    this.mode = mode;
  }

  setAttackDomain(domain: AttackDomain): void {
    this.attackDomain = domain;
    this.currentDomain$.next(domain);
  }

  switchDomain(domain: AttackDomain): void {
    if (domain === this.currentDomain$.value) return;
    this.attackDomain = domain;
    this.currentDomain$.next(domain);
    this.domainSubject.next(null);
    this.loadDomain();
  }

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
    this.loadDomain();
  }

  loadDomain(): void {
    this.loadingSubject.next(true);
    this.errorSubject.next(null);

    const config = DOMAIN_CONFIG[this.attackDomain];
    const load$ = this.mode === 'live' ? this.loadLive(config) : this.loadBundled(config);
    load$.subscribe({
      next: (domain) => {
        this.domainSubject.next(domain);
        this.loadingSubject.next(false);
        this.lastFetched$.next(new Date().toISOString());
      },
      error: (err) => {
        this.errorSubject.next(err?.message ?? 'Failed to load ATT&CK data');
        this.loadingSubject.next(false);
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

  getSoftwareForGroup(groupId: string): AttackSoftware[] {
    const domain = this.domainSubject.value;
    if (!domain) return [];
    // Find software that shares at least one technique with this group
    const groupTechIds = new Set((domain.techniquesByGroup.get(groupId) ?? []).map(t => t.id));
    if (!groupTechIds.size) return [];
    const result = new Map<string, AttackSoftware>();
    for (const sw of domain.software) {
      const swTechs = domain.techniquesBySoftware.get(sw.id) ?? [];
      if (swTechs.some(t => groupTechIds.has(t.id))) {
        result.set(sw.id, sw);
      }
    }
    return [...result.values()];
  }

  getCampaignsForGroup(groupId: string): Campaign[] {
    return (this.domainSubject.value?.campaigns ?? []).filter(c => c.attributedGroupIds.includes(groupId));
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

  private loadLive(config: typeof DOMAIN_CONFIG[AttackDomain]): Observable<Domain> {
    return from(this.loadFromIDB(config.idbKey)).pipe(
      switchMap((cached) => {
        if (cached) return of(cached);
        return this.http.get<any>(config.liveUrl).pipe(
          retryWithBackoff(),
          switchMap((bundle) => from(this.saveToIDB(bundle, config.idbKey).then(() => this.parseBundle(bundle, config.name)))),
          catchError(() => config.bundledUrl ? this.loadBundled(config) : throwError(() => new Error('No bundled fallback for this domain'))),
        );
      }),
    );
  }

  private loadBundled(config: typeof DOMAIN_CONFIG[AttackDomain]): Observable<Domain> {
    if (!config.bundledUrl) {
      return throwError(() => new Error('No bundled fallback available'));
    }
    return this.http
      .get<any>(config.bundledUrl)
      .pipe(switchMap((bundle) => of(this.parseBundle(bundle, config.name))));
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
    const campaignUsesRels: Array<{ campaignRef: string; techniqueRef: string }> = [];
    // detects: detection-strategy → technique (v18) or data-component → technique (legacy)
    const detectsRels: Array<{ sourceRef: string; techniqueRef: string }> = [];

    for (const obj of bundle.objects ?? []) {
      // x-mitre-collection is never revoked — parse it before the revoked check
      if (obj.type === 'x-mitre-collection') {
        attackVersion = obj.x_mitre_version ?? '';
        attackModified = obj.modified ?? '';
        continue;
      }

      if (obj.revoked || obj.x_mitre_deprecated) continue;

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
          if (obj.relationship_type === 'mitigates') {
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
              campaignUsesRels.push({ campaignRef: obj.source_ref, techniqueRef: obj.target_ref });
            }
          } else if (
            obj.relationship_type === 'detects' &&
            (obj.source_ref?.startsWith('x-mitre-detection-strategy--') ||
             obj.source_ref?.startsWith('x-mitre-data-component--')) &&
            obj.target_ref?.startsWith('attack-pattern--')
          ) {
            detectsRels.push({ sourceRef: obj.source_ref, techniqueRef: obj.target_ref });
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

      for (const dcId of dcIds) {
        const dc = dataComponentsMap.get(dcId);
        if (!dc) continue;

        if (!techniquesByDataComponent.has(dc.id)) techniquesByDataComponent.set(dc.id, []);
        techniquesByDataComponent.get(dc.id)!.push(technique);

        if (!dataComponentsByTechnique.has(technique.id)) dataComponentsByTechnique.set(technique.id, []);
        dataComponentsByTechnique.get(technique.id)!.push(dc);
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
    };
  }

  private extractAttackId(obj: any): string | null {
    for (const ref of obj.external_references ?? []) {
      if (ref.source_name?.startsWith('mitre-attack') && ref.external_id) {
        return ref.external_id;
      }
    }
    return null;
  }

  private extractUrl(obj: any): string {
    for (const ref of obj.external_references ?? []) {
      if (ref.source_name?.startsWith('mitre-attack') && ref.url) {
        return ref.url;
      }
    }
    return '';
  }
}

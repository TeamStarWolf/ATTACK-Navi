// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

export interface MispGalaxyCluster {
  uuid: string;
  value: string;          // e.g. "PowerShell - T1059.001"
  description: string;
  attackId: string;       // parsed from value or meta.external_id
  mitrePlatforms: string[];
  synonyms: string[];
  refs: string[];
  related: string[];      // related cluster UUIDs
  tags: string[];         // MISP galaxy tags for hunting
}

export interface MispTag {
  name: string;           // e.g. 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"'
  colour: string;
  exportable: boolean;
}

export interface MispConfig {
  url: string;
  apiKey: string;
  orgId: string;
  connected: boolean;
  mode: 'direct' | 'proxy';
  proxyUrl: string;
}

export interface MispAttribute {
  id: string;
  type: string;
  value: string;
  category: string;
  comment: string;
  timestamp: string;
  to_ids: boolean;
  event_id: string;
}

export interface MispEvent {
  id: string;
  info: string;
  date: string;
  org: string;
  attribute_count: number;
  threat_level_id: string;
  published: boolean;
  uuid: string;
}

interface MispGalaxyClusterRaw {
  uuid: string;
  value: string;
  description?: string;
  meta?: {
    external_id?: string | string[];
    'mitre-platforms'?: string[];
    synonyms?: string[];
    refs?: string[];
    related?: string[];
  };
}

interface MispGalaxyFile {
  uuid?: string;
  name?: string;
  description?: string;
  version?: string;
  values?: MispGalaxyClusterRaw[];
}

// MISP galaxy ATT&CK pattern cluster URL (mitre-attack-pattern.json)
const GALAXY_URL =
  'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json';

@Injectable({ providedIn: 'root' })
export class MispService {
  private byAttackId = new Map<string, MispGalaxyCluster>();
  private allClusters: MispGalaxyCluster[] = [];

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  // ─── Live server state ──────────────────────────────────────────────────
  private serverConfig: MispConfig = { url: '', apiKey: '', orgId: '', connected: false, mode: 'direct', proxyUrl: '' };

  private connectedSubject = new BehaviorSubject<boolean>(false);
  readonly connected$ = this.connectedSubject.asObservable();

  private serverLoadingSubject = new BehaviorSubject<boolean>(false);
  readonly serverLoading$ = this.serverLoadingSubject.asObservable();

  private serverErrorSubject = new BehaviorSubject<string | null>(null);
  readonly serverError$ = this.serverErrorSubject.asObservable();

  // Caches for live server queries
  private attributeCache = new Map<string, MispAttribute[]>();
  private eventCache = new Map<string, MispEvent[]>();

  constructor(private http: HttpClient) {
    this.load();
    this.loadConfigFromStorage();
  }

  // ─── Live server configuration ──────────────────────────────────────────

  private loadConfigFromStorage(): void {
    try {
      const stored = localStorage.getItem('misp_config');
      if (stored) {
        const c = JSON.parse(stored);
        this.serverConfig = {
          ...this.serverConfig,
          url: typeof c?.url === 'string' ? c.url : '',
          orgId: typeof c?.orgId === 'string' ? c.orgId : '',
          connected: false,
          apiKey: '',
          mode: c?.mode === 'proxy' ? 'proxy' : 'direct',
          proxyUrl: typeof c?.proxyUrl === 'string' ? c.proxyUrl : '',
        };
      }
    } catch {
      // ignore
    }
  }

  saveConfig(config: MispConfig): void {
    this.serverConfig = {
      url: config.url.replace(/\/$/, ''),
      apiKey: config.apiKey,
      orgId: config.orgId,
      connected: false,
      mode: config.mode === 'proxy' ? 'proxy' : 'direct',
      proxyUrl: config.proxyUrl.replace(/\/$/, ''),
    };
    this.attributeCache.clear();
    this.eventCache.clear();
    try {
      localStorage.setItem('misp_config', JSON.stringify({
        url: this.serverConfig.url,
        orgId: this.serverConfig.orgId,
        mode: this.serverConfig.mode,
        proxyUrl: this.serverConfig.proxyUrl,
      }));
    } catch {
      // ignore
    }
    this.testConnection().subscribe();
  }

  getConfig(): MispConfig {
    return { ...this.serverConfig };
  }

  clearConfig(): void {
    this.serverConfig = { url: '', apiKey: '', orgId: '', connected: false, mode: 'direct', proxyUrl: '' };
    this.connectedSubject.next(false);
    this.serverErrorSubject.next(null);
    localStorage.removeItem('misp_config');
    this.attributeCache.clear();
    this.eventCache.clear();
  }

  testConnection(): Observable<boolean> {
    if (this.serverConfig.mode === 'proxy') {
      if (!this.serverConfig.proxyUrl) {
        this.connectedSubject.next(false);
        this.serverErrorSubject.next('No secure proxy URL configured.');
        return of(false);
      }
    } else if (!this.serverConfig.url || !this.serverConfig.apiKey) {
      this.connectedSubject.next(false);
      this.serverErrorSubject.next('No URL or API key configured.');
      return of(false);
    }

    this.serverLoadingSubject.next(true);
    this.serverErrorSubject.next(null);

    return this.mispFetch<any>('/servers/getVersion').pipe(
      map(data => {
        if (data?.version) {
          this.serverConfig.connected = true;
          this.connectedSubject.next(true);
          this.serverErrorSubject.next(null);
          this.serverLoadingSubject.next(false);
          return true;
        }
        this.serverConfig.connected = false;
        this.connectedSubject.next(false);
        this.serverErrorSubject.next('Unexpected response from MISP server.');
        this.serverLoadingSubject.next(false);
        return false;
      }),
      catchError(err => {
        this.serverConfig.connected = false;
        this.connectedSubject.next(false);
        this.serverErrorSubject.next(`Connection failed: ${err?.message ?? 'Network error'}`);
        this.serverLoadingSubject.next(false);
        return of(false);
      }),
    );
  }

  // ─── Live server data queries ───────────────────────────────────────────

  getAttributesForTechnique(attackId: string): Observable<MispAttribute[]> {
    if (!this.serverConfig.connected) return of([]);
    if (this.attributeCache.has(attackId)) return of(this.attributeCache.get(attackId)!);

    const cluster = this.getCluster(attackId);
    const tagValue = cluster
      ? `misp-galaxy:mitre-attack-pattern="${cluster.value}"`
      : `misp-galaxy:mitre-attack-pattern="${attackId}"`;

    const body = {
      returnFormat: 'json',
      tags: [tagValue],
      limit: 50,
    };

    return this.mispFetch<any>('/attributes/restSearch', body).pipe(
      map(data => {
        const attrs: MispAttribute[] = (data?.response?.Attribute ?? []).map((a: any) => ({
          id: a.id ?? '',
          type: a.type ?? '',
          value: a.value ?? '',
          category: a.category ?? '',
          comment: a.comment ?? '',
          timestamp: a.timestamp ?? '',
          to_ids: a.to_ids ?? false,
          event_id: a.event_id ?? '',
        }));
        this.attributeCache.set(attackId, attrs);
        return attrs;
      }),
      catchError(() => of([])),
    );
  }

  getEventsForTechnique(attackId: string): Observable<MispEvent[]> {
    if (!this.serverConfig.connected) return of([]);
    if (this.eventCache.has(attackId)) return of(this.eventCache.get(attackId)!);

    const cluster = this.getCluster(attackId);
    const tagValue = cluster
      ? `misp-galaxy:mitre-attack-pattern="${cluster.value}"`
      : `misp-galaxy:mitre-attack-pattern="${attackId}"`;

    const body = {
      returnFormat: 'json',
      tags: [tagValue],
      limit: 20,
    };

    return this.mispFetch<any>('/events/restSearch', body).pipe(
      map(data => {
        const events: MispEvent[] = (data?.response ?? []).map((e: any) => {
          const evt = e.Event ?? e;
          return {
            id: evt.id ?? '',
            info: evt.info ?? '',
            date: evt.date ?? '',
            org: evt.Org?.name ?? evt.orgc_id ?? '',
            attribute_count: evt.attribute_count ?? 0,
            threat_level_id: evt.threat_level_id ?? '',
            published: evt.published ?? false,
            uuid: evt.uuid ?? '',
          };
        });
        this.eventCache.set(attackId, events);
        return events;
      }),
      catchError(() => of([])),
    );
  }

  createEvent(attackId: string, techniqueName: string): Observable<any> {
    if (!this.serverConfig.connected) {
      return of({ success: false, message: 'Not connected to MISP server.' });
    }

    const templateJson = this.generateEventTemplate(attackId, techniqueName);
    const body = JSON.parse(templateJson);

    return this.mispFetch<any>('/events/add', body).pipe(
      map(data => ({ success: true, event: data })),
      catchError(err => of({ success: false, message: err?.message ?? 'Failed to create event.' })),
    );
  }

  // ─── Private: MISP API fetch with CORS proxy fallback ───────────────────

  private mispFetch<T>(endpoint: string, body?: any): Observable<T> {
    const url = this.serverConfig.mode === 'proxy'
      ? `${this.serverConfig.proxyUrl}/api/misp${endpoint}`
      : `${this.serverConfig.url}${endpoint}`;
    const headers = this.serverConfig.mode === 'proxy'
      ? new HttpHeaders({
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        })
      : new HttpHeaders({
          'Authorization': this.serverConfig.apiKey,
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        });

    return body
      ? this.http.post<T>(url, body, { headers })
      : this.http.get<T>(url, { headers });
  }

  private load(): void {
    this.http.get<MispGalaxyFile>(GALAXY_URL)
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        if (!data?.values?.length) return;
        this.ingest(data.values);
        this.totalSubject.next(this.allClusters.length);
        this.loadedSubject.next(true);
      });
  }

  private ingest(rawValues: MispGalaxyClusterRaw[]): void {
    this.byAttackId.clear();
    this.allClusters = [];

    for (const raw of rawValues) {
      // Extract ATT&CK ID from meta.external_id or from the value string
      let attackId = '';
      const extId = raw.meta?.external_id;
      if (Array.isArray(extId)) {
        attackId = extId[0] ?? '';
      } else if (typeof extId === 'string') {
        attackId = extId;
      }

      // Fallback: parse from value like "PowerShell - T1059.001"
      if (!attackId) {
        const m = raw.value.match(/\b(T\d{4}(?:\.\d{3})?)\b/);
        if (m) attackId = m[1];
      }

      if (!attackId) continue;

      const cluster: MispGalaxyCluster = {
        uuid: raw.uuid ?? '',
        value: raw.value ?? '',
        description: raw.description ?? '',
        attackId,
        mitrePlatforms: raw.meta?.['mitre-platforms'] ?? [],
        synonyms: raw.meta?.synonyms ?? [],
        refs: raw.meta?.refs ?? [],
        related: raw.meta?.related ?? [],
        tags: [
          `misp-galaxy:mitre-attack-pattern="${raw.value}"`,
        ],
      };

      this.allClusters.push(cluster);
      this.byAttackId.set(attackId, cluster);
    }
  }

  /** Get MISP galaxy cluster for an ATT&CK technique ID. */
  getCluster(attackId: string): MispGalaxyCluster | null {
    return this.byAttackId.get(attackId) ?? this.byAttackId.get(attackId.split('.')[0]) ?? null;
  }

  /** Get all clusters. */
  getAll(): MispGalaxyCluster[] {
    return this.allClusters;
  }

  /** Check if a technique has a MISP galaxy mapping. */
  hasMisp(attackId: string): boolean {
    return this.byAttackId.has(attackId) || this.byAttackId.has(attackId.split('.')[0]);
  }

  /** Generate MISP tags for a technique — copy-paste ready. */
  getMispTags(attackId: string): MispTag[] {
    const cluster = this.getCluster(attackId);
    if (!cluster) return [];

    return cluster.tags.map(tag => ({
      name: tag,
      colour: this.tagColor(attackId),
      exportable: true,
    }));
  }

  /** Generate a MISP event JSON template for a technique. */
  generateEventTemplate(attackId: string, techniqueName: string): string {
    const cluster = this.getCluster(attackId);
    const tags = this.getMispTags(attackId);
    const now = new Date().toISOString().split('T')[0];

    const template = {
      Event: {
        info: `ATT&CK ${attackId} - ${techniqueName} Detection`,
        date: now,
        threat_level_id: '2',
        analysis: '0',
        distribution: '0',
        tags: tags.map(t => ({ name: t.name, exportable: t.exportable })),
        Galaxy: cluster ? [{
          type: 'mitre-attack-pattern',
          name: 'ATT&CK Pattern',
          uuid: cluster.uuid,
          GalaxyCluster: [{
            type: 'mitre-attack-pattern',
            value: cluster.value,
            description: cluster.description,
            uuid: cluster.uuid,
            tag_name: tags[0]?.name ?? '',
          }],
        }] : [],
        Attribute: [
          {
            type: 'comment',
            value: `Technique reference: https://attack.mitre.org/techniques/${attackId.replace('.', '/')}`,
            category: 'External analysis',
            to_ids: false,
          },
        ],
      },
    };

    return JSON.stringify(template, null, 2);
  }

  /** Search clusters by name or description. */
  search(query: string): MispGalaxyCluster[] {
    const q = query.toLowerCase();
    return this.allClusters.filter(c =>
      c.value.toLowerCase().includes(q) ||
      c.attackId.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q)
    ).slice(0, 50);
  }

  private tagColor(attackId: string): string {
    // Color by tactic prefix (approximate)
    const id = attackId.toUpperCase();
    if (id.startsWith('T1595') || id.startsWith('T1589') || id.startsWith('T1590')) return '#0099cc'; // Reconnaissance
    if (id.startsWith('T1583') || id.startsWith('T1584')) return '#336699'; // Resource Development
    if (id.startsWith('T1566') || id.startsWith('T1190') || id.startsWith('T1133')) return '#cc3300'; // Initial Access
    if (id.startsWith('T1059') || id.startsWith('T1204') || id.startsWith('T1047')) return '#ff6600'; // Execution
    if (id.startsWith('T1078') || id.startsWith('T1547') || id.startsWith('T1053')) return '#cc9900'; // Persistence
    if (id.startsWith('T1548') || id.startsWith('T1068') || id.startsWith('T1134')) return '#9933cc'; // Privilege Escalation
    if (id.startsWith('T1562') || id.startsWith('T1070') || id.startsWith('T1036')) return '#339933'; // Defense Evasion
    if (id.startsWith('T1003') || id.startsWith('T1056') || id.startsWith('T1110')) return '#cc0066'; // Credential Access
    if (id.startsWith('T1046') || id.startsWith('T1082') || id.startsWith('T1018')) return '#006699'; // Discovery
    if (id.startsWith('T1021') || id.startsWith('T1091') || id.startsWith('T1534')) return '#0066cc'; // Lateral Movement
    if (id.startsWith('T1560') || id.startsWith('T1005') || id.startsWith('T1114')) return '#cc6600'; // Collection
    if (id.startsWith('T1071') || id.startsWith('T1090') || id.startsWith('T1095')) return '#993366'; // C2
    if (id.startsWith('T1048') || id.startsWith('T1041') || id.startsWith('T1567')) return '#cc0000'; // Exfiltration
    if (id.startsWith('T1485') || id.startsWith('T1490') || id.startsWith('T1486')) return '#660000'; // Impact
    return '#666699';
  }
}

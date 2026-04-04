import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

export interface OpenCtiConfig {
  url: string;       // e.g. https://demo.opencti.io
  token: string;     // API token (Bearer)
  connected: boolean;
  mode: 'direct' | 'proxy';
  proxyUrl: string;
}

export interface OpenCtiIndicator {
  id: string;
  name: string;
  pattern: string;        // STIX pattern or YARA/Sigma/Snort
  patternType: string;    // 'stix', 'yara', 'sigma', 'suricata'
  validFrom: string;
  confidence: number;
  revoked: boolean;
  attackIds: string[];    // mapped ATT&CK technique IDs
  labels: string[];
  description: string;
  externalRef?: string;
}

export interface OpenCtiThreatActor {
  id: string;
  name: string;
  description: string;
  aliases: string[];
  labels: string[];
  attackIds: string[];    // techniques this actor uses
  confidence: number;
}

export interface OpenCtiRelationship {
  id: string;
  fromId: string;
  toId: string;
  relationshipType: string;
  confidence: number;
}

// GraphQL queries
const INDICATORS_QUERY = `
  query IndicatorsByTechnique($attackId: String!) {
    indicators(filters: {
      key: "indicates",
      values: [$attackId]
    }) {
      edges {
        node {
          id
          name
          pattern
          pattern_type
          valid_from
          confidence
          revoked
          killChainPhases {
            phase_name
            kill_chain_name
          }
          objectLabel {
            edges { node { value color } }
          }
          description
        }
      }
    }
  }
`;

const THREAT_ACTORS_QUERY = `
  query ThreatActorsByTechnique($attackId: String!) {
    threatActors(filters: {
      key: "uses",
      values: [$attackId]
    }) {
      edges {
        node {
          id
          name
          description
          aliases
          confidence
          objectLabel {
            edges { node { value } }
          }
        }
      }
    }
  }
`;

@Injectable({ providedIn: 'root' })
export class OpenCtiService {
  private config: OpenCtiConfig = {
    url: '',
    token: '',
    connected: false,
    mode: 'direct',
    proxyUrl: '',
  };

  private connectedSubject = new BehaviorSubject<boolean>(false);
  readonly connected$ = this.connectedSubject.asObservable();

  private loadingSubject = new BehaviorSubject<boolean>(false);
  readonly loading$ = this.loadingSubject.asObservable();

  private errorSubject = new BehaviorSubject<string | null>(null);
  readonly error$ = this.errorSubject.asObservable();

  // Cached results per technique
  private indicatorCache = new Map<string, OpenCtiIndicator[]>();
  private actorCache = new Map<string, OpenCtiThreatActor[]>();

  constructor(private http: HttpClient) {
    this.loadConfigFromStorage();
  }

  // ─── Configuration ────────────────────────────────────────────────────────

  private loadConfigFromStorage(): void {
    try {
      const stored = localStorage.getItem('opencti_config');
      if (stored) {
        const c = JSON.parse(stored);
        this.config = {
          ...this.config,
          url: typeof c?.url === 'string' ? c.url : '',
          connected: false,
          token: '',
          mode: c?.mode === 'proxy' ? 'proxy' : 'direct',
          proxyUrl: typeof c?.proxyUrl === 'string' ? c.proxyUrl : '',
        };
      }
    } catch {
      // ignore
    }
  }

  saveConfig(config: Partial<OpenCtiConfig>): void {
    this.config = {
      url: (config.url ?? '').replace(/\/$/, ''),
      token: config.token ?? '',
      connected: false,
      mode: config.mode === 'proxy' ? 'proxy' : 'direct',
      proxyUrl: (config.proxyUrl ?? '').replace(/\/$/, ''),
    };
    this.indicatorCache.clear();
    this.actorCache.clear();
    try {
      localStorage.setItem('opencti_config', JSON.stringify({
        url: this.config.url,
        mode: this.config.mode,
        proxyUrl: this.config.proxyUrl,
      }));
    } catch {
      // ignore
    }
    this.testConnection();
  }

  getConfig(): OpenCtiConfig {
    return { ...this.config };
  }

  clearConfig(): void {
    this.config = { url: '', token: '', connected: false, mode: 'direct', proxyUrl: '' };
    this.connectedSubject.next(false);
    localStorage.removeItem('opencti_config');
    this.indicatorCache.clear();
    this.actorCache.clear();
  }

  testConnection(): void {
    if (this.config.mode === 'proxy') {
      if (!this.config.proxyUrl) {
        this.connectedSubject.next(false);
        this.errorSubject.next('No secure proxy URL configured.');
        return;
      }
    } else if (!this.config.url || !this.config.token) {
      this.connectedSubject.next(false);
      this.errorSubject.next('No URL or token configured.');
      return;
    }

    this.loadingSubject.next(true);
    this.errorSubject.next(null);

    const query = `{ about { version title } }`;
    this.graphql<any>(query, {}).subscribe({
      next: (data) => {
        if (data?.about) {
          this.config.connected = true;
          this.connectedSubject.next(true);
          this.errorSubject.next(null);
        } else {
          this.config.connected = false;
          this.connectedSubject.next(false);
          this.errorSubject.next('Unexpected response from OpenCTI server.');
        }
        this.loadingSubject.next(false);
      },
      error: (err) => {
        this.config.connected = false;
        this.connectedSubject.next(false);
        this.errorSubject.next(`Connection failed: ${err?.message ?? 'Network error'}`);
        this.loadingSubject.next(false);
      },
    });
  }

  // ─── Data Queries ─────────────────────────────────────────────────────────

  /** Fetch indicators related to an ATT&CK technique from OpenCTI. */
  getIndicatorsForTechnique(attackId: string): Observable<OpenCtiIndicator[]> {
    if (!this.config.connected) return of([]);
    if (this.indicatorCache.has(attackId)) return of(this.indicatorCache.get(attackId)!);

    return this.graphql<any>(INDICATORS_QUERY, { attackId }).pipe(
      map(data => {
        const edges = data?.indicators?.edges ?? [];
        const indicators: OpenCtiIndicator[] = edges.map((e: any) => {
          const n = e.node;
          return {
            id: n.id ?? '',
            name: n.name ?? '',
            pattern: n.pattern ?? '',
            patternType: n.pattern_type ?? 'stix',
            validFrom: n.valid_from ?? '',
            confidence: n.confidence ?? 0,
            revoked: n.revoked ?? false,
            attackIds: [attackId],
            labels: (n.objectLabel?.edges ?? []).map((le: any) => le.node?.value ?? ''),
            description: n.description ?? '',
          } as OpenCtiIndicator;
        });
        this.indicatorCache.set(attackId, indicators);
        return indicators;
      }),
      catchError(() => of([])),
    );
  }

  /** Fetch threat actors using an ATT&CK technique from OpenCTI. */
  getThreatActorsForTechnique(attackId: string): Observable<OpenCtiThreatActor[]> {
    if (!this.config.connected) return of([]);
    if (this.actorCache.has(attackId)) return of(this.actorCache.get(attackId)!);

    return this.graphql<any>(THREAT_ACTORS_QUERY, { attackId }).pipe(
      map(data => {
        const edges = data?.threatActors?.edges ?? [];
        const actors: OpenCtiThreatActor[] = edges.map((e: any) => {
          const n = e.node;
          return {
            id: n.id ?? '',
            name: n.name ?? '',
            description: n.description ?? '',
            aliases: n.aliases ?? [],
            labels: (n.objectLabel?.edges ?? []).map((le: any) => le.node?.value ?? ''),
            attackIds: [attackId],
            confidence: n.confidence ?? 0,
          } as OpenCtiThreatActor;
        });
        this.actorCache.set(attackId, actors);
        return actors;
      }),
      catchError(() => of([])),
    );
  }

  /** Import a STIX bundle from a URL into OpenCTI (requires write access). */
  importStixBundle(stixJson: string): Observable<{ success: boolean; message: string }> {
    if (!this.config.connected) {
      return of({ success: false, message: 'Not connected to OpenCTI.' });
    }

    const endpoint = `${this.config.url}/graphql`;
    const mutation = `
      mutation ImportStix($stixData: String!) {
        stixObjectOrStixRelationshipImport(stixData: $stixData) { id }
      }
    `;
    return this.graphql<any>(mutation, { stixData: stixJson }).pipe(
      map(() => ({ success: true, message: 'Bundle imported successfully.' })),
      catchError(err => of({ success: false, message: `Import failed: ${err?.message ?? 'Unknown error'}` })),
    );
  }

  /** Generate a STIX 2.1 report bundle for a set of technique IDs. */
  generateStixReport(attackIds: string[], reportTitle: string): string {
    const now = new Date().toISOString();
    const bundle = {
      type: 'bundle',
      id: `bundle--${this.uuid()}`,
      objects: [
        {
          type: 'report',
          spec_version: '2.1',
          id: `report--${this.uuid()}`,
          created: now,
          modified: now,
          name: reportTitle,
          description: `ATT&CK technique coverage report — ${attackIds.length} techniques`,
          report_types: ['threat-report'],
          published: now,
          object_refs: attackIds.map(id => `attack-pattern--${this.attackIdToFakeStixId(id)}`),
        },
        ...attackIds.map(id => ({
          type: 'attack-pattern',
          spec_version: '2.1',
          id: `attack-pattern--${this.attackIdToFakeStixId(id)}`,
          created: now,
          modified: now,
          name: id,
          external_references: [{
            source_name: 'mitre-attack',
            external_id: id,
            url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}`,
          }],
        })),
      ],
    };
    return JSON.stringify(bundle, null, 2);
  }

  /** OpenCTI public demo URL — for documentation link */
  getDemoUrl(): string {
    return 'https://demo.opencti.io';
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private graphql<T>(query: string, variables: Record<string, unknown>): Observable<T> {
    const endpoint = this.config.mode === 'proxy'
      ? `${this.config.proxyUrl}/api/opencti/graphql`
      : `${this.config.url}/graphql`;
    const headers = this.config.mode === 'proxy'
      ? new HttpHeaders({ 'Content-Type': 'application/json' })
      : new HttpHeaders({
          'Authorization': `Bearer ${this.config.token}`,
          'Content-Type': 'application/json',
        });

    return this.http.post<{ data: T }>(endpoint, { query, variables }, { headers }).pipe(
      map(res => res.data),
      catchError(err => { throw err; }),
    );
  }

  private uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  private attackIdToFakeStixId(attackId: string): string {
    // Deterministic fake STIX ID based on ATT&CK ID for bundle consistency
    const seed = attackId.replace(/\./g, '');
    let hash = 0;
    for (const c of seed) hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
    const hex = hash.toString(16).padStart(8, '0');
    return `${hex}-${seed.slice(0,4)}-4abc-8def-${hex}${seed.slice(0,4)}`;
  }
}
